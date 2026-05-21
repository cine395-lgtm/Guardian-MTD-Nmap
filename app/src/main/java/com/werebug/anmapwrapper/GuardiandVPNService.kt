package com.werebug.anmapwrapper

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import java.net.URL
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors


private var certEngine: CertificateEngine? = null

class GuardianVpnService : VpnService() {

    companion object {
        const val VPN_LOG_TAG = "GuardianVPN"
        var isRunning = false
        var instance: GuardianVpnService? = null

        const val CHANNEL_ID = "guardian_vpn"
        const val NOTIFICATION_ID = 1001

        @Volatile var isKillSwitchActive: Boolean = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null
    private var readerThread: Thread? = null
    private val running = AtomicBoolean(false)

    private var proxyEngine: GuardianTcpProxy? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "STOP_VPN" -> stopVpnInternal()
            "START_VPN", null -> {
                if (!running.get()) {
                    createNotificationChannel()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        startForeground(
                            NOTIFICATION_ID,
                            buildNotification(),
                            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                        )
                    } else {
                        startForeground(NOTIFICATION_ID, buildNotification())
                    }
                    DnsPolicyEngine.loadDenylist(this)
                    establishTunnel()
                } else {
                    DnsPolicyEngine.loadDenylist(this)
                    broadcastTraffic("🔄 Regole Firewall DNS sincronizzate.")
                }
            }
        }
        return START_STICKY
    }

    private fun establishTunnel() {
        if (vpnInterface != null) return
        try {
            val builder = Builder()
                .setSession("GuardianFullTunnel")
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")

            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.e(VPN_LOG_TAG, "Impossibile escludere l'applicazione dal tunnel: ${e.message}")
            }

            val established = builder.establish() ?: return
            vpnInterface = established
            tunInput = FileInputStream(established.fileDescriptor)
            tunOutput = FileOutputStream(established.fileDescriptor)

            running.set(true)
            isRunning = true

            notifyUiStatusChange()

            // 1. Avviamo il lettore di pacchetti TUN per la telemetria e il reindirizzamento NAT
            startTunReader()

            // 2. SVEGLIAMO IL MOTORE CRITTOGRAFICO DELLA CA
            broadcastTraffic("🔑 Ok")
            certEngine = CertificateEngine(this)

            // 3. INNESCO DEL PROXY TCP DINAMICO
            proxyEngine = GuardianTcpProxy(18080)
            proxyEngine?.startProxy()

            // =========================================================================
            // 4. SCHEDULAZIONE REMOTA AUTOMATICA (OGNI 2 GIORNI) - ANDROID 17
            // =========================================================================
            try {
                val telemetryWorkRequest = androidx.work.PeriodicWorkRequestBuilder<ReportWorker>(
                    2, java.util.concurrent.TimeUnit.DAYS // Ciclo di esecuzione ogni 48 ore
                )
                    .setConstraints(
                        androidx.work.Constraints.Builder()
                            .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED) // Solo se c'è rete attiva
                            .build()
                    )
                    .build()

                androidx.work.WorkManager.getInstance(this).enqueueUniquePeriodicWork(
                    "GuardianRemoteReport",
                    androidx.work.ExistingPeriodicWorkPolicy.KEEP, // Mantiene il timer attivo senza resettarlo al riavvio della VPN
                    telemetryWorkRequest
                )
                broadcastTraffic("🕒 Timer Telemetria Remota (48h) agganciato al sistema.")
            } catch (workEx: Exception) {
                Log.e(VPN_LOG_TAG, "Impossibile registrare il WorkManager di telemetria: ${workEx.message}")
            }
            // =========================================================================

            broadcastTraffic("--- 🛡️ Full-Tunnel MTD Attivato ---")
            broadcastTraffic("🟢 Tutto il traffico del dispositivo è ora instradato e protetto.")
        } catch (e: Exception) {
            Log.e(VPN_LOG_TAG, "Errore stabilimento full-tunnel: ${e.message}", e)
        }
    }

    private fun startTunReader() {
        broadcastTraffic("ok")
        certEngine = CertificateEngine(this)

        proxyEngine = GuardianTcpProxy(18080)
        proxyEngine?.startProxy()
        val input = tunInput ?: return
        val output = tunOutput ?: return

        readerThread?.interrupt()

        readerThread = Thread {
            val pcapFile = File(filesDir, "tmp/telemetry_traffic.pcap")
            val pcapWriter = PcapWriter(pcapFile)
            val buffer = ByteArray(32767)

            try {
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    val length = input.read(buffer)
                    if (length <= 0) continue

                    if (isKillSwitchActive) {
                        continue
                    }

                    pcapWriter.writePacket(buffer, length)

                    try {
                        analizzaEInviaSNI(buffer, length)
                    } catch (sniEx: Exception) {
                    }

                    handlePacket(buffer, length, output)
                }
            } catch (e: Exception) {
                Log.d(VPN_LOG_TAG, "Lettore TUN arrestato o interrotto.")
            } catch (e: java.io.IOException) {
                Log.e(VPN_LOG_TAG, "Errore I/O sul descrittore TUN: ${e.message}")
            } finally {
                try { pcapWriter.close() } catch (_: Exception) {}
            }
        }.apply {
            name = "GuardianTunReader"
            start()
        }
    }

    private fun analizzaEInviaSNI(packet: ByteArray, length: Int) {
        if (length < 40) return

        val ipVersion = (packet[0].toInt() and 0xF0) ushr 4
        if (ipVersion != 4) return

        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (packet[9].toInt() == 6) {

            val tcpHeaderOffset = ipHeaderLength
            val tragicOffset = tcpHeaderOffset + 12
            if (tragicOffset >= length) return

            val tcpDataOffset = ((packet[tragicOffset].toInt() and 0xF0) ushr 4) * 4
            val tlsOffset = tcpHeaderOffset + tcpDataOffset

            if (length > tlsOffset + 5) {
                val contentType = packet[tlsOffset].toInt() and 0xFF
                val handshakeType = packet[tlsOffset + 5].toInt() and 0xFF

                if (contentType == 22 && handshakeType == 1) {
                    val payloadString = StringBuilder()
                    for (i in (tlsOffset + 43) until (length - 1)) {
                        val b = packet[i].toInt() and 0xFF
                        if (b in 32..126) {
                            payloadString.append(b.toChar())
                        } else {
                            if (payloadString.length > 4) {
                                val candidate = payloadString.toString()
                                if (candidate.contains(".") && (candidate.endsWith(".com") || candidate.endsWith(".net") || candidate.endsWith(".org") || candidate.endsWith(".it") || candidate.contains("google") || candidate.contains("api"))) {
                                    val logLine = "🔒 [HTTPS SNI] Connessione a: $candidate"
                                    val intent = Intent("VPN_TRAFFIC_UPDATE").apply {
                                        putExtra("LOG_LINE", logLine)
                                    }
                                    sendBroadcast(intent)
                                    break
                                }
                            }
                            payloadString.setLength(0)
                        }
                    }
                }
            }
        }
    }

    private fun handlePacket(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        val ipv4 = PacketParsers.parseIpv4Packet(packet, length) ?: return

        if (ipv4.protocol == 6) {
            val tcpHeaderOffset = ipv4.payloadOffset
            if (tcpHeaderOffset + 4 <= length) {
                val destPort = ((packet[tcpHeaderOffset + 2].toInt() and 0xFF) shl 8) or
                        (packet[tcpHeaderOffset + 3].toInt() and 0xFF)

                if (destPort == 443) {
                    packet[16] = 0x7F.toByte()
                    packet[17] = 0x00.toByte()
                    packet[18] = 0x00.toByte()
                    packet[19] = 0x01.toByte()

                    packet[tcpHeaderOffset + 2] = 0x46.toByte()
                    packet[tcpHeaderOffset + 3] = 0xA8.toByte()

                    recalculateChecksums(packet, length, ipv4.payloadOffset)

                    outputStream.write(packet, 0, length)
                    outputStream.flush()
                    return
                }
            }

            outputStream.write(packet, 0, length)
            outputStream.flush()
            return
        }

        if (ipv4.protocol != 17) {
            outputStream.write(packet, 0, length)
            outputStream.flush()
            return
        }

        val udp = PacketParsers.parseUdpHeader(packet, ipv4.payloadOffset, length) ?: return

        if (udp.destinationPort != 53) {
            outputStream.write(packet, 0, length)
            outputStream.flush()
            return
        }

        val dnsOffset = ipv4.payloadOffset + 8
        val dns = PacketParsers.parseDnsQuery(packet, dnsOffset, length)
        val domain = dns?.domain ?: "unknown"

        if (DnsPolicyEngine.shouldBlock(domain)) {
            val blockedPacket = DnsPacketBuilder.buildNxdomainResponse(ipv4, packet, length)
            outputStream.write(blockedPacket)
            outputStream.flush()
            broadcastTraffic("🚨 DROP: Bloccato -> $domain")
            return
        }

        val doHResponsePayload = forwardQueryDoh(packet.copyOfRange(dnsOffset, length))
        if (doHResponsePayload != null) {
            val responsePacket = DnsPacketBuilder.buildUdpIpv4Response(
                ipv4,
                packet,
                length,
                doHResponsePayload,
                doHResponsePayload.size
            )
            outputStream.write(responsePacket)
            outputStream.flush()
            broadcastTraffic("🟢 DOH-SECURE: Risolto -> $domain")
        } else {
            outputStream.write(packet, 0, length)
            outputStream.flush()
        }
    }

    private fun forwardQueryDoh(dnsQuery: ByteArray): ByteArray? {
        var connection: HttpsURLConnection? = null
        return try {
            val url = URL("https://1.0.0.1/dns-query")
            connection = url.openConnection() as HttpsURLConnection
            connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            connection.doOutput = true
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/dns-message")
            connection.setRequestProperty("Accept", "application/dns-message")
            connection.connectTimeout = 3000

            val os = connection.outputStream
            os.write(dnsQuery)
            os.close()

            if (connection.responseCode == 200) connection.inputStream.readBytes() else null
        } catch (_: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    private fun notifyUiStatusChange() {
        val intent = Intent("UPDATE_UI_ACTION")
        intent.setPackage(packageName)
        sendBroadcast(intent)
    }

    private fun broadcastTraffic(logLine: String) {
        val intent = Intent("VPN_TRAFFIC_UPDATE").apply {
            putExtra("LOG_LINE", logLine)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun stopVpnInternal() {
        running.set(false)
        isRunning = false

        notifyUiStatusChange()

        try {
            tunInput?.close()
        } catch (e: Exception) {
            Log.e(VPN_LOG_TAG, "Errore chiusura tunInput", e)
        }

        try {
            tunOutput?.close()
        } catch (e: Exception) {
            Log.e(VPN_LOG_TAG, "Errore chiusura tunOutput", e)
        }

        try {
            proxyEngine?.stopProxy()
            proxyEngine = null
            Log.d(VPN_LOG_TAG, "Proxy TCP fermato correttamente.")
        } catch (e: Exception) {
            Log.e(VPN_LOG_TAG, "Errore durante l'arresto del proxy: ${e.message}")
        }
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(VPN_LOG_TAG, "Errore chiusura vpnInterface", e)
        }

        vpnInterface = null
        tunInput = null
        tunOutput = null

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (e: Exception) {
            Log.e(VPN_LOG_TAG, "Errore stopForeground", e)
        }

        stopSelf()
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Security Core")
            .setContentText("Active Protection Enabled")

            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Guardian VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(channel)
        }
    }

    private fun recalculateChecksums(packet: ByteArray, length: Int, payloadOffset: Int) {
        packet[10] = 0
        packet[11] = 0

        var ipChecksum = 0
        for (i in 0 until payloadOffset step 2) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            ipChecksum += word
        }
        while (ipChecksum ushr 16 > 0) {
            ipChecksum = (ipChecksum and 0xFFFF) + (ipChecksum ushr 16)
        }
        ipChecksum = ipChecksum.inv()
        packet[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()
    }

    override fun onDestroy() {
        instance = null
        isRunning = false
        super.onDestroy()
    }
}
// =========================================================================
// CLASSE COMPLEMENTARE PROXY TCP EVOLUTA (Sostituisci in fondo al file)
// =========================================================================
class GuardianTcpProxy(private val proxyPort: Int) {

    private var serverSocket: ServerSocket? = null
    private val threadPool = Executors.newCachedThreadPool()
    @Volatile var isRunning = false

    fun startProxy() {
        isRunning = true
        Thread {
            try {
                serverSocket = ServerSocket(proxyPort)
                Log.d("GuardianProxy", "Proxy Server Socket dinamico avviato sulla porta $proxyPort")

                while (isRunning) {
                    val clientSocket = serverSocket?.accept() ?: break
                    threadPool.execute {
                        handleClientConnection(clientSocket)
                    }
                }
            } catch (e: Exception) {
                Log.e("GuardianProxy", "Errore nel ciclo principale del proxy: ${e.message}")
            }
        }.start()
    }

    private fun handleClientConnection(clientSocket: Socket) {
        try {
            // 1. LETTURA PREVENTIVA: Leggiamo i primi byte (l'Handshake TLS) per scoprire la vera destinazione
            val inputStream = clientSocket.getInputStream()
            val bufferPeek = ByteArray(10240) // Buffer per analizzare il Client Hello

            clientSocket.soTimeout = 3000
            val bytesRead = inputStream.read(bufferPeek)
            if (bytesRead <= 0) {
                clientSocket.close()
                return
            }

            // 2. ESTRAZIONE DELLA DESTINAZIONE TRAMITE SNI
            val targetHost = estraiHostDaClientHello(bufferPeek, bytesRead) ?: "1.1.1.1"
            val targetPort = 443

            Log.d("GuardianProxy", "🔗 Rilevata destinazione dal proxy: $targetHost:$targetPort")

            // 3. APERTURA CONNESSIONE SPECCHIO VERSO INTERNET REALISTICA
            val targetSocket = Socket(targetHost, targetPort)
            val outputStream = clientSocket.getOutputStream()

            // Spediamo al vero server internet i byte iniziali che abbiamo "sbirciato" per non rompere la sessione
            targetSocket.getOutputStream().write(bufferPeek, 0, bytesRead)
            targetSocket.getOutputStream().flush()

            // 4. TRANSITO ASINCRONO BIDIREZIONALE
            val clientToTarget = Thread { forwardData(inputStream, targetSocket.getOutputStream()) }
            val targetToClient = Thread { forwardData(targetSocket.getInputStream(), outputStream) }

            clientToTarget.start()
            targetToClient.start()

            clientToTarget.join()
            targetToClient.join()

        } catch (e: Exception) {
            Log.e("GuardianProxy", "Errore di instradamento proxy: ${e.message}")
        } finally {
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    // Parser SNI interno alla ServerSocket per ricostruire la destinazione originale
    private fun estraiHostDaClientHello(packet: ByteArray, length: Int): String? {
        try {
            if (length < 45) return null
            val contentType = packet[0].toInt() and 0xFF
            val handshakeType = packet[5].toInt() and 0xFF

            if (contentType == 22 && handshakeType == 1) { // TLS Handshake + Client Hello
                val payloadString = StringBuilder()
                for (i in 43 until (length - 1)) {
                    val b = packet[i].toInt() and 0xFF
                    if (b in 32..126) {
                        payloadString.append(b.toChar())
                    } else {
                        if (payloadString.length > 4) {
                            val candidate = payloadString.toString()
                            if (candidate.contains(".") && (candidate.endsWith(".com") || candidate.endsWith(".net") || candidate.endsWith(".org") || candidate.endsWith(".it") || candidate.contains("google") || candidate.contains("api"))) {
                                return candidate
                            }
                        }
                        payloadString.setLength(0)
                    }
                }
            }
        } catch (_: Exception) {}
        return null
    }

    private fun forwardData(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(8192)
        try {
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                if (bytesRead > 0) {
                    output.write(buffer, 0, bytesRead)
                    output.flush()
                }
            }
        } catch (_: Exception) {}
    }

    fun stopProxy() {
        isRunning = false
        try {
            serverSocket?.close()
            threadPool.shutdownNow()
        } catch (e: Exception) {
            Log.e("GuardianProxy", "Errore durante l'arresto del proxy: ${e.message}")
        }
    }

}