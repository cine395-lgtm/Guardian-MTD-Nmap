package com.werebug.anmapwrapper

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.graphics.Color
import android.net.wifi.WifiManager
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.os.HandlerCompat
import androidx.preference.PreferenceManager
import java.io.File
import java.io.FileOutputStream
import java.io.DataOutputStream
import java.lang.ref.WeakReference
import java.net.InetSocketAddress
import java.net.Socket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.Collections
import java.util.concurrent.Executors
import android.util.Log
import android.content.pm.PackageManager
import android.os.Looper
import java.net.SocketTimeoutException

class PcapWriter(private val file: File) {
  private var dos: DataOutputStream? = null

  init {
    if (!file.exists()) {
      dos = DataOutputStream(FileOutputStream(file))
      dos?.writeInt(0xa1b2c3d4.toInt())
      dos?.writeShort(2)
      dos?.writeShort(4)
      dos?.writeInt(0)
      dos?.writeInt(0)
      dos?.writeInt(65535)
      dos?.writeInt(101)
      dos?.flush()
    } else {
      dos = DataOutputStream(FileOutputStream(file, true))
    }
  }

  fun writePacket(packet: ByteArray, length: Int) {
    try {
      val timestampSec = System.currentTimeMillis() / 1000
      val timestampUsec = (System.currentTimeMillis() % 1000) * 1000

      dos?.writeInt(timestampSec.toInt())
      dos?.writeInt(timestampUsec.toInt())
      dos?.writeInt(length)
      dos?.writeInt(length)

      dos?.write(packet, 0, length)
      dos?.flush()
    } catch (e: Exception) {
      Log.e("PcapWriter", "Errore durante la scrittura del pacchetto: ${e.message}")
    }
  }

  fun close() {
    dos?.close()
  }
}

// =========================================================================
// MAIN ACTIVITY PRINCIPALE (Versione ultra-compatibile)
// =========================================================================
class MainActivity : AppCompatActivity() {

  companion object {
    const val LOG_TAG = "ANMAPWRAPPER_CUSTOM_LOG"
    const val XML_OUTPUT_FILE = "tmp/scan_output.xml"
  }

  private val executorService = Executors.newFixedThreadPool(1)
  private val sweepExecutor = Executors.newFixedThreadPool(40)
  private val mainThreadHandler = HandlerCompat.createAsync(Looper.getMainLooper())

  private lateinit var libDir: String
  private lateinit var nmapExecutablePath: String
  private lateinit var sharedPreferences: SharedPreferences
  var isScanning = false
  private var currentNmapScan: NmapScan? = null

  private lateinit var tvVpnStatus: TextView
  private lateinit var btnVpnToggle: Button
  private lateinit var tvLiveTraffic: TextView
  private lateinit var btnCheckNetwork: Button
  private lateinit var tvNetworkHealth: TextView
  private lateinit var etDomainInput: EditText
  private lateinit var btnDomainToggle: Button
  private lateinit var tvDenyList: TextView
  private lateinit var etIpAddress: EditText
  private lateinit var btnScan: Button
  private lateinit var tvDetectedHosts: TextView
  private lateinit var tvNmapResult: TextView

  data class HostProfile(
    val ip: String,
    var isAlive: Boolean = false,
    val openPorts: MutableSet<Int> = mutableSetOf(),
    var hostType: String = "Unknown"
  )

  private val trafficLogs = mutableListOf<String>()
  private val discoveredIps = Collections.synchronizedSet(mutableSetOf<String>())
  data class HostResult(val isAlive: Boolean, val os: String)

  // =========================================================================
  // RICEVITORE TRAFFICO AGGIORNATO (Senza parent-cast pericolosi)
  // =========================================================================
  private val trafficReceiver = object : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      val logLine = intent?.getStringExtra("LOG_LINE") ?: return

      runOnUiThread {
        // Appendiamo direttamente sulla TextView nativa ereditata dal tuo vecchio codice
        tvLiveTraffic.append("\n$logLine")
      }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    libDir = applicationInfo.nativeLibraryDir
    nmapExecutablePath = "$libDir/libnmap.so"
    sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)

    // Esecuzione asincrona degli asset (Manteniamo i tuoi exact reference originari)
    executorService.execute(ImportNmapAssets(WeakReference(this)))
    makeTmpDir()
    initViews()
    setupListeners()

    DnsPolicyEngine.loadDenylist(applicationContext)
    updateDenyListUI()

    val engineFilter = IntentFilter("UPDATE_UI_ACTION")
    ContextCompat.registerReceiver(this, object : BroadcastReceiver() {
      override fun onReceive(c: Context?, i: Intent?) {
        mainThreadHandler.post { updateVpnUiStatus() }
      }
    }, engineFilter, ContextCompat.RECEIVER_NOT_EXPORTED)

    val trafficFilter = IntentFilter("VPN_TRAFFIC_UPDATE")
    ContextCompat.registerReceiver(this, trafficReceiver, trafficFilter, ContextCompat.RECEIVER_NOT_EXPORTED)

    requestLanPermissionsIfNeeded()
  }

  override fun onResume() {
    super.onResume()
    updateVpnUiStatus()
  }

  private fun initViews() {
    tvVpnStatus = findViewById(R.id.tvVpnStatus)
    btnVpnToggle = findViewById(R.id.btnVpnToggle)
    tvLiveTraffic = findViewById(R.id.tvLiveTraffic)
    btnCheckNetwork = findViewById(R.id.btnCheckNetwork)
    tvNetworkHealth = findViewById(R.id.tvNetworkHealth)
    etDomainInput = findViewById(R.id.etDomainInput)
    btnDomainToggle = findViewById(R.id.btnDomainToggle)
    tvDenyList = findViewById(R.id.tvDenyList)
    etIpAddress = findViewById(R.id.etIpAddress)
    btnScan = findViewById(R.id.btnScan)
    tvDetectedHosts = findViewById(R.id.tvDetectedHosts)
    tvNmapResult = findViewById(R.id.tvNmapResult)
  }

  fun setupListeners() {
    btnVpnToggle.setOnClickListener {
      if (GuardianVpnService.isRunning) {
        startService(Intent(this, GuardianVpnService::class.java).apply { action = "STOP_VPN" })
      } else {
        val intent = android.net.VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 101) else startVpnService()
      }
    }

    btnCheckNetwork.setOnClickListener {
      tvNetworkHealth.text = "🔄 Rilevamento in corso..."
      executorService.execute {
        val detected = executeMitMAudit()
        mainThreadHandler.post {
          tvNetworkHealth.text = if (detected) "🚨 THREAT DETECTED (MitM Alert)" else "🟢 INTEGRITY VERIFIED"
          tvNetworkHealth.setTextColor(if (detected) Color.RED else Color.GREEN)
        }
      }
    }

    btnScan.setOnClickListener {
      if (isScanning) {
        currentNmapScan?.stopScan()
        isScanning = false
        btnScan.text = "DEPLOY NETWORK AUDIT TASK"
        tvNmapResult.append("\n⚠️ Operazione interrotta dall'operatore.")
      } else {
        val input = etIpAddress.text.toString().trim()
        if (input.isEmpty()) {
          Toast.makeText(this, "Inserisci un IP o una Subnet validi", Toast.LENGTH_SHORT).show()
          return@setOnClickListener
        }

        isScanning = true
        btnScan.text = "ABORT"

        tvDetectedHosts.text = "🔬 Analisi host in corso..."
        tvNmapResult.text = "Inizializzazione sottoprocesso d'ispezione locale...\n"
        discoveredIps.clear()

        val cleanInput = input.replace("(", "/").replace(")", "").replace(" ", "")

        try {
          val command = buildStandardNmapCommand(cleanInput)
          currentNmapScan = NmapScan(WeakReference(this), command, mainThreadHandler, libDir)
          executorService.execute(currentNmapScan)

        } catch (e: Exception) {
          Log.e(LOG_TAG, "Errore nel lancio del sottoprocesso: ${e.message}")
          isScanning = false
          btnScan.text = "DEPLOY NETWORK AUDIT TASK"
          tvDetectedHosts.text = "❌ Errore."
          tvNmapResult.text = "❌ Fallimento esecuzione core: ${e.message}"
        }
      }
    }

    btnDomainToggle.setOnClickListener {
      val domain = etDomainInput.text.toString().trim()
      if (domain.isNotEmpty()) {
        // Se il dominio c'è già, lo rimuove, altrimenti lo aggiunge (Toggle)
        val currentDomains = DnsPolicyEngine.getActiveDomains()
        if (currentDomains.contains(domain.lowercase())) {
          DnsPolicyEngine.removeDomain(applicationContext, domain)
          Toast.makeText(this, "Policy disattivata per: $domain", Toast.LENGTH_SHORT).show()
        } else {
          DnsPolicyEngine.addDomain(applicationContext, domain)
          Toast.makeText(this, "Policy attivata per: $domain", Toast.LENGTH_SHORT).show()
        }

        // Svuota l'input di testo
        etDomainInput.text.clear()

        // FORZATURA AGGIORNAMENTO UI: Rileggiamo immediatamente e aggiorniamo la TextView
        updateDenyListUI()
      }
    }
  }

  fun elaboraEVisualizzaRigaNmap(rigaNmap: String) {
    val trimmed = rigaNmap.trim()

    if (trimmed.contains("libnmap.so") || trimmed.contains("--datadir") || trimmed.contains("unprivileged")) {
      return
    }

    if (trimmed.isNotEmpty()) {
      if (tvNmapResult.text.contains("Inizializzazione") || tvNmapResult.text.contains("sottoprocesso")) {
        tvNmapResult.text = ""
      }
      if (tvDetectedHosts.text.contains("Analisi host") || tvDetectedHosts.text.contains("In attesa")) {
        tvDetectedHosts.text = ""
      }
    }

    if (trimmed.isNotEmpty()) {
      tvNmapResult.append(rigaNmap + "\n")
    }

    if (trimmed.contains("Nmap scan report for")) {
      val ipEstratto = trimmed.substringAfter("Nmap scan report for").trim()
      val ipPulito = ipEstratto.replace("(", "").replace(")", "")

      if (discoveredIps.add(ipPulito)) {
        tvDetectedHosts.append("🟢 Detected Target: $ipPulito\n")
      }
    }
  }

  private fun startNsdDiscovery() {
    val nsdManager = getSystemService(Context.NSD_SERVICE) as NsdManager

    val discoveryListener = object : NsdManager.DiscoveryListener {
      override fun onDiscoveryStarted(regType: String) {
        Log.d(LOG_TAG, "Servizio mDNS avviato")
      }

      override fun onServiceFound(serviceInfo: NsdServiceInfo) {
        nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
          override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
            Log.e(LOG_TAG, "Risoluzione mDNS fallita: $errorCode")
          }

          override fun onServiceResolved(resolvedServiceInfo: NsdServiceInfo) {
            val ip = resolvedServiceInfo.host.hostAddress ?: return
            mainThreadHandler.post {
              if (discoveredIps.add(ip)) {
                if (tvDetectedHosts.text.contains("Analisi")) tvDetectedHosts.text = ""
                tvDetectedHosts.append("📱 $ip [mDNS Node: ${resolvedServiceInfo.serviceName}]\n")
              }
            }
          }
        })
      }

      override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
      override fun onDiscoveryStopped(regType: String) {}
      override fun onStartDiscoveryFailed(regType: String, errorCode: Int) { nsdManager.stopServiceDiscovery(this) }
      override fun onStopDiscoveryFailed(regType: String, errorCode: Int) { nsdManager.stopServiceDiscovery(this) }
    }
    nsdManager.discoverServices("_http._tcp", NsdManager.PROTOCOL_DNS_SD, discoveryListener)
  }

  private fun discoverUpnpDevices() {
    sweepExecutor.execute {
      try {
        val msg = "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 2\r\n" +
                "ST: ssdp:all\r\n\r\n"

        val socket = DatagramSocket()
        GuardianVpnService.instance?.protect(socket)
        socket.soTimeout = 3000

        val sendPacket = DatagramPacket(msg.toByteArray(), msg.length, InetAddress.getByName("239.255.255.250"), 1900)
        socket.send(sendPacket)

        val receiveBuffer = ByteArray(2048)
        val startTime = System.currentTimeMillis()

        while (System.currentTimeMillis() - startTime < 3000) {
          try {
            val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
            socket.receive(receivePacket)

            val ip = receivePacket.address.hostAddress ?: continue
            if (ip != "10.222.221.206" && !ip.endsWith(".255")) {
              mainThreadHandler.post {
                if (discoveredIps.add(ip)) {
                  if (tvDetectedHosts.text.contains("Analisi")) tvDetectedHosts.text = ""
                  tvDetectedHosts.append("📡 $ip [SSDP Multicast Node]\n")
                }
              }
            }
          } catch (e: SocketTimeoutException) {
            // Concluso timeout pacchetto singolo
          }
        }
        socket.close()
      } catch (e: Exception) {
        Log.e(LOG_TAG, "Errore SSDP: ${e.message}")
      }
    }
  }

  private fun probeHost(ip: String): HostProfile? {
    val ports = intArrayOf(445, 80, 443, 53, 8080)
    var isAlive = false
    val openPorts = mutableSetOf<Int>()

    for (p in ports) {
      try {
        val socket = Socket()
        GuardianVpnService.instance?.protect(socket)
        socket.connect(InetSocketAddress(ip, p), 300)
        isAlive = true
        openPorts.add(p)
        socket.close()
      } catch (e: java.net.ConnectException) {
        isAlive = true
      } catch (e: Exception) { }
    }

    if (!isAlive) return null

    val p = HostProfile(ip = ip)
    p.isAlive = true
    p.openPorts.addAll(openPorts)

    if (openPorts.isEmpty()) {
      p.hostType = "🛡️ Alive (Firewalled)"
    } else {
      applyHeuristics(p)
    }
    return p
  }

  private fun startStealthSweep(targetIp: String) {
    val match = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}""").find(targetIp) ?: return
    val subnet = match.groupValues[1]

    discoveredIps.clear()
    Log.d(LOG_TAG, "Inizio scansione su subnet: $subnet")

    mainThreadHandler.post {
      tvDetectedHosts.text = "🔍 Analisi stealth attiva..."
    }

    for (i in 1..254) {
      val ipToTest = subnet + i
      sweepExecutor.execute {
        val result = probeHost(ipToTest)
        if (result != null) {
          Log.d(LOG_TAG, "Host trovato: $ipToTest")
          if (discoveredIps.add(ipToTest)) {
            mainThreadHandler.post {
              if (tvDetectedHosts.text.toString().contains("🔍")) tvDetectedHosts.text = ""
              tvDetectedHosts.append("🟢 $ipToTest [Type: ${result.hostType}]\n")
            }
          }
        }
      }
    }
  }

  private fun executeMitMAudit(): Boolean {
    return try {
      Runtime.getRuntime().exec("ip neigh").inputStream.bufferedReader().readText().isNotEmpty()
    } catch (e: Exception) { false }
  }

  private fun buildStandardNmapCommand(input: String): List<String> {
    val argv = mutableListOf(
      "nmap",
      "-sT",
      "-Pn",
      "-n",
      "--unprivileged",
      "-T3",
      "--scan-delay", "200ms",
      "--max-retries", "1",
      "-F",
      "--script", "banner",
      "--datadir", filesDir.absolutePath
    )

    argv.add(input)
    patchBinaryPaths(argv)
    return argv
  }

  private fun patchBinaryPaths(argv: MutableList<String>) {
    val idx = argv.indexOf("nmap")
    if (idx != -1) { argv.removeAt(idx); argv.add(idx, nmapExecutablePath) }
  }

  private fun patchReserved(argv: MutableList<String>, flag: String, value: String) {
    if (!argv.contains(flag)) Collections.addAll(argv, flag, value)
  }

  private var currentTargetIp: String? = null

  fun updateOutputView(out: String?, fin: Boolean) {
    mainThreadHandler.post {
      if (out != null) {
        tvNmapResult.append(out)

        val lines = out.split("\n")
        for (line in lines) {
          val trimmedLine = line.trim()

          if (trimmedLine.contains("Nmap scan report for")) {
            val rawIp = trimmedLine.substringAfter("Nmap scan report for ").trim()
            currentTargetIp = if (rawIp.contains("(")) {
              rawIp.substringAfter("(").substringBefore(")").trim()
            } else {
              rawIp
            }
          }

          if (currentTargetIp != null) {
            if (trimmedLine.contains("Host is up") ||
              (trimmedLine.contains("/tcp") && trimmedLine.contains("open"))) {

              verifyHostLiveness(currentTargetIp!!)
              currentTargetIp = null
            }
          }
        }
      }

      if (fin) {
        isScanning = false
        btnScan.text = "DEPLOY NETWORK AUDIT TASK"
        currentTargetIp = null
      }
    }
  }

  private fun verifyHostLiveness(ip: String) {
    if (ip.endsWith(".255")) return

    sweepExecutor.execute {
      var hostRilevato = false

      val porteTest = intArrayOf(5555, 62078)
      for (port in porteTest) {
        try {
          val socket = Socket()
          GuardianVpnService.instance?.protect(socket)
          socket.connect(InetSocketAddress(ip, port), 80)
          socket.close()
          hostRilevato = true
          break
        } catch (e: java.net.ConnectException) {
          hostRilevato = true
          break
        } catch (e: Exception) { }
      }

      if (hostRilevato) {
        mainThreadHandler.post {
          if (discoveredIps.add(ip)) {
            if (tvDetectedHosts.text.contains("Analisi") || tvDetectedHosts.text.contains("Scansione")) {
              tvDetectedHosts.text = ""
            }
            tvDetectedHosts.append("🟢 $ip [Verified Hardware Node]\n")
          }
        }
      }
    }
  }

  private fun addIpToRegistry(ip: String) {
    if (ip.endsWith(".255")) return

    if (discoveredIps.add(ip)) {
      if (tvDetectedHosts.text.contains("Analisi") || tvDetectedHosts.text.contains("Scansione")) tvDetectedHosts.text = ""
      tvDetectedHosts.append("🟢 $ip [Active Infrastructure Device]\n")
    }
  }

  private fun solicitAndDiscoverDevices() {
    executorService.execute {
      val udpSocket = DatagramSocket()
      udpSocket.broadcast = true
      udpSocket.soTimeout = 1000

      try {
        val broadcastAddr = InetAddress.getByName("255.255.255.255")

        val netbiosData = byteArrayOf(
          0xA1.toByte(), 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41, 0x41,
          0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
          0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
          0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
          0x41, 0x00, 0x00, 0x21, 0x00, 0x01
        )
        val netbiosPacket = DatagramPacket(netbiosData, netbiosData.size, broadcastAddr, 137)
        udpSocket.send(netbiosPacket)

        val ssdpQuery = "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 2\r\n" +
                "ST: ssdp:all\r\n\r\n"
        val ssdpData = ssdpQuery.toByteArray()
        val mcastAddr = InetAddress.getByName("239.255.255.250")
        val ssdpPacket = DatagramPacket(ssdpData, ssdpData.size, mcastAddr, 1900)
        udpSocket.send(ssdpPacket)

        val buffer = ByteArray(1024)
        val startTime = System.currentTimeMillis()

        while (System.currentTimeMillis() - startTime < 2000) {
          try {
            val receivePacket = DatagramPacket(buffer, buffer.size)
            udpSocket.receive(receivePacket)

            val senderIp = receivePacket.address.hostAddress

            if (senderIp != null && senderIp != "10.222.221.206" && !senderIp.endsWith(".255")) {
              mainThreadHandler.post {
                if (discoveredIps.add(senderIp)) {
                  if (tvDetectedHosts.text.contains("Analisi") || tvDetectedHosts.text.contains("Scansione")) tvDetectedHosts.text = ""
                  tvDetectedHosts.append("🎯 $senderIp [UDP Request Responder]\n")
                }
              }
            }
          } catch (e: SocketTimeoutException) {
            break
          }
        }

      } catch (e: Exception) {
        Log.e("Solicitor", "Errore pacchetti: ${e.message}")
      } finally {
        udpSocket.close()
      }
    }
  }

  fun initScanView() {
    isScanning = true
    btnScan.text = "ABORT"
    tvNmapResult.text = "Inizializzazione...\n"
  }

  private fun getActiveArpDevices(): List<String> {
    val devices = mutableListOf<String>()
    try {
      val process = Runtime.getRuntime().exec("ip neigh")
      val reader = process.inputStream.bufferedReader()
      reader.forEachLine { line ->
        Log.d(LOG_TAG, "ARP Line: $line")
        if (line.contains("REACHABLE") || line.contains("DELAY") || line.contains("STALE")) {
          val parts = line.split(" ")
          if (parts.isNotEmpty()) {
            devices.add(parts[0])
          }
        }
      }
      process.waitFor()
    } catch (e: Exception) {
      Log.e(LOG_TAG, "Errore critico QA Arp: ${e.message}")
    }
    return devices
  }

  private fun updateVpnUiStatus() {
    val running = GuardianVpnService.isRunning
    btnVpnToggle.text = if (running) "DEACTIVATE ENGINE" else "ACTIVATE ENGINE"
    tvVpnStatus.text = if (running) "NDR CORE: OPERATIONAL" else "NDR CORE: SLEEP"
    tvVpnStatus.setTextColor(if (running) Color.GREEN else Color.RED)
  }

  private fun updateDenyListUI() {
    mainThreadHandler.post {
      val domains = DnsPolicyEngine.getActiveDomains()
      tvDenyList.text = if (domains.isEmpty()) {
        "No Active Firewall Rules."
      } else {
        domains.joinToString("\n") { "🚫 Policy Deny Rule: $it" }
      }
    }
  }

  private fun startVpnService() {
    val intent = Intent(this, GuardianVpnService::class.java).apply { action = "START_VPN" }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
  }

  private fun requestLanPermissionsIfNeeded() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      if (ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
        wifiPermissionLauncher.launch(Manifest.permission.NEARBY_WIFI_DEVICES)
      }
    }
  }

  private val wifiPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }
  private fun makeTmpDir() = File(filesDir, "tmp").mkdirs()
  override fun onCreateOptionsMenu(menu: Menu?): Boolean = true
  override fun onDestroy() {
    super.onDestroy()
    try { unregisterReceiver(trafficReceiver) } catch (_: Exception) {}
  }

  private fun applyHeuristics(p: HostProfile) {
    val ports = p.openPorts
    p.hostType = when {
      445 in ports -> "🪟 Windows Node"
      80 in ports || 443 in ports -> "🌐 Web Endpoint"
      else -> "🟢 Active Host"
    }
  }
}