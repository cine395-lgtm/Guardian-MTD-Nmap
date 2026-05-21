package com.werebug.anmapwrapper

import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

// Modello dati per tracciare l'esito del rinvio della query
data class DnsForwardResult(
    val response: ByteArray?,
    val length: Int,
    val upstream: String,
    val success: Boolean
)

object DnsForwarder {
    private const val TAG = "DnsForwarder"

    fun forwardQuery(
        service: VpnService,
        request: ByteArray,
        length: Int,
        upstreamHost: String,
        upstreamPort: Int = 53,
        timeoutMs: Int = 3000
    ): DnsForwardResult {
        // Inizializza un socket datagram UDP non vincolato
        val socket = DatagramSocket(null)
        return try {
            socket.bind(null)

            // CRITICO: Protegge il socket per bypassare il routing della VPN ed evitare il loop infinito
            service.protect(socket)
            socket.soTimeout = timeoutMs

            // Impacchetta e spedisce la richiesta al server DNS reale (es. 1.1.1.1)
            val address = InetSocketAddress(upstreamHost, upstreamPort)
            val outbound = DatagramPacket(request, length, address)
            socket.send(outbound)

            // Resta in ascolto della risposta reale dal server remoto
            val buffer = ByteArray(1500)
            val inbound = DatagramPacket(buffer, buffer.size)
            socket.receive(inbound)

            val response = inbound.data.copyOfRange(0, inbound.length)
            Log.d(TAG, "DNS inoltrato con successo a $upstreamHost:${upstreamPort}, risposta = ${inbound.length} bytes")

            DnsForwardResult(
                response = response,
                length = inbound.length,
                upstream = upstreamHost,
                success = true
            )
        } catch (e: SocketTimeoutException) {
            Log.w(TAG, "Timeout richiesta DNS da upstream: $upstreamHost")
            DnsForwardResult(
                response = null,
                length = 0,
                upstream = upstreamHost,
                success = false
            )
        } catch (e: Exception) {
            Log.e(TAG, "Fallimento inoltro DNS verso: $upstreamHost", e)
            DnsForwardResult(
                response = null,
                length = 0,
                upstream = upstreamHost,
                success = false
            )
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
                // Chiusura sicura del canale socket
            }
        }
    }
}