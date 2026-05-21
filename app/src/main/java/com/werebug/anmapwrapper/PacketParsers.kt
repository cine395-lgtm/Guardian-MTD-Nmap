package com.werebug.anmapwrapper

import java.nio.ByteBuffer
import java.nio.ByteOrder

// Data class strutturali per mappare i pacchetti di rete
data class ParsedIpv4Packet(
    val protocol: Int,
    val sourceIp: String,
    val destinationIp: String,
    val headerLength: Int,
    val totalLength: Int,
    val payloadOffset: Int
)

data class ParsedUdpHeader(
    val sourcePort: Int,
    val destinationPort: Int,
    val length: Int
)

data class ParsedDnsQuery(
    val domain: String?,
    val queryType: Int?
)

object PacketParsers {

    // Scompone l'header IPv4 analizzando i byte grezzi
    fun parseIpv4Packet(packet: ByteArray, length: Int): ParsedIpv4Packet? {
        if (length < 20) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null

        val totalLength = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        val protocol = packet[9].toInt() and 0xFF

        val sourceIp = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}.${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
        val destinationIp = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}.${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"

        return ParsedIpv4Packet(
            protocol = protocol,
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            headerLength = ihl,
            totalLength = totalLength,
            payloadOffset = ihl
        )
    }

    // Estrae le porte sorgente e destinazione del datagramma UDP
    fun parseUdpHeader(packet: ByteArray, udpOffset: Int, length: Int): ParsedUdpHeader? {
        if (length < udpOffset + 8) return null

        val sourcePort = ((packet[udpOffset].toInt() and 0xFF) shl 8) or
                (packet[udpOffset + 1].toInt() and 0xFF)

        val destinationPort = ((packet[udpOffset + 2].toInt() and 0xFF) shl 8) or
                (packet[udpOffset + 3].toInt() and 0xFF)

        val udpLength = ((packet[udpOffset + 4].toInt() and 0xFF) shl 8) or
                (packet[udpOffset + 5].toInt() and 0xFF)

        return ParsedUdpHeader(
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            length = udpLength
        )
    }

    // Ricostruisce la stringa del dominio decodificando i vettori DNS QNAME
    fun parseDnsQuery(packet: ByteArray, dnsOffset: Int, length: Int): ParsedDnsQuery? {
        if (length < dnsOffset + 12) return null

        val qdCount = ((packet[dnsOffset + 4].toInt() and 0xFF) shl 8) or
                (packet[dnsOffset + 5].toInt() and 0xFF)

        if (qdCount < 1) return null

        var cursor = dnsOffset + 12
        val labels = mutableListOf<String>()

        while (cursor < length) {
            val labelLength = packet[cursor].toInt() and 0xFF
            cursor++

            if (labelLength == 0) break
            if (cursor + labelLength > length) return null

            val label = packet.copyOfRange(cursor, cursor + labelLength).toString(Charsets.UTF_8)
            labels.add(label)
            cursor += labelLength
        }

        if (cursor + 4 > length) return ParsedDnsQuery(
            domain = labels.joinToString(".").ifBlank { null },
            queryType = null
        )

        val queryType = ((packet[cursor].toInt() and 0xFF) shl 8) or
                (packet[cursor + 1].toInt() and 0xFF)

        return ParsedDnsQuery(
            domain = labels.joinToString(".").ifBlank { null },
            queryType = queryType
        )
    }

    // Identificatore testuale dei protocolli di trasporto standard
    fun protocolName(protocol: Int): String {
        return when (protocol) {
            1 -> "ICMP"
            6 -> "TCP"
            17 -> "UDP"
            else -> "IP-$protocol"
        }
    }
}