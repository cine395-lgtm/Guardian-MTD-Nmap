package com.werebug.anmapwrapper

import java.io.ByteArrayOutputStream

object DnsPacketBuilder {

    // Costruisce la struttura IP/UDP attorno alla risposta DNS autorizzata ricevuta da Internet
    fun buildUdpIpv4Response(
        requestIpv4: ParsedIpv4Packet,
        requestPacket: ByteArray,
        requestLength: Int,
        dnsResponsePayload: ByteArray,
        dnsResponseLength: Int
    ): ByteArray {
        val udpOffset = requestIpv4.payloadOffset

        // Estrae gli IP originali per invertirli
        val srcIp = requestPacket.copyOfRange(12, 16)
        val dstIp = requestPacket.copyOfRange(16, 20)

        // Estrae le porte UDP originali per invertirle
        val srcPort = requestPacket.copyOfRange(udpOffset, udpOffset + 2)
        val dstPort = requestPacket.copyOfRange(udpOffset + 2, udpOffset + 4)

        val newUdpLength = 8 + dnsResponseLength
        val newTotalLength = 20 + newUdpLength

        val out = ByteArrayOutputStream()

        // Generazione dell'header IPv4 da 20 byte
        val ipHeader = ByteArray(20)
        ipHeader[0] = 0x45.toByte() // Versione 4, IHL 5 (5 * 4 = 20 byte)
        ipHeader[1] = 0 // Type of Service
        ipHeader[2] = ((newTotalLength shr 8) and 0xFF).toByte()
        ipHeader[3] = (newTotalLength and 0xFF).toByte()
        ipHeader[4] = requestPacket[4] // Mantiene l'ID identificativo originale
        ipHeader[5] = requestPacket[5]
        ipHeader[6] = requestPacket[6] // Flags & Fragment Offset
        ipHeader[7] = requestPacket[7]
        ipHeader[8] = 64.toByte() // TTL (Time to Live)
        ipHeader[9] = 17.toByte() // Protocollo 17 (UDP)
        ipHeader[10] = 0 // Reset temporaneo Checksum
        ipHeader[11] = 0

        // Inversione geometrica degli IP (Sorgente diventa Destinazione)
        for (i in 0 until 4) {
            ipHeader[12 + i] = dstIp[i]
            ipHeader[16 + i] = srcIp[i]
        }

        // Calcolo e iniezione del checksum IP hardware
        val ipChecksum = checksum(ipHeader)
        ipHeader[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        ipHeader[11] = (ipChecksum and 0xFF).toByte()

        // Generazione dell'header UDP da 8 byte
        val udpHeader = ByteArray(8)
        udpHeader[0] = dstPort[0] // Inversione porte
        udpHeader[1] = dstPort[1]
        udpHeader[2] = srcPort[0]
        udpHeader[3] = srcPort[1]
        udpHeader[4] = ((newUdpLength shr 8) and 0xFF).toByte() // Lunghezza UDP totale
        udpHeader[5] = (newUdpLength and 0xFF).toByte()
        udpHeader[6] = 0 // Reset temporaneo Checksum UDP
        udpHeader[7] = 0

        // Creazione del Pseudo-Header per il calcolo matematico del Checksum UDP
        val pseudo = ByteArrayOutputStream()
        pseudo.write(dstIp)
        pseudo.write(srcIp)
        pseudo.write(0)
        pseudo.write(17) // Codice UDP
        pseudo.write(byteArrayOf(
            ((newUdpLength shr 8) and 0xFF).toByte(),
            (newUdpLength and 0xFF).toByte()
        ))
        pseudo.write(udpHeader)
        pseudo.write(dnsResponsePayload, 0, dnsResponseLength)

        val udpChecksum = checksum(pseudo.toByteArray())
        udpHeader[6] = ((udpChecksum shr 8) and 0xFF).toByte()
        udpHeader[7] = (udpChecksum and 0xFF).toByte()

        // Assemblaggio finale del frame binario
        out.write(ipHeader)
        out.write(udpHeader)
        out.write(dnsResponsePayload, 0, dnsResponseLength)

        return out.toByteArray()
    }

    // Fabbrica da zero la finta risposta di blocco NXDOMAIN (Dominio Non Esistente)
    fun buildNxdomainResponse(
        requestIpv4: ParsedIpv4Packet,
        requestPacket: ByteArray,
        requestLength: Int
    ): ByteArray {
        val udpOffset = requestIpv4.payloadOffset
        val dnsOffset = udpOffset + 8

        if (requestLength <= dnsOffset || requestLength < dnsOffset + 12) {
            throw IllegalArgumentException("Pacchetto di richiesta DNS non valido o corrotto")
        }

        val dnsRequest = requestPacket.copyOfRange(dnsOffset, requestLength)
        val dnsResponse = dnsRequest.copyOf()

        // Manipolazione bit a bit dei Flag DNS: imposta la risposta e preserva il bit RD (Recursion Desired)
        val rdBit = dnsRequest[2].toInt() and 0x01
        dnsResponse[2] = (0x80 or rdBit).toByte() // Flag QR = 1 (Risposta)
        dnsResponse[3] = 0x83.toByte() // RCODE = 3 (NXDOMAIN - Nome dominio inesistente)

        // Svuota i contatori delle sezioni Answer, Authority e Additional per conformità standard RFC
        dnsResponse[6] = 0x00
        dnsResponse[7] = 0x00
        dnsResponse[8] = 0x00
        dnsResponse[9] = 0x00
        dnsResponse[10] = 0x00
        dnsResponse[11] = 0x00

        return buildUdpIpv4Response(
            requestIpv4 = requestIpv4,
            requestPacket = requestPacket,
            requestLength = requestLength,
            dnsResponsePayload = dnsResponse,
            dnsResponseLength = dnsResponse.size
        )
    }

    // Algoritmo di Checksum standard Internet (RFC 1071) - Somma a complemento a 1
    private fun checksum(data: ByteArray): Int {
        var sum = 0
        var i = 0

        while (i < data.size) {
            val high = data[i].toInt() and 0xFF
            val low = if (i + 1 < data.size) data[i + 1].toInt() and 0xFF else 0
            sum += (high shl 8) or low
            i += 2
        }

        while ((sum shr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return sum.inv() and 0xFFFF
    }
}