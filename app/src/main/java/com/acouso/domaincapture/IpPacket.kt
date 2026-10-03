package com.acouso.domaincapture

/** Utilidades para leer y construir paquetes IPv4 / UDP / TCP crudos del túnel. */
object IpPacket {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    fun u32(b: ByteArray, i: Int): Long =
        (u16(b, i).toLong() shl 16) or u16(b, i + 2).toLong()

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v shr 8).toByte()
        b[i + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, i: Int, v: Long) {
        put16(b, i, (v shr 16).toInt() and 0xFFFF)
        put16(b, i + 2, v.toInt() and 0xFFFF)
    }

    private fun checksum(b: ByteArray, off: Int, len: Int, initial: Long = 0): Int {
        var sum = initial
        var i = off
        while (i + 1 < off + len) {
            sum += u16(b, i)
            i += 2
        }
        if (i < off + len) sum += (b[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun pseudoHeaderSum(src: ByteArray, dst: ByteArray, proto: Int, len: Int): Long {
        var sum = 0L
        for (i in 0 until 4 step 2) sum += u16(src, i) + u16(dst, i)
        return sum + proto + len
    }

    private fun ipHeader(out: ByteArray, totalLen: Int, proto: Int, src: ByteArray, dst: ByteArray) {
        out[0] = 0x45
        put16(out, 2, totalLen)
        put16(out, 6, 0x4000) // Don't Fragment
        out[8] = 64
        out[9] = proto.toByte()
        System.arraycopy(src, 0, out, 12, 4)
        System.arraycopy(dst, 0, out, 16, 4)
        put16(out, 10, checksum(out, 0, 20))
    }

    fun buildUdp(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray, payloadLen: Int): ByteArray {
        val udpLen = 8 + payloadLen
        val out = ByteArray(20 + udpLen)
        ipHeader(out, out.size, PROTO_UDP, src, dst)
        put16(out, 20, srcPort)
        put16(out, 22, dstPort)
        put16(out, 24, udpLen)
        System.arraycopy(payload, 0, out, 28, payloadLen)
        var cs = checksum(out, 20, udpLen, pseudoHeaderSum(src, dst, PROTO_UDP, udpLen))
        if (cs == 0) cs = 0xFFFF
        put16(out, 26, cs)
        return out
    }

    /**
     * Genera un TCP RST para un segmento recibido (RFC 793). Se usa para rechazar al instante
     * DNS-over-TCP / DoT / DoH hacia los resolvers interceptados, forzando a la app a usar DNS por UDP.
     */
    fun buildTcpReset(pkt: ByteArray, ihl: Int, totalLen: Int): ByteArray? {
        val t = ihl
        if (totalLen < t + 20) return null
        val flags = pkt[t + 13].toInt() and 0xFF
        if (flags and 0x04 != 0) return null // no respondemos a un RST

        val src = pkt.copyOfRange(12, 16)
        val dst = pkt.copyOfRange(16, 20)
        val srcPort = u16(pkt, t)
        val dstPort = u16(pkt, t + 2)
        val seq = u32(pkt, t + 4)
        val ack = u32(pkt, t + 8)
        val dataOff = ((pkt[t + 12].toInt() shr 4) and 0x0F) * 4
        var segLen = (totalLen - t - dataOff).coerceAtLeast(0).toLong()
        if (flags and 0x02 != 0) segLen++ // SYN
        if (flags and 0x01 != 0) segLen++ // FIN

        val out = ByteArray(40)
        ipHeader(out, 40, PROTO_TCP, dst, src)
        put16(out, 20, dstPort)
        put16(out, 22, srcPort)
        if (flags and 0x10 != 0) { // ACK presente
            put32(out, 24, ack)
            out[33] = 0x04 // RST
        } else {
            put32(out, 28, (seq + segLen) and 0xFFFFFFFFL)
            out[33] = 0x14 // RST + ACK
        }
        out[32] = (5 shl 4).toByte()
        put16(out, 36, checksum(out, 20, 20, pseudoHeaderSum(dst, src, PROTO_TCP, 20)))
        return out
    }
}
