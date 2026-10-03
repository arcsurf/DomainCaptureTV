package com.acouso.domaincapture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketTest {

    private fun hex(s: String) = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** Suma de complemento a uno sobre un rango; un checksum válido da 0xFFFF. */
    private fun onesSum(b: ByteArray, off: Int, len: Int, initial: Long = 0): Int {
        var sum = initial
        var i = off
        while (i + 1 < off + len) { sum += IpPacket.u16(b, i); i += 2 }
        if (i < off + len) sum += (b[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.toInt()
    }

    private fun pseudo(p: ByteArray, proto: Int, len: Int): Long {
        var s = 0L
        for (i in 12 until 20 step 2) s += IpPacket.u16(p, i)
        return s + proto + len
    }

    // Respuesta real: www.netflix.com CNAME www.dradis.netflix.com, A 1.2.3.4 (con compresión)
    private val response = hex(
        "1234 8180 0001 0002 0000 0000" +
            "03777777 076e6574666c6978 03636f6d 00 0001 0001" +
            "c00c 0005 0001 0000003c 0009 06647261646973 c010" +
            "c02d 0001 0001 0000003c 0004 01020304"
    )

    @Test fun parsesDnsResponseWithCompression() {
        val msg = DnsCodec.parse(response, 0, response.size)
        assertNotNull(msg)
        msg!!
        assertTrue(msg.isResponse)
        assertEquals(listOf("www.netflix.com" to 1), msg.questions)
        assertEquals(DnsAnswer("www.netflix.com", 5, "dradis.netflix.com"), msg.answers[0])
        assertEquals(DnsAnswer("dradis.netflix.com", 1, "1.2.3.4"), msg.answers[1])
    }

    @Test fun udpPacketHasValidChecksums() {
        val p = IpPacket.buildUdp(byteArrayOf(10, 111, 222.toByte(), 1), byteArrayOf(10, 111, 222.toByte(), 2), 53, 40000, response, response.size)
        assertEquals(0xFFFF, onesSum(p, 0, 20))
        assertEquals(0xFFFF, onesSum(p, 20, p.size - 20, pseudo(p, 17, p.size - 20)))
    }

    @Test fun tcpResetForSyn() {
        // SYN 10.111.222.2:50000 -> 8.8.8.8:443, seq=1000
        val syn = ByteArray(40)
        syn[0] = 0x45; syn[3] = 40; syn[9] = 6
        byteArrayOf(10, 111, 222.toByte(), 2).copyInto(syn, 12)
        byteArrayOf(8, 8, 8, 8).copyInto(syn, 16)
        syn[20] = (50000 shr 8).toByte(); syn[21] = 50000.toByte()
        syn[22] = 1; syn[23] = 0xBB.toByte()
        syn[26] = 0x03; syn[27] = 0xE8.toByte()
        syn[32] = 0x50; syn[33] = 0x02
        val rst = IpPacket.buildTcpReset(syn, 20, 40)!!
        assertEquals(0xFFFF, onesSum(rst, 0, 20))
        assertEquals(0xFFFF, onesSum(rst, 20, 20, pseudo(rst, 6, 20)))
        assertEquals(443, IpPacket.u16(rst, 20))
        assertEquals(50000, IpPacket.u16(rst, 22))
        assertEquals(1001L, IpPacket.u32(rst, 28))
        assertEquals(0x14, rst[33].toInt())
    }

    @Test fun baseDomain() {
        assertEquals("nflxso.net", ReportWriter.baseDomain("occ-0-1.1.nflxso.net"))
        assertEquals("bbc.co.uk", ReportWriter.baseDomain("a.b.bbc.co.uk"))
        assertEquals("disneyplus.com", ReportWriter.baseDomain("disneyplus.com"))
    }
}
