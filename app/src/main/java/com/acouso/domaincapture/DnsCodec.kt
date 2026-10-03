package com.acouso.domaincapture

import java.net.InetAddress

data class DnsAnswer(val name: String, val type: Int, val data: String)

data class DnsMessage(
    val id: Int,
    val isResponse: Boolean,
    val questions: List<Pair<String, Int>>,
    val answers: List<DnsAnswer>,
)

/** Parser mínimo de mensajes DNS (RFC 1035): preguntas + respuestas A / AAAA / CNAME. */
object DnsCodec {

    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28

    fun typeName(type: Int): String = when (type) {
        1 -> "A"
        5 -> "CNAME"
        12 -> "PTR"
        16 -> "TXT"
        28 -> "AAAA"
        33 -> "SRV"
        64 -> "SVCB"
        65 -> "HTTPS"
        else -> "TYPE$type"
    }

    fun parse(buf: ByteArray, off: Int, len: Int): DnsMessage? {
        if (len < 12) return null
        val end = off + len
        return try {
            val id = u16(buf, off)
            val flags = u16(buf, off + 2)
            val qdCount = u16(buf, off + 4)
            val anCount = u16(buf, off + 6)
            var p = off + 12

            val questions = ArrayList<Pair<String, Int>>(qdCount)
            repeat(qdCount) {
                val (name, next) = readName(buf, off, p, end)
                p = next
                questions += name to u16(buf, p)
                p += 4
            }

            val answers = ArrayList<DnsAnswer>(anCount)
            for (i in 0 until anCount) {
                if (p >= end) break
                val (name, next) = readName(buf, off, p, end)
                p = next
                val type = u16(buf, p)
                val rdLen = u16(buf, p + 8)
                p += 10
                if (p + rdLen > end) break
                when (type) {
                    TYPE_A -> if (rdLen == 4)
                        answers += DnsAnswer(name, type, InetAddress.getByAddress(buf.copyOfRange(p, p + 4)).hostAddress!!)
                    TYPE_AAAA -> if (rdLen == 16)
                        answers += DnsAnswer(name, type, InetAddress.getByAddress(buf.copyOfRange(p, p + 16)).hostAddress!!)
                    TYPE_CNAME -> answers += DnsAnswer(name, type, readName(buf, off, p, end).first)
                }
                p += rdLen
            }
            DnsMessage(id, flags and 0x8000 != 0, questions, answers)
        } catch (e: Exception) {
            null
        }
    }

    /** Lee un nombre DNS (con soporte de punteros de compresión). Devuelve el nombre y la posición siguiente. */
    private fun readName(buf: ByteArray, msgStart: Int, start: Int, end: Int): Pair<String, Int> {
        val sb = StringBuilder()
        var p = start
        var nextAfterName = -1
        var jumps = 0
        while (true) {
            if (p >= end) throw IndexOutOfBoundsException()
            val len = buf[p].toInt() and 0xFF
            when {
                len == 0 -> {
                    if (nextAfterName < 0) nextAfterName = p + 1
                    break
                }
                len and 0xC0 == 0xC0 -> {
                    if (p + 1 >= end || ++jumps > 32) throw IllegalStateException("bad pointer")
                    if (nextAfterName < 0) nextAfterName = p + 2
                    p = msgStart + (((len and 0x3F) shl 8) or (buf[p + 1].toInt() and 0xFF))
                }
                else -> {
                    if (p + 1 + len > end) throw IndexOutOfBoundsException()
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(buf, p + 1, len, Charsets.US_ASCII))
                    p += 1 + len
                }
            }
        }
        return sb.toString().lowercase() to nextAfterName
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
}
