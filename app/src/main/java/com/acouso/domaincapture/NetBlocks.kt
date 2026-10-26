package com.acouso.domaincapture

import android.util.Log
import org.json.JSONObject
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.net.URLEncoder

/** Bloque de red IPv4/IPv6 en notación CIDR (la dirección siempre queda alineada a la máscara). */
class Cidr private constructor(val v6: Boolean, val addr: BigInteger, val len: Int) : Comparable<Cidr> {

    val bits get() = if (v6) 128 else 32
    private val size get() = BigInteger.ONE.shiftLeft(bits - len)

    fun contains(o: Cidr) = v6 == o.v6 && o.len >= len && o.addr.shiftRight(bits - len) == addr.shiftRight(bits - len)

    /** Bloque que contiene a este con máscara [newLen] (más corta). */
    fun widen(newLen: Int) = of(v6, addr, minOf(newLen, len))

    /** true si este y [o] son las dos mitades de un mismo bloque /len-1. */
    fun isSiblingOf(o: Cidr) = v6 == o.v6 && len == o.len && len > 0 &&
        !addr.testBit(bits - len) && o.addr == addr + size

    fun parent() = of(v6, addr, len - 1)

    override fun compareTo(other: Cidr): Int =
        compareValuesBy(this, other, { it.v6 }, { it.addr }, { it.len })

    override fun equals(other: Any?) = other is Cidr && v6 == other.v6 && addr == other.addr && len == other.len
    override fun hashCode() = addr.hashCode() * 31 + len + if (v6) 1000 else 0

    override fun toString(): String = "${format(v6, addr)}/$len"

    companion object {
        private val NUMERIC = Regex("^[0-9A-Fa-f:.]+$")

        fun of(v6: Boolean, addr: BigInteger, len: Int): Cidr {
            val bits = if (v6) 128 else 32
            val mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
                .xor(BigInteger.ONE.shiftLeft(bits - len).subtract(BigInteger.ONE))
            return Cidr(v6, addr.and(mask), len)
        }

        /** "1.2.3.0/24", "2a00:86c0::/32" o una IP suelta (-> /32 o /128). Null si no es válida. */
        fun parse(s: String): Cidr? {
            val parts = s.trim().split('/')
            if (parts.size > 2 || !NUMERIC.matches(parts[0])) return null
            val bytes = try { InetAddress.getByName(parts[0]).address } catch (e: Exception) { return null }
            val v6 = bytes.size == 16
            val bits = bytes.size * 8
            val len = if (parts.size == 2) parts[1].toIntOrNull() ?: return null else bits
            if (len !in 0..bits) return null
            return of(v6, BigInteger(1, bytes), len)
        }

        private fun format(v6: Boolean, addr: BigInteger): String {
            if (!v6) return (3 downTo 0).joinToString(".") { addr.shiftRight(it * 8).toInt().and(0xFF).toString() }
            val groups = (7 downTo 0).map { addr.shiftRight(it * 16).toInt() and 0xFFFF }
            // Comprime la racha de ceros más larga (mínimo 2 grupos) con "::"
            var bestStart = -1; var bestLen = 1
            var i = 0
            while (i < 8) {
                if (groups[i] == 0) {
                    var j = i
                    while (j < 8 && groups[j] == 0) j++
                    if (j - i > bestLen) { bestStart = i; bestLen = j - i }
                    i = j
                } else i++
            }
            val hex = groups.map { Integer.toHexString(it) }
            if (bestStart < 0) return hex.joinToString(":")
            return hex.subList(0, bestStart).joinToString(":") + "::" + hex.subList(bestStart + bestLen, 8).joinToString(":")
        }

        /** Sumariza sin pérdida: quita bloques contenidos en otros y une mitades contiguas. */
        fun aggregate(input: Collection<Cidr>): List<Cidr> {
            val stack = ArrayList<Cidr>()
            for (c in input.toSortedSet()) {
                if (stack.isNotEmpty() && stack.last().contains(c)) continue
                stack += c
                while (stack.size >= 2 && stack[stack.size - 2].isSiblingOf(stack.last())) {
                    val p = stack.removeAt(stack.size - 2).parent()
                    stack[stack.size - 1] = p
                }
            }
            return stack
        }

        private val RESERVED = listOf(
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
            "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
            "::/127", "64:ff9b::/96", "fc00::/7", "fe80::/10", "ff00::/8",
        ).map { parse(it)!! }

        fun isPublic(c: Cidr) = RESERVED.none { it.contains(c) }
    }
}

/** Un sistema autónomo (ASN) que sirvió contenido a la app. */
class AsnInfo(val asn: String) {
    var holder = ""
    /** Prefijos BGP anunciados que contienen IPs observadas. */
    val seenPrefixes = sortedSetOf<Cidr>()
    val ips = sortedSetOf<Cidr>()
    val domains = sortedSetOf<String>()
    /** Todos los prefijos que origina el ASN (null si no se expandió o no se pudo consultar). */
    var allPrefixes: List<Cidr>? = null
    /** ASN del propio proveedor de Internet (cachés embebidas tipo Netflix OCA, Google GGC, Akamai AANP). */
    var isIsp = false
}

class NetReport(
    val online: Boolean,
    val publicIp: String?,
    val ispAsns: Set<String>,
    val asns: List<AsnInfo>,
    /** IP -> (prefijo anunciado, ASNs de origen). */
    val byIp: Map<Cidr, Pair<Cidr, List<String>>>,
    /** IPs para las que no se encontró prefijo (se cubren con /24 o /48). */
    val unresolved: List<Cidr>,
    /** Prefijos que contienen las IPs observadas, sumarizados. */
    val minimal: List<Cidr>,
    /** [minimal] + todos los prefijos de cada ASN de CDN, sumarizados. */
    val full: List<Cidr>,
    val errors: List<String>,
)

/**
 * Convierte las IPs resueltas en bloques de red usando RIPEstat (datos BGP de RIPE RIS):
 * IP -> prefijo anunciado + ASN -> todos los prefijos del ASN -> sumarización CIDR.
 */
object NetBlocks {

    private const val TAG = "NetBlocks"
    private const val API = "https://stat.ripe.net/data"
    const val FALLBACK_V4 = 24
    const val FALLBACK_V6 = 48
    /** Para cachés dentro del ISP no se expande el ASN (sería toda la red del proveedor). */
    private const val ISP_V4 = 24
    private const val ISP_V6 = 64

    fun fallbackBlock(ip: Cidr) = ip.widen(if (ip.v6) FALLBACK_V6 else FALLBACK_V4)

    fun build(entries: List<DomainEntry>, online: Boolean, progress: (String) -> Unit = {}): NetReport {
        val ipDomains = sortedMapOf<Cidr, MutableSet<String>>()
        entries.forEach { e ->
            e.ips.mapNotNull(Cidr::parse).filter(Cidr::isPublic).forEach { ipDomains.getOrPut(it) { sortedSetOf() } += e.name }
        }
        val errors = ArrayList<String>()

        if (!online || ipDomains.isEmpty()) {
            val blocks = Cidr.aggregate(ipDomains.keys.map(::fallbackBlock))
            return NetReport(false, null, emptySet(), emptyList(), emptyMap(), ipDomains.keys.toList(), blocks, blocks, errors)
        }

        // ASN del proveedor de Internet (IP pública del TV)
        progress("Consultando IP pública…")
        val publicIp = try { get("whats-my-ip", emptyMap())?.optString("ip")?.ifEmpty { null } } catch (e: Exception) { errors += "whats-my-ip: ${e.message}"; null }
        val ispAsns = publicIp?.let { ip -> try { networkInfo(ip)?.second?.toSet() } catch (e: Exception) { null } } ?: emptySet()

        // IP -> prefijo anunciado. Los prefijos globales no son más específicos que /24 (v4) o /48 (v6),
        // así que una consulta por bloque /24 o /48 alcanza para todas sus IPs.
        val byIp = LinkedHashMap<Cidr, Pair<Cidr, List<String>>>()
        val cache = HashMap<Cidr, Pair<Cidr, List<String>>?>()
        val unresolved = ArrayList<Cidr>()
        var n = 0
        for (ip in ipDomains.keys) {
            val key = fallbackBlock(ip)
            if (key !in cache) {
                progress("Consultando prefijos BGP (${++n})…")
                cache[key] = try {
                    networkInfo(ip.toString().substringBefore('/'))
                } catch (e: Exception) {
                    errors += "network-info $ip: ${e.message}"; null
                }
            }
            val info = cache[key]
            if (info == null || info.second.isEmpty()) unresolved += ip else byIp[ip] = info
        }

        val asns = sortedMapOf<String, AsnInfo>(compareBy({ it.toLongOrNull() ?: Long.MAX_VALUE }, { it }))
        byIp.forEach { (ip, info) ->
            info.second.forEach { asn ->
                asns.getOrPut(asn) { AsnInfo(asn) }.apply {
                    seenPrefixes += info.first
                    ips += ip
                    domains += ipDomains[ip].orEmpty()
                    isIsp = asn in ispAsns
                }
            }
        }

        asns.values.forEachIndexed { i, a ->
            progress("Consultando AS${a.asn} (${i + 1}/${asns.size})…")
            a.holder = try { get("as-overview", mapOf("resource" to "AS${a.asn}"))?.optString("holder").orEmpty() } catch (e: Exception) { "" }
            if (a.isIsp) return@forEachIndexed
            a.allPrefixes = try {
                asPrefixes(a.asn)
            } catch (e: Exception) {
                errors += "ris-prefixes AS${a.asn}: ${e.message}"; null
            }
        }

        val minimalSet = ArrayList<Cidr>()
        asns.values.forEach { a ->
            if (a.isIsp) a.ips.forEach { minimalSet += it.widen(if (it.v6) ISP_V6 else ISP_V4) }
            else minimalSet += a.seenPrefixes
        }
        unresolved.forEach { minimalSet += fallbackBlock(it) }
        val minimal = Cidr.aggregate(minimalSet)
        val full = Cidr.aggregate(minimal + asns.values.flatMap { it.allPrefixes.orEmpty() })
        return NetReport(true, publicIp, ispAsns, asns.values.toList(), byIp, unresolved, minimal, full, errors)
    }

    /** Prefijo anunciado más específico que contiene [ip] y sus ASNs de origen. */
    private fun networkInfo(ip: String): Pair<Cidr, List<String>>? {
        val d = get("network-info", mapOf("resource" to ip)) ?: return null
        val prefix = Cidr.parse(d.optString("prefix")) ?: return null
        val arr = d.optJSONArray("asns") ?: return null
        return prefix to (0 until arr.length()).map { arr.getString(it) }
    }

    /** Todos los prefijos (v4 y v6) que origina el ASN según RIPE RIS. */
    private fun asPrefixes(asn: String): List<Cidr> {
        val d = get("ris-prefixes", mapOf("resource" to "AS$asn", "list_prefixes" to "true", "types" to "o", "noise" to "filter"))
            ?: return emptyList()
        val p = d.optJSONObject("prefixes") ?: return emptyList()
        return listOf("v4", "v6").flatMap { fam ->
            val arr = p.optJSONObject(fam)?.optJSONArray("originating") ?: return@flatMap emptyList()
            (0 until arr.length()).mapNotNull { Cidr.parse(arr.getString(it)) }
        }
    }

    /** GET a la API de RIPEstat; devuelve el objeto "data". */
    private fun get(call: String, params: Map<String, String>): JSONObject? {
        val q = (params + ("sourceapp" to "DomainCaptureTV")).entries
            .joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}" }
        val conn = URL("$API/$call/data.json?$q").openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 10_000
            conn.readTimeout = 30_000
            conn.setRequestProperty("User-Agent", "DomainCaptureTV")
            if (conn.responseCode != 200) {
                Log.w(TAG, "$call -> HTTP ${conn.responseCode}")
                throw IllegalStateException("HTTP ${conn.responseCode}")
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            return JSONObject(body).optJSONObject("data")
        } finally {
            conn.disconnect()
        }
    }
}
