package com.acouso.domaincapture

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.Looper
import android.provider.MediaStore
import java.io.File
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Genera el reporte (TXT + CSV) y lo guarda en Download/DomainCapture del Android TV. */
object ReportWriter {

    const val FOLDER = "DomainCapture"

    private val tsFile = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
    private val tsHuman = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private val tsShort = SimpleDateFormat("HH:mm:ss", Locale.US)

    private val SECOND_LEVEL = setOf("co", "com", "net", "org", "gov", "edu", "ac", "gob", "mil")

    private val KNOWN_DNS = mapOf(
        "8.8.8.8" to "Google", "8.8.4.4" to "Google",
        "1.1.1.1" to "Cloudflare", "1.0.0.1" to "Cloudflare",
        "9.9.9.9" to "Quad9", "149.112.112.112" to "Quad9",
        "208.67.222.222" to "OpenDNS", "208.67.220.220" to "OpenDNS",
    )

    /** Describe un servidor DNS: "Google (público)", "red local (router)", "DNS de la red / ISP". */
    fun describeDnsServer(ip: String): String {
        KNOWN_DNS[ip]?.let { return "$it (público)" }
        val addr = try { InetAddress.getByName(ip) } catch (e: Exception) { null }
        val local = addr != null && (addr.isSiteLocalAddress || addr.isLinkLocalAddress || addr.isLoopbackAddress)
        val network = ip in CaptureState.networkDns
        return when {
            local -> "red local (router)"
            network -> "DNS de la red / ISP"
            else -> "otro"
        }
    }

    private fun viaText(via: Set<String>): String = via.sorted().joinToString(" + ") {
        if (it == DnsServerStat.VIA_DIRECT) "la app lo consultó directamente" else "DNS del sistema (reenviado por la VPN)"
    }

    /** Aproximación a eTLD+1: "occ-0-123.1.nflxso.net" -> "nflxso.net", "x.bbc.co.uk" -> "bbc.co.uk". */
    fun baseDomain(name: String): String {
        val parts = name.split('.')
        if (parts.size <= 2) return name
        val tld = parts[parts.size - 1]
        val sld = parts[parts.size - 2]
        val n = if (tld.length == 2 && sld in SECOND_LEVEL) 3 else 2
        return parts.takeLast(n).joinToString(".")
    }

    /** Escribe los archivos y devuelve la ruta visible para el usuario. */
    fun write(ctx: Context): String {
        val entries = CaptureState.domains.values.sortedBy { it.name }
        val start = CaptureState.startedAt
        val end = if (CaptureState.stoppedAt > 0) CaptureState.stoppedAt else System.currentTimeMillis()
        val label = CaptureState.targetLabel ?: "app"
        val safe = label.replace(Regex("[^A-Za-z0-9._-]+"), "_").trim('_').ifEmpty { "app" }
        val base = "dominios_${safe}_${tsFile.format(Date(start))}"

        // Las consultas a RIPEstat no pueden ir en el hilo principal (p.ej. al destruirse el servicio)
        val online = Looper.myLooper() != Looper.getMainLooper()
        val net = NetBlocks.build(entries, online) { CaptureState.status = "Analizando redes: $it" }
        val nets = "redes_${safe}_${tsFile.format(Date(start))}"

        val txt = buildTxt(entries, label, start, end, net, nets)
        val csv = buildCsv(entries, net)

        val dir = save(ctx, "$base.txt", "text/plain", txt)
        save(ctx, "$base.csv", "text/csv", csv)
        save(ctx, "$nets.txt", "text/plain", cidrList(net.full))
        save(ctx, "${nets}_min.txt", "text/plain", cidrList(net.minimal))
        return "$dir/$base.txt (+ .csv, $nets.txt)"
    }

    /** Un bloque CIDR por línea, IPv4 primero; listo para importar en la VPN / router. */
    private fun cidrList(blocks: List<Cidr>) = blocks.joinToString("") { "$it\n" }

    private fun countText(blocks: List<Cidr>) = "${blocks.size} bloques (${blocks.count { !it.v6 }} IPv4, ${blocks.count { it.v6 }} IPv6)"

    private fun StringBuilder.appendNetBlocks(net: NetReport, nets: String) {
        appendLine("== BLOQUES DE RED / CDN ==")
        if (!net.online) {
            appendLine("Sin consulta a RIPEstat: cada IP se amplió a /${NetBlocks.FALLBACK_V4} (IPv4) o /${NetBlocks.FALLBACK_V6} (IPv6).")
        } else {
            appendLine("Fuente: RIPEstat (tablas BGP de RIPE RIS). IP pública del TV: ${net.publicIp ?: "?"}" +
                if (net.ispAsns.isNotEmpty()) " (ISP: ${net.ispAsns.joinToString { "AS$it" }})" else "")
            appendLine("%-9s %-40s %5s %9s %9s %10s".format("ASN", "titular", "IPs", "dominios", "prefijos", "total ASN"))
            net.asns.forEach { a ->
                appendLine("%-9s %-40s %5d %9d %9d %10s".format(
                    "AS${a.asn}", a.holder.take(40), a.ips.size, a.domains.size, a.seenPrefixes.size,
                    when { a.isIsp -> "ISP" ; a.allPrefixes == null -> "error"; else -> a.allPrefixes!!.size.toString() },
                ))
            }
            if (net.asns.any { it.isIsp }) {
                appendLine("Nota: \"ISP\" = caché del CDN alojada en tu proveedor (Netflix OCA, Google GGC, Akamai…).")
                appendLine("      No se expande todo el ASN (sería la red entera del ISP); se usa /24 o /64 por IP.")
            }
            appendLine()
            net.asns.forEach { a ->
                appendLine("-- AS${a.asn} ${a.holder}")
                appendLine("   dominios: ${a.domains.joinToString(", ")}")
                appendLine("   prefijos con IPs observadas: ${a.seenPrefixes.joinToString(", ")}")
            }
            if (net.unresolved.isNotEmpty()) {
                appendLine("-- Sin prefijo BGP conocido (se usa /${NetBlocks.FALLBACK_V4} o /${NetBlocks.FALLBACK_V6}): ${net.unresolved.joinToString(", ")}")
            }
            net.errors.forEach { appendLine("!! $it") }
        }
        appendLine()
        appendLine("== LISTA MÍNIMA DE BLOQUES CIDR (${countText(net.minimal)}) ==")
        appendLine("Prefijos que contienen las IPs vistas en esta captura, sumarizados. Archivo: ${nets}_min.txt")
        net.minimal.forEach { appendLine(it.toString()) }
        appendLine()
        appendLine("== LISTA COMPLETA DE BLOQUES CIDR (${countText(net.full)}) ==")
        appendLine("Mínima + todos los prefijos de cada ASN de CDN (IPs que la app podría usar en otra sesión).")
        appendLine("Archivo: $nets.txt")
        net.full.forEach { appendLine(it.toString()) }
        appendLine()
    }

    private fun buildTxt(entries: List<DomainEntry>, label: String, start: Long, end: Long, net: NetReport, nets: String): String = buildString {
        val dur = (end - start) / 1000
        appendLine("REPORTE DE DOMINIOS - Domain Capture TV")
        appendLine("=".repeat(60))
        appendLine("App analizada   : $label (${CaptureState.targetPackage})")
        appendLine("Inicio          : ${tsHuman.format(Date(start))}")
        appendLine("Fin             : ${tsHuman.format(Date(end))}")
        appendLine("Duración        : %02d:%02d:%02d".format(dur / 3600, dur / 60 % 60, dur % 60))
        appendLine("Consultas DNS   : ${CaptureState.totalQueries.get()}")
        appendLine("Dominios únicos : ${entries.size}")
        appendLine("DNS de la red   : ${CaptureState.networkDns.joinToString(", ").ifEmpty { "no detectado (se usaron 8.8.8.8 / 1.1.1.1)" }}")
        appendLine()

        val servers = CaptureState.dnsServers.values.sortedByDescending { it.answered.get() }
        appendLine("== SERVIDORES DNS CONSULTADOS (${servers.size}) ==")
        appendLine("%-16s %-24s %10s %6s %9s  %s".format("IP", "tipo", "respuestas", "fallos", "dominios", "cómo llegó la consulta"))
        servers.forEach { s ->
            appendLine("%-16s %-24s %10d %6d %9d  %s".format(
                s.ip, describeDnsServer(s.ip), s.answered.get(), s.failed.get(), s.domains.size, viaText(s.via),
            ))
        }
        if (servers.any { describeDnsServer(it.ip) == "red local (router)" }) {
            appendLine("Nota: el router reenvía a su propio DNS (ISP u otro); ese salto no es visible desde el TV.")
        }
        appendLine()
        servers.filter { it.domains.isNotEmpty() }.forEach { s ->
            appendLine("-- ${s.ip} resolvió ${s.domains.size} dominios:")
            s.domains.sorted().forEach { appendLine("   $it") }
        }
        appendLine()

        appendLine("== LISTA DE DOMINIOS (${entries.size}) ==")
        entries.forEach { appendLine(it.name) }
        appendLine()

        val groups = entries.groupBy { baseDomain(it.name) }.toSortedMap()
        appendLine("== AGRUPADO POR DOMINIO BASE (${groups.size}) ==")
        groups.forEach { (b, list) ->
            val q = list.sumOf { it.queries.get() }
            appendLine("%-40s %3d subdominios  %5d consultas".format(b, list.size, q))
        }
        appendLine()

        appendNetBlocks(net, nets)

        appendLine("== DETALLE ==")
        entries.forEach { e ->
            appendLine(e.name)
            val origin = if (e.queries.get() > 0) "consulta directa" else "solo vía CNAME"
            appendLine("   origen: $origin | consultas: ${e.queries.get()} | tipos: ${e.types.sorted().joinToString(",").ifEmpty { "-" }}")
            appendLine("   visto: ${tsShort.format(Date(e.firstSeen))} -> ${tsShort.format(Date(e.lastSeen))}")
            if (e.cnameTo.isNotEmpty()) appendLine("   CNAME -> ${e.cnameTo.sorted().joinToString(", ")}")
            if (e.aliasOf.isNotEmpty()) appendLine("   alias de: ${e.aliasOf.sorted().joinToString(", ")}")
            if (e.ips.isNotEmpty()) appendLine("   IPs: ${e.ips.sorted().joinToString(", ")}")
            networksOf(e, net).takeIf { it.isNotEmpty() }?.let { appendLine("   redes: ${it.joinToString(", ")}") }
            if (e.dnsServers.isNotEmpty()) appendLine("   resuelto por DNS: ${e.dnsServers.sorted().joinToString(", ")}")
        }
    }

    /** Prefijos (con ASN) de las IPs de un dominio: "45.57.40.0/24 AS40027". */
    private fun networksOf(e: DomainEntry, net: NetReport): List<String> =
        e.ips.mapNotNull(Cidr::parse).filter(Cidr::isPublic).map { ip ->
            net.byIp[ip]?.let { (p, asns) -> "$p ${asns.joinToString("/") { "AS$it" }}" } ?: NetBlocks.fallbackBlock(ip).toString()
        }.distinct().sorted()

    private fun buildCsv(entries: List<DomainEntry>, net: NetReport): String = buildString {
        fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""
        appendLine("dominio,dominio_base,origen,consultas,primera_vez,ultima_vez,tipos,ips,cname_destino,alias_de,servidores_dns,redes")
        entries.forEach { e ->
            appendLine(
                listOf(
                    e.name,
                    baseDomain(e.name),
                    if (e.queries.get() > 0) "consulta" else "cname",
                    e.queries.get().toString(),
                    tsHuman.format(Date(e.firstSeen)),
                    tsHuman.format(Date(e.lastSeen)),
                    e.types.sorted().joinToString(" "),
                    e.ips.sorted().joinToString(" "),
                    e.cnameTo.sorted().joinToString(" "),
                    e.aliasOf.sorted().joinToString(" "),
                    e.dnsServers.sorted().joinToString(" "),
                    networksOf(e, net).joinToString(" | "),
                ).joinToString(",") { q(it) }
            )
        }
    }

    /** Guarda en Download/DomainCapture. Devuelve el directorio usado. */
    private fun save(ctx: Context, name: String, mime: String, content: String): String {
        val bytes = content.toByteArray(Charsets.UTF_8)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val resolver = ctx.contentResolver
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, mime)
                    put(MediaStore.Downloads.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/$FOLDER")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IllegalStateException("MediaStore insert falló")
                resolver.openOutputStream(uri)!!.use { it.write(bytes) }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(uri, values, null, null)
                return "/sdcard/${Environment.DIRECTORY_DOWNLOADS}/$FOLDER"
            } catch (e: Exception) {
                // cae al almacenamiento propio de la app
            }
        } else {
            try {
                @Suppress("DEPRECATION")
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), FOLDER)
                dir.mkdirs()
                File(dir, name).writeBytes(bytes)
                return dir.absolutePath
            } catch (e: Exception) {
                // sin permiso de almacenamiento -> almacenamiento propio
            }
        }
        val dir = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, FOLDER)
        dir.mkdirs()
        File(dir, name).writeBytes(bytes)
        return dir.absolutePath
    }
}
