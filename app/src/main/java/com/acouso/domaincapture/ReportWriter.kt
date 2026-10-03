package com.acouso.domaincapture

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
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

        val txt = buildTxt(entries, label, start, end)
        val csv = buildCsv(entries)

        val dir = save(ctx, "$base.txt", "text/plain", txt)
        save(ctx, "$base.csv", "text/csv", csv)
        return "$dir/$base.txt (+ .csv)"
    }

    private fun buildTxt(entries: List<DomainEntry>, label: String, start: Long, end: Long): String = buildString {
        val dur = (end - start) / 1000
        appendLine("REPORTE DE DOMINIOS - Domain Capture TV")
        appendLine("=".repeat(60))
        appendLine("App analizada   : $label (${CaptureState.targetPackage})")
        appendLine("Inicio          : ${tsHuman.format(Date(start))}")
        appendLine("Fin             : ${tsHuman.format(Date(end))}")
        appendLine("Duración        : %02d:%02d:%02d".format(dur / 3600, dur / 60 % 60, dur % 60))
        appendLine("Consultas DNS   : ${CaptureState.totalQueries.get()}")
        appendLine("Dominios únicos : ${entries.size}")
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

        appendLine("== DETALLE ==")
        entries.forEach { e ->
            appendLine(e.name)
            val origin = if (e.queries.get() > 0) "consulta directa" else "solo vía CNAME"
            appendLine("   origen: $origin | consultas: ${e.queries.get()} | tipos: ${e.types.sorted().joinToString(",").ifEmpty { "-" }}")
            appendLine("   visto: ${tsShort.format(Date(e.firstSeen))} -> ${tsShort.format(Date(e.lastSeen))}")
            if (e.cnameTo.isNotEmpty()) appendLine("   CNAME -> ${e.cnameTo.sorted().joinToString(", ")}")
            if (e.aliasOf.isNotEmpty()) appendLine("   alias de: ${e.aliasOf.sorted().joinToString(", ")}")
            if (e.ips.isNotEmpty()) appendLine("   IPs: ${e.ips.sorted().joinToString(", ")}")
        }
    }

    private fun buildCsv(entries: List<DomainEntry>): String = buildString {
        fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""
        appendLine("dominio,dominio_base,origen,consultas,primera_vez,ultima_vez,tipos,ips,cname_destino,alias_de")
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
