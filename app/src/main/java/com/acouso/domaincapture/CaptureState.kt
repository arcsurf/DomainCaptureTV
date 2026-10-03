package com.acouso.domaincapture

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class DomainEntry(val name: String, val firstSeen: Long) {
    @Volatile var lastSeen: Long = firstSeen
    val queries = AtomicInteger(0)
    val types: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val ips: MutableSet<String> = ConcurrentHashMap.newKeySet()
    /** Este dominio es alias (CNAME) de... */
    val cnameTo: MutableSet<String> = ConcurrentHashMap.newKeySet()
    /** Este dominio apareció como destino CNAME de... */
    val aliasOf: MutableSet<String> = ConcurrentHashMap.newKeySet()
}

/** Estado compartido entre el servicio VPN y la UI (mismo proceso). */
object CaptureState {
    @Volatile var running = false
    @Volatile var targetPackage: String? = null
    @Volatile var targetLabel: String? = null
    @Volatile var startedAt = 0L
    @Volatile var stoppedAt = 0L
    @Volatile var status = "Listo"
    @Volatile var lastReport: String? = null
    @Volatile var autoStopActive = false
    val totalQueries = AtomicInteger(0)
    val domains = ConcurrentHashMap<String, DomainEntry>()

    fun reset(pkg: String, label: String) {
        domains.clear()
        totalQueries.set(0)
        targetPackage = pkg
        targetLabel = label
        startedAt = System.currentTimeMillis()
        stoppedAt = 0L
        lastReport = null
    }

    private fun entry(name: String): DomainEntry {
        val now = System.currentTimeMillis()
        return domains.computeIfAbsent(name) { DomainEntry(it, now) }.also { it.lastSeen = now }
    }

    private fun ignored(name: String) = name.isEmpty() || name.endsWith(".arpa") || !name.contains('.')

    fun recordQuery(name: String, type: Int) {
        if (ignored(name)) return
        totalQueries.incrementAndGet()
        entry(name).apply {
            queries.incrementAndGet()
            types += DnsCodec.typeName(type)
        }
    }

    fun recordAnswer(answer: DnsAnswer) {
        if (ignored(answer.name)) return
        when (answer.type) {
            DnsCodec.TYPE_CNAME -> {
                entry(answer.name).cnameTo += answer.data
                if (!ignored(answer.data)) entry(answer.data).aliasOf += answer.name
            }
            else -> entry(answer.name).ips += answer.data
        }
    }
}
