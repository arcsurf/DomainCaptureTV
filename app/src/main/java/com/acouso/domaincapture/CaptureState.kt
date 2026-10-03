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
    /** IPs de los servidores DNS que respondieron por este dominio. */
    val dnsServers: MutableSet<String> = ConcurrentHashMap.newKeySet()
}

class DnsServerStat(val ip: String) {
    val answered = AtomicInteger(0)
    val failed = AtomicInteger(0)
    /** Cómo llegó la consulta: VIA_SYSTEM (DNS asignado por la VPN) o VIA_DIRECT (la app eligió este servidor). */
    val via: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val domains: MutableSet<String> = ConcurrentHashMap.newKeySet()

    companion object {
        const val VIA_SYSTEM = "sistema"
        const val VIA_DIRECT = "directo"
    }
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
    val dnsServers = ConcurrentHashMap<String, DnsServerStat>()
    /** DNS configurados en la red activa (router/ISP) al iniciar la captura. */
    @Volatile var networkDns: List<String> = emptyList()

    fun reset(pkg: String, label: String) {
        domains.clear()
        dnsServers.clear()
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

    private fun server(ip: String, direct: Boolean) = dnsServers.computeIfAbsent(ip) { DnsServerStat(it) }
        .also { it.via += if (direct) DnsServerStat.VIA_DIRECT else DnsServerStat.VIA_SYSTEM }

    /** Respuesta recibida de [serverIp]: asocia el servidor a los dominios preguntados y respondidos. */
    fun recordResponse(serverIp: String, direct: Boolean, msg: DnsMessage?) {
        val stat = server(serverIp, direct)
        stat.answered.incrementAndGet()
        if (msg == null) return
        msg.answers.forEach(::recordAnswer)
        val names = msg.questions.map { it.first } + msg.answers.map { it.name } +
            msg.answers.filter { it.type == DnsCodec.TYPE_CNAME }.map { it.data }
        names.filterNot(::ignored).toSet().forEach { name ->
            domains[name]?.dnsServers?.add(serverIp)
            stat.domains += name
        }
    }

    fun recordDnsFailure(serverIp: String, direct: Boolean) {
        server(serverIp, direct).failed.incrementAndGet()
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
