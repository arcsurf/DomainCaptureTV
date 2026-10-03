package com.acouso.domaincapture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * VPN local "solo DNS" aplicada únicamente a la app objetivo (addAllowedApplication).
 *
 * - La app objetivo recibe como DNS un resolver ficticio (10.111.222.1) que vive dentro del túnel.
 * - Las consultas DNS se registran y se reenvían al DNS real con un socket protegido.
 * - El resto del tráfico de la app NO pasa por el túnel (solo hay rutas /32), así que el streaming
 *   funciona a velocidad normal.
 * - Las IPs de resolvers públicos conocidos también se enrutan al túnel: el UDP/53 se captura igual y
 *   cualquier TCP (DoT/DoH/DNS-TCP) recibe un RST para forzar el uso de DNS clásico.
 */
class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "DomainCapture"
        const val ACTION_START = "com.acouso.domaincapture.START"
        const val ACTION_STOP = "com.acouso.domaincapture.STOP"
        const val EXTRA_PKG = "pkg"
        const val EXTRA_LABEL = "label"
        const val EXTRA_AUTOSTOP = "autostop"

        private const val VPN_ADDR = "10.111.222.2"
        private const val FAKE_DNS = "10.111.222.1"
        private val PUBLIC_DNS = listOf(
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220",
        )
        /** Tiempo que la app objetivo debe estar fuera de primer plano para cortar la captura. */
        private const val LEAVE_GRACE_MS = 8_000L

        private const val CHANNEL = "capture"
        private const val NOTIF_RUNNING = 1
        private const val NOTIF_DONE = 2
    }

    private var tun: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    private var pool: ExecutorService? = null
    private var upstreams: List<InetAddress> = emptyList()
    private val fakeDns: InetAddress = InetAddress.getByName(FAKE_DNS)
    private val stopLock = Any()

    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startCapture(
                intent.getStringExtra(EXTRA_PKG) ?: return START_NOT_STICKY,
                intent.getStringExtra(EXTRA_LABEL) ?: "",
                intent.getBooleanExtra(EXTRA_AUTOSTOP, true),
            )
            ACTION_STOP -> Thread { stopCapture("Detenido por el usuario") }.start()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Thread { stopCapture("VPN revocada por el sistema") }.start()
    }

    override fun onDestroy() {
        if (running) stopCapture("Servicio finalizado")
        super.onDestroy()
    }

    // ---------------------------------------------------------------- inicio / fin

    private fun startCapture(pkg: String, label: String, autoStop: Boolean) {
        if (running) return
        val networkDns = detectNetworkDns()
        upstreams = (networkDns + listOf(InetAddress.getByName("8.8.8.8"), InetAddress.getByName("1.1.1.1"))).distinct()
        CaptureState.reset(pkg, label.ifEmpty { pkg })
        CaptureState.networkDns = networkDns.mapNotNull { it.hostAddress }

        val builder = Builder()
            .setSession("Domain Capture: ${label.ifEmpty { pkg }}")
            .setMtu(1500)
            .addAddress(VPN_ADDR, 32)
            .addDnsServer(FAKE_DNS)
            .addRoute(FAKE_DNS, 32)
        PUBLIC_DNS.forEach { builder.addRoute(it, 32) }
        builder.allowFamily(OsConstants.AF_INET6) // IPv6 sigue por la red normal
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        try {
            builder.addAllowedApplication(pkg)
        } catch (e: Exception) {
            CaptureState.status = "No se encontró la app $pkg"
            stopSelf()
            return
        }

        val iface = try { builder.establish() } catch (e: Exception) { null }
        if (iface == null) {
            CaptureState.status = "No se pudo crear la VPN (¿permiso denegado?)"
            stopSelf()
            return
        }
        tun = iface
        tunOut = FileOutputStream(iface.fileDescriptor)
        pool = Executors.newFixedThreadPool(8)
        running = true
        CaptureState.running = true
        CaptureState.autoStopActive = autoStop && UsageAccess.granted(this)
        CaptureState.status = "Capturando DNS de ${CaptureState.targetLabel}" +
            if (CaptureState.autoStopActive) " (se detiene sola al cerrar la app)" else " (detener manualmente)"

        goForeground()
        Thread(::readLoop, "tun-reader").start()
        if (CaptureState.autoStopActive) Thread({ monitorLoop(pkg) }, "app-monitor").start()
        Log.i(TAG, "Captura iniciada para $pkg, upstream=$upstreams")
    }

    private fun stopCapture(reason: String) {
        synchronized(stopLock) {
            if (!running) return
            running = false
            CaptureState.running = false
            CaptureState.stoppedAt = System.currentTimeMillis()
            try { tun?.close() } catch (_: Exception) {}
            tun = null
            pool?.shutdownNow()

            val result = try {
                "Reporte guardado en ${ReportWriter.write(this)}"
            } catch (e: Exception) {
                Log.e(TAG, "Error guardando reporte", e)
                "Error guardando reporte: ${e.message}"
            }
            CaptureState.lastReport = result
            CaptureState.status = "$reason. ${CaptureState.domains.size} dominios. $result"

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
            notifyDone(reason, result)
            stopSelf()
        }
    }

    // ---------------------------------------------------------------- túnel

    private fun readLoop() {
        val fd = tun?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val buf = ByteArray(32767)
        val pollFd = StructPollfd().apply {
            this.fd = fd
            events = OsConstants.POLLIN.toShort()
        }
        while (running) {
            try {
                if (Os.poll(arrayOf(pollFd), 500) <= 0) continue
                val n = input.read(buf)
                if (n > 0) handlePacket(buf.copyOf(n), n)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                break
            } catch (e: Exception) {
                if (running) Log.w(TAG, "readLoop", e)
                break
            }
        }
    }

    private fun handlePacket(pkt: ByteArray, n: Int) {
        if (n < 20 || (pkt[0].toInt() shr 4) and 0x0F != 4) return
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        val totalLen = minOf(IpPacket.u16(pkt, 2), n)
        when (pkt[9].toInt() and 0xFF) {
            IpPacket.PROTO_UDP -> {
                if (totalLen < ihl + 8) return
                val srcPort = IpPacket.u16(pkt, ihl)
                val dstPort = IpPacket.u16(pkt, ihl + 2)
                if (dstPort != 53) return
                val payload = pkt.copyOfRange(ihl + 8, totalLen)
                val src = pkt.copyOfRange(12, 16)
                val dst = pkt.copyOfRange(16, 20)
                DnsCodec.parse(payload, 0, payload.size)?.questions?.forEach { (name, type) ->
                    CaptureState.recordQuery(name, type)
                }
                try {
                    pool?.execute { forwardDns(src, dst, srcPort, payload) }
                } catch (_: Exception) {}
            }
            IpPacket.PROTO_TCP -> IpPacket.buildTcpReset(pkt, ihl, totalLen)?.let(::writeTun)
        }
    }

    private fun forwardDns(src: ByteArray, dst: ByteArray, srcPort: Int, query: ByteArray) {
        val dstAddr = InetAddress.getByAddress(dst)
        val direct = dstAddr != fakeDns
        val targets = if (direct) listOf(dstAddr) else upstreams
        for (server in targets) {
            val serverIp = server.hostAddress ?: continue
            try {
                DatagramSocket().use { sock ->
                    protect(sock)
                    sock.soTimeout = 4000
                    sock.send(DatagramPacket(query, query.size, server, 53))
                    val resp = ByteArray(4096)
                    val pkt = DatagramPacket(resp, resp.size)
                    sock.receive(pkt)
                    CaptureState.recordResponse(serverIp, direct, DnsCodec.parse(resp, 0, pkt.length))
                    writeTun(IpPacket.buildUdp(dst, src, 53, srcPort, resp, pkt.length))
                }
                return
            } catch (e: Exception) {
                if (!running) return
                CaptureState.recordDnsFailure(serverIp, direct)
            }
        }
    }

    private fun writeTun(packet: ByteArray) {
        val out = tunOut ?: return
        synchronized(out) {
            try { if (running) out.write(packet) } catch (_: Exception) {}
        }
    }

    /** DNS IPv4 de la red activa (normalmente el router o el ISP). */
    private fun detectNetworkDns(): List<InetAddress> {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return try {
            cm.activeNetwork?.let { cm.getLinkProperties(it)?.dnsServers }.orEmpty()
                .filter { it is Inet4Address && it != fakeDns }
        } catch (e: Exception) { emptyList() }
    }

    // ---------------------------------------------------------------- detección de cierre de la app

    /**
     * Mira los eventos de UsageStats: cuando la app objetivo estuvo en primer plano y luego otra
     * actividad (launcher, otra app, esta misma app) pasa a primer plano durante más de
     * LEAVE_GRACE_MS, se detiene la captura y se genera el reporte.
     */
    private fun monitorLoop(target: String) {
        val usm = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        var lastTs = System.currentTimeMillis() - 5_000
        var targetSeen = false
        var leftAt = 0L
        val ev = UsageEvents.Event()
        while (running) {
            try { Thread.sleep(1500) } catch (_: InterruptedException) { return }
            val now = System.currentTimeMillis()
            val events = try { usm.queryEvents(now - 30_000, now) } catch (e: Exception) { null } ?: continue
            while (events.hasNextEvent()) {
                events.getNextEvent(ev)
                if (ev.timeStamp <= lastTs) continue
                lastTs = ev.timeStamp
                // 1 = ACTIVITY_RESUMED / MOVE_TO_FOREGROUND
                if (ev.eventType != 1) continue
                if (ev.packageName == target) {
                    targetSeen = true
                    leftAt = 0L
                } else if (targetSeen && leftAt == 0L) {
                    leftAt = ev.timeStamp
                }
            }
            if (targetSeen && leftAt > 0 && now - leftAt >= LEAVE_GRACE_MS) {
                stopCapture("Se cerró ${CaptureState.targetLabel}")
                return
            }
        }
    }

    // ---------------------------------------------------------------- notificaciones

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Captura", NotificationManager.IMPORTANCE_LOW))
        }
    }

    @Suppress("DEPRECATION")
    private fun builder(): Notification.Builder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL)
        else Notification.Builder(this)

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
    )

    private fun goForeground() {
        ensureChannel()
        val stop = PendingIntent.getService(
            this, 1, Intent(this, CaptureVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        @Suppress("DEPRECATION")
        val n = builder()
            .setSmallIcon(R.drawable.ic_app)
            .setContentTitle("Capturando dominios")
            .setContentText(CaptureState.targetLabel)
            .setOngoing(true)
            .setContentIntent(openAppIntent())
            .addAction(Notification.Action.Builder(0, "Detener y guardar", stop).build())
            .build()
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_RUNNING, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIF_RUNNING, n)
            }
        } catch (e: Exception) {
            // El sistema mantiene vivo el VpnService igualmente (está enlazado por el framework).
            Log.w(TAG, "startForeground falló", e)
        }
    }

    private fun notifyDone(reason: String, result: String) {
        ensureChannel()
        val n = builder()
            .setSmallIcon(R.drawable.ic_app)
            .setContentTitle("$reason – ${CaptureState.domains.size} dominios")
            .setContentText(result)
            .setStyle(Notification.BigTextStyle().bigText(result))
            .setContentIntent(openAppIntent())
            .setAutoCancel(true)
            .build()
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIF_DONE, n)
        } catch (_: Exception) {}
    }
}
