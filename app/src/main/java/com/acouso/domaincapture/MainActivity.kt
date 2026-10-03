package com.acouso.domaincapture

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

class MainActivity : Activity() {

    private data class AppItem(val pkg: String, val label: String, val icon: Drawable?)

    private val ui = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("cfg", MODE_PRIVATE) }
    private var apps: List<AppItem> = emptyList()
    private var selected: AppItem? = null

    private lateinit var txtTarget: TextView
    private lateinit var txtStatus: TextView
    private lateinit var txtCount: TextView
    private lateinit var txtDomains: TextView
    private lateinit var txtUsage: TextView
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button
    private lateinit var chkAuto: CheckBox
    private lateinit var adapter: AppAdapter

    private val refresher = object : Runnable {
        override fun run() {
            refresh()
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        txtTarget = findViewById(R.id.txtTarget)
        txtStatus = findViewById(R.id.txtStatus)
        txtCount = findViewById(R.id.txtCount)
        txtDomains = findViewById(R.id.txtDomains)
        txtUsage = findViewById(R.id.txtUsage)
        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)
        chkAuto = findViewById(R.id.chkAuto)

        chkAuto.isChecked = prefs.getBoolean("autostop", true)
        chkAuto.setOnCheckedChangeListener { _, v -> prefs.edit().putBoolean("autostop", v).apply() }

        apps = loadApps()
        selected = apps.firstOrNull { it.pkg == prefs.getString("target", null) }
        adapter = AppAdapter()
        findViewById<RecyclerView>(R.id.listApps).apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
        }

        btnStart.setOnClickListener { startClicked() }
        btnStop.setOnClickListener {
            startService(Intent(this, CaptureVpnService::class.java).setAction(CaptureVpnService.ACTION_STOP))
        }
        findViewById<Button>(R.id.btnUsage).setOnClickListener { openUsageSettings() }
        findViewById<Button>(R.id.btnAppInfo).setOnClickListener { openTargetAppInfo() }

        requestRuntimePermissions()
    }

    override fun onResume() {
        super.onResume()
        ui.post(refresher)
    }

    override fun onPause() {
        ui.removeCallbacks(refresher)
        super.onPause()
    }

    private fun requestRuntimePermissions() {
        val perms = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 33) perms += Manifest.permission.POST_NOTIFICATIONS
        if (Build.VERSION.SDK_INT <= 28) perms += Manifest.permission.WRITE_EXTERNAL_STORAGE
        val missing = perms.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) requestPermissions(missing.toTypedArray(), 10)
    }

    private fun loadApps(): List<AppItem> {
        val pm = packageManager
        val result = LinkedHashMap<String, AppItem>()
        for (cat in listOf(Intent.CATEGORY_LEANBACK_LAUNCHER, Intent.CATEGORY_LAUNCHER)) {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(cat)
            for (ri in pm.queryIntentActivities(intent, 0)) {
                val pkg = ri.activityInfo.packageName
                if (pkg == packageName || pkg in result) continue
                val ai = ri.activityInfo.applicationInfo
                result[pkg] = AppItem(pkg, pm.getApplicationLabel(ai).toString(), try { pm.getApplicationIcon(ai) } catch (_: Exception) { null })
            }
        }
        return result.values.sortedBy { it.label.lowercase() }
    }

    // ------------------------------------------------------------- captura

    private fun startClicked() {
        if (CaptureState.running) return
        if (selected == null) {
            Toast.makeText(this, "Elegí primero una app de la lista", Toast.LENGTH_SHORT).show()
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) startActivityForResult(prepare, 1) else onActivityResult(1, RESULT_OK, null)
    }

    @Deprecated("API de Activity clásica")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != 1) return
        if (resultCode != RESULT_OK) {
            Toast.makeText(this, "Sin permiso de VPN no se puede capturar", Toast.LENGTH_LONG).show()
            return
        }
        val app = selected ?: return
        startService(
            Intent(this, CaptureVpnService::class.java)
                .setAction(CaptureVpnService.ACTION_START)
                .putExtra(CaptureVpnService.EXTRA_PKG, app.pkg)
                .putExtra(CaptureVpnService.EXTRA_LABEL, app.label)
                .putExtra(CaptureVpnService.EXTRA_AUTOSTOP, chkAuto.isChecked)
        )
        launchWhenRunning(app, 0)
    }

    /** Espera a que el túnel esté arriba y abre la app objetivo. */
    private fun launchWhenRunning(app: AppItem, attempt: Int) {
        ui.postDelayed({
            if (CaptureState.running) {
                val launch = packageManager.getLeanbackLaunchIntentForPackage(app.pkg)
                    ?: packageManager.getLaunchIntentForPackage(app.pkg)
                if (launch != null) startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                else Toast.makeText(this, "Captura activa. Abrí ${app.label} manualmente.", Toast.LENGTH_LONG).show()
            } else if (attempt < 10) {
                launchWhenRunning(app, attempt + 1)
            } else {
                refresh()
            }
        }, 400)
    }

    // ------------------------------------------------------------- permisos / ajustes

    private fun openUsageSettings() {
        try {
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        } catch (e: Exception) {
            AlertDialog.Builder(this)
                .setTitle("Acceso a datos de uso")
                .setMessage(
                    "Este Android TV no tiene la pantalla de 'Acceso a datos de uso'.\n\n" +
                        "Concedelo desde una PC con:\n\n${UsageAccess.adbCommand(this)}"
                )
                .setPositiveButton("OK", null)
                .show()
        }
    }

    private fun openTargetAppInfo() {
        val app = selected ?: run {
            Toast.makeText(this, "Elegí primero una app", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, android.net.Uri.parse("package:${app.pkg}")))
        } catch (_: Exception) {}
    }

    // ------------------------------------------------------------- refresco de pantalla

    private fun refresh() {
        val running = CaptureState.running
        btnStart.isEnabled = !running
        btnStop.isEnabled = running
        txtTarget.text = selected?.let { "App objetivo: ${it.label}  (${it.pkg})" } ?: "App objetivo: (ninguna)"

        val usage = UsageAccess.granted(this)
        txtUsage.text = if (usage) "Acceso a datos de uso: OK (auto-detener disponible)"
        else "Acceso a datos de uso: NO concedido → la captura deberá detenerse a mano.\n${UsageAccess.adbCommand(this)}"

        txtStatus.text = CaptureState.status
        val entries = CaptureState.domains.values.sortedByDescending { it.firstSeen }
        txtCount.text = "Dominios: ${entries.size}   Consultas DNS: ${CaptureState.totalQueries.get()}"
        txtDomains.text = if (entries.isEmpty()) "(todavía no hay dominios capturados)"
        else entries.take(300).joinToString("\n") { e ->
            val ip = e.ips.firstOrNull()?.let { "  → $it" + if (e.ips.size > 1) " (+${e.ips.size - 1})" else "" } ?: ""
            "${e.name}$ip"
        }
    }

    // ------------------------------------------------------------- lista de apps

    private inner class AppAdapter : RecyclerView.Adapter<AppAdapter.VH>() {
        inner class VH(v: View) : RecyclerView.ViewHolder(v) {
            val icon: ImageView = v.findViewById(R.id.appIcon)
            val label: TextView = v.findViewById(R.id.appLabel)
            val pkg: TextView = v.findViewById(R.id.appPkg)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            VH(LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false))

        override fun getItemCount() = apps.size

        override fun onBindViewHolder(h: VH, position: Int) {
            val app = apps[position]
            h.icon.setImageDrawable(app.icon)
            h.label.text = if (app.pkg == selected?.pkg) "✔ ${app.label}" else app.label
            h.pkg.text = app.pkg
            h.itemView.isActivated = app.pkg == selected?.pkg
            h.itemView.setOnClickListener {
                if (CaptureState.running) return@setOnClickListener
                selected = app
                prefs.edit().putString("target", app.pkg).apply()
                notifyDataSetChanged()
                refresh()
                btnStart.requestFocus()
            }
        }
    }
}
