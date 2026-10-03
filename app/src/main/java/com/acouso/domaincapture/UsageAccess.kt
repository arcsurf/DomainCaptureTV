package com.acouso.domaincapture

import android.app.AppOpsManager
import android.content.Context
import android.os.Build
import android.os.Process

/** Comprueba si la app tiene "Acceso a datos de uso" (necesario para detectar el cierre de la app objetivo). */
object UsageAccess {
    fun granted(ctx: Context): Boolean {
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        } else {
            @Suppress("DEPRECATION")
            ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun adbCommand(ctx: Context) = "adb shell appops set ${ctx.packageName} GET_USAGE_STATS allow"
}
