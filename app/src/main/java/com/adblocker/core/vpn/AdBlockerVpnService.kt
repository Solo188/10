package com.adblocker.core.vpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.adblocker.AdBlockerApp
import com.adblocker.R
import com.adblocker.core.proxy.LocalProxyService
import com.adblocker.ui.main.MainActivity
import com.adblocker.utils.Logger
import com.adblocker.utils.NetworkUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.FileInputStream

/**
 * core.vpn — AdBlockerVpnService
 *
 * Lifecycle:
 *  1. onStartCommand(ACTION_START)
 *  2. Start LocalProxyService (LittleProxy) on a free port
 *  3. Establish TUN interface with OS-level HTTP proxy pointing at LittleProxy
 *  4. Drain the TUN fd on a background thread (no packet parsing)
 *
 * All HTTP/HTTPS routing is handled by the OS via VpnBuilder.setHttpProxy().
 * No packet construction, no TCP stack, no sequence numbers.
 */
class AdBlockerVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.adblocker.VPN_START"
        const val ACTION_STOP  = "com.adblocker.VPN_STOP"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "VpnService"
        private const val VPN_ADDRESS = "10.0.0.1"
        private const val VPN_ROUTE   = "0.0.0.0"

        @Volatile var isRunning: Boolean = false
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunFd: ParcelFileDescriptor? = null
    private var drainThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_START -> { startVpn(); START_STICKY }
            ACTION_STOP  -> { stopVpn();  START_NOT_STICKY }
            else         -> START_NOT_STICKY
        }
    }

    private fun startVpn() {
        if (isRunning) return
        Logger.i(TAG, "Starting VPN service")
        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))

        serviceScope.launch {
            try {
                // 1. Find a free port and start LittleProxy
                val proxyPort = NetworkUtils.findFreePort(8118)
                Logger.i(TAG, "Proxy port: $proxyPort")
                startProxyService(proxyPort)
                delay(800)   // let the proxy bind

                // 2. Build a simple router — no TCP stack, no packet parsing
                val router = SocketVpnRouter(proxyPort = proxyPort)

                // 3. Establish the TUN interface, with the OS proxy pointing at LittleProxy
                val fd = Builder()
                    .setSession("AdBlocker")
                    .addAddress(VPN_ADDRESS, 24)
                    .addRoute(VPN_ROUTE, 0)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    .setMtu(1500)
                    .setBlocking(true)
                    .setHttpProxy(router.proxyInfo())   // OS routes HTTP/HTTPS here
                    .establish()
                    ?: error("VpnService.establish() returned null — VPN permission not granted?")

                tunFd = fd

                // 4. Drain the TUN fd so its buffer doesn't fill (we don't parse packets)
                drainThread = router.startTunDrain(FileInputStream(fd.fileDescriptor))

                isRunning = true
                updateNotification("Active — filtering traffic")
                Logger.i(TAG, "VPN started, proxy on 127.0.0.1:$proxyPort")

            } catch (e: Exception) {
                Logger.e(TAG, "VPN startup failed", e)
                isRunning = false
                stopVpn()
            }
        }
    }

    private fun stopVpn() {
        Logger.i(TAG, "Stopping VPN")
        isRunning = false
        drainThread?.interrupt()
        drainThread = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        stopService(Intent(this, LocalProxyService::class.java))
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startProxyService(port: Int) {
        startService(
            Intent(this, LocalProxyService::class.java)
                .putExtra(LocalProxyService.EXTRA_PORT, port)
        )
    }

    private fun buildNotification(statusText: String): Notification {
        val openUi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, AdBlockerVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, AdBlockerApp.NOTIFICATION_CHANNEL_VPN)
            .setContentTitle("AdBlocker")
            .setContentText(statusText)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(openUi)
            .addAction(R.drawable.ic_stop, "Stop", stopPi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        (getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    override fun onRevoke() {
        Logger.w(TAG, "VPN permission revoked by system")
        stopVpn()
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }
}
