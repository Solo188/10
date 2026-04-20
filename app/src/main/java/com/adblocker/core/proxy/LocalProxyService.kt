package com.adblocker.core.proxy

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.adblocker.AdBlockerApp
import com.adblocker.utils.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * core.proxy — LocalProxyService
 *
 * Android Service that owns the lifetime of the embedded LittleProxy instance.
 * Started by AdBlockerVpnService; destroyed when the VPN is stopped.
 *
 * The proxy is started on a background thread so the service returns from
 * onStartCommand() immediately (no ANR risk).
 */
class LocalProxyService : Service() {

    companion object {
        const val EXTRA_PORT = "proxy_port"
        private const val DEFAULT_PORT = 8118
        private const val TAG = "ProxyService"

        /** Shared port so VpnService can read back what port was bound. */
        @Volatile var boundPort: Int = 0
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var proxyServer: LittleProxyServer? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val port = intent?.getIntExtra(EXTRA_PORT, DEFAULT_PORT) ?: DEFAULT_PORT
        boundPort = port
        startProxy(port)
        return START_NOT_STICKY
    }

    private fun startProxy(port: Int) {
        scope.launch {
            try {
                val app = application as AdBlockerApp

                val server = LittleProxyServer(
                    context      = applicationContext,
                    port         = port,
                    filterEngine = app.filterEngine
                )
                proxyServer = server
                server.start()

                Logger.i(TAG, "LittleProxy started on port $port")
                Logger.i(TAG,
                    "Root CA PEM: ${server.getCaPemFile().absolutePath}\n" +
                    "  → Copy this file to your device Downloads folder, then\n" +
                    "  → Settings → Security → Encryption & Credentials → Install a certificate → CA certificate"
                )

            } catch (e: Exception) {
                Logger.e(TAG, "Proxy startup failed — stopping service", e)
                stopSelf()
            }
        }
    }

    override fun onDestroy() {
        scope.launch {
            proxyServer?.stop()
            Logger.i(TAG, "LittleProxy stopped")
        }
        scope.cancel()
        super.onDestroy()
    }
}
