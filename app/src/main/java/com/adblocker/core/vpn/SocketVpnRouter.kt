package com.adblocker.core.vpn

import android.net.ProxyInfo
import android.net.VpnService
import com.adblocker.utils.Logger
import java.io.FileInputStream
import java.io.InputStream
import kotlin.concurrent.thread

/**
 * core.vpn — SocketVpnRouter
 *
 * Minimal routing layer.  No TCP stack.  No packet construction.
 * No sequence numbers.  No checksums.
 *
 * How it works:
 *   VpnService.Builder.setHttpProxy() tells the Android OS to route
 *   all HTTP and HTTPS connections from every app through a specific
 *   proxy host:port.  The OS TCP stack handles the actual connections;
 *   we never touch individual packets.
 *
 *   LittleProxy on 127.0.0.1:proxyPort receives the connections,
 *   performs MITM (via CertificateSniffingMitmManager), applies
 *   AdBlockerHttpFilters, and forwards to the real server.
 *
 * Flow:
 *   App → OS TCP stack → VPN proxy setting → 127.0.0.1:proxyPort
 *       → LittleProxy → MITM → Internet
 */
class SocketVpnRouter(
    private val proxyHost: String = "127.0.0.1",
    private val proxyPort: Int
) {
    companion object {
        private const val TAG = "SocketVpnRouter"
    }

    /**
     * Returns the [ProxyInfo] to pass to [VpnService.Builder.setHttpProxy].
     * The OS will route all HTTP/HTTPS traffic through LittleProxy.
     */
    fun proxyInfo(): ProxyInfo =
        ProxyInfo.buildDirectProxy(proxyHost, proxyPort)

    /**
     * Starts a background thread that drains the raw TUN file descriptor.
     * We only drain it to prevent the file descriptor buffer from filling up;
     * we do NOT parse or process any bytes from it.  All real traffic routing
     * is handled by the OS via the proxy setting above.
     *
     * @param tunStream  the [InputStream] of the established TUN fd
     * @return the drain thread (call [Thread.interrupt] to stop)
     */
    fun startTunDrain(tunStream: InputStream): Thread {
        Logger.i(TAG, "TUN drain thread started (proxy=$proxyHost:$proxyPort)")
        return thread(name = "tun-drain", isDaemon = true) {
            val buf = ByteArray(4096)
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val n = tunStream.read(buf)
                    if (n < 0) break
                    // Intentionally do nothing — OS handles all routing via proxy setting
                }
            } catch (_: InterruptedException) {
            } catch (_: Exception) {
            } finally {
                Logger.i(TAG, "TUN drain thread stopped")
            }
        }
    }
}
