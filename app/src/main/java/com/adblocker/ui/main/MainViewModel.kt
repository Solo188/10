package com.adblocker.ui.main

import android.app.Activity
import android.content.Intent
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adblocker.core.proxy.LittleProxyServer
import com.adblocker.core.vpn.VpnController
import com.adblocker.core.vpn.VpnState
import com.adblocker.ui.log.RequestLogEntry
import com.adblocker.utils.Logger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Collections
import android.content.Context

/**
 * ui.main — MainViewModel
 *
 * Bridges the VPN controller, filter engine stats, and request log
 * to the UI without exposing Android framework directly.
 *
 * Log entries are posted by AdBlockerHttpFilters via the companion
 * object callback so the ViewModel doesn't need to be passed deep into
 * the networking stack.
 */
class MainViewModel : ViewModel() {

    companion object {
        private const val TAG = "MainViewModel"
        private const val MAX_LOG_ENTRIES = 500

        /**
         * Static callback invoked by AdBlockerHttpFilters on every intercepted request.
         * Decouples the network layer from the ViewModel lifecycle.
         */
        var onRequestIntercepted: ((RequestLogEntry) -> Unit)? = null
    }

    private lateinit var vpnController: VpnController
    private lateinit var appContext: Context

    private val _vpnState = MutableStateFlow(VpnState.STOPPED)
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

    private val _requestLog = MutableStateFlow<List<RequestLogEntry>>(emptyList())
    val requestLog: StateFlow<List<RequestLogEntry>> = _requestLog.asStateFlow()

    private val _blockedCount = MutableStateFlow(0)
    val blockedCount: StateFlow<Int> = _blockedCount.asStateFlow()

    private val logBuffer = Collections.synchronizedList(mutableListOf<RequestLogEntry>())

    fun initialize(context: Context) {
        appContext = context.applicationContext
        vpnController = VpnController(appContext)

        // Wire up the interceptor callback
        onRequestIntercepted = { entry ->
            viewModelScope.launch {
                logBuffer.add(0, entry)
                if (logBuffer.size > MAX_LOG_ENTRIES) logBuffer.removeAt(logBuffer.size - 1)
                _requestLog.value = logBuffer.toList()
                if (entry.blocked) _blockedCount.value++
            }
        }

        // Mirror VPN controller state
        viewModelScope.launch {
            vpnController.state.collect { state ->
                _vpnState.value = state
            }
        }
    }

    fun toggleVpn() { vpnController.toggle() }
    fun startVpn()  { vpnController.start() }
    fun stopVpn()   { vpnController.stop() }

    fun clearLog() {
        logBuffer.clear()
        _requestLog.value = emptyList()
        _blockedCount.value = 0
    }

    /**
     * Shares the root CA PEM file so the user can install it on the device.
     *
     * The CA PEM is written to `filesDir/adblocker-ca.pem` by
     * BouncyCastleSslEngineSource on first launch; LittleProxyServer
     * exposes the path via getCaPemFile().
     *
     * To enable HTTPS filtering the user must install this CA:
     *   Settings → Security → Encryption & Credentials → Install a certificate → CA certificate
     */
    fun exportCaCertificate(activity: Activity) {
        viewModelScope.launch {
            try {
                // Derive the same Authority the server uses so we find the right file
                val authority = org.littleshoot.proxy.mitm.Authority(
                    appContext.filesDir,
                    "adblocker-ca",
                    "AdBlockerCA_2024!".toCharArray(),
                    "AdBlocker Root CA", "AdBlocker",
                    "Certificate Authority", "AdBlocker MITM",
                    "AdBlocker TLS Interception"
                )
                val pemFile = authority.aliasFile(".pem")

                if (!pemFile.exists()) {
                    Logger.w(TAG, "CA PEM not found — start the VPN first to generate it")
                    return@launch
                }

                val uri = FileProvider.getUriForFile(
                    activity,
                    "${activity.packageName}.fileprovider",
                    pemFile
                )
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, "application/x-x509-ca-cert")
                    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                            Intent.FLAG_ACTIVITY_NEW_TASK
                }
                activity.startActivity(intent)
                Logger.i(TAG, "CA cert share intent fired: ${pemFile.absolutePath}")

            } catch (e: Exception) {
                Logger.e(TAG, "CA export failed", e)
            }
        }
    }

    override fun onCleared() {
        onRequestIntercepted = null
        super.onCleared()
    }
}
