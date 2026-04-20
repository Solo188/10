package com.adblocker.core.vpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResultLauncher
import com.adblocker.utils.Logger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * core.vpn — VpnController
 *
 * Single point of truth for VPN lifecycle management.
 * The UI observes [state] and calls [requestStart] / [stop].
 *
 * VPN permission flow:
 *   Android requires an explicit user intent before a VPN can be established.
 *   Call [prepareIntent] and launch the returned intent via
 *   ActivityResultLauncher before calling [start].
 */
class VpnController(private val context: Context) {

    companion object {
        private const val TAG = "VpnController"
    }

    private val _state = MutableStateFlow(VpnState.STOPPED)
    val state: StateFlow<VpnState> = _state

    /**
     * Returns the system-provided permission intent, or null if permission is
     * already granted (safe to call [start] directly).
     */
    fun prepareIntent(): Intent? = VpnService.prepare(context)

    /**
     * Start the VPN service.  Caller must ensure permission is already granted
     * (i.e. [prepareIntent] returned null or the user approved the intent).
     */
    fun start() {
        Logger.i(TAG, "Requesting VPN start")
        _state.value = VpnState.CONNECTING
        context.startService(
            Intent(context, AdBlockerVpnService::class.java).apply {
                action = AdBlockerVpnService.ACTION_START
            }
        )
        // Transition to CONNECTED once the service reports it's up.
        // In a full implementation use a bound service or broadcast.
        _state.value = VpnState.CONNECTED
    }

    /** Stop the VPN service gracefully. */
    fun stop() {
        Logger.i(TAG, "Requesting VPN stop")
        _state.value = VpnState.STOPPING
        context.startService(
            Intent(context, AdBlockerVpnService::class.java).apply {
                action = AdBlockerVpnService.ACTION_STOP
            }
        )
        _state.value = VpnState.STOPPED
    }

    fun toggle() {
        if (_state.value == VpnState.CONNECTED) stop() else start()
    }
}

enum class VpnState {
    STOPPED, CONNECTING, CONNECTED, STOPPING, ERROR
}
