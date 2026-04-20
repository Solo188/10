package com.adblocker.core.proxy

import android.content.Context
import com.adblocker.filter.engine.FilterEngine
import com.adblocker.utils.Logger
import org.littleshoot.proxy.HttpFilters
import org.littleshoot.proxy.HttpFiltersSource
import org.littleshoot.proxy.HttpFiltersSourceAdapter
import org.littleshoot.proxy.impl.DefaultHttpProxyServer
import org.littleshoot.proxy.mitm.Authority
import org.littleshoot.proxy.mitm.CertificateSniffingMitmManager
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.http.HttpRequest
import java.io.File
import java.net.InetSocketAddress

/**
 * core.proxy — LittleProxyServer
 *
 * Embeds LittleProxy inside the Android process and configures it with:
 *  - MITM support via CertificateSniffingMitmManager (real per-domain certs)
 *  - Ad-blocking filter via AdBlockerHttpFilters
 *  - Bound to 127.0.0.1 only (not accessible outside the device)
 *
 * LittleProxy handles HTTP CONNECT automatically when a MitmManager is
 * installed; the proxy then decrypts the TLS stream and hands decoded
 * HttpRequest objects to our HttpFiltersSource.
 */
class LittleProxyServer(
    private val context: Context,
    private val port: Int,
    private val filterEngine: FilterEngine
) {
    companion object {
        private const val TAG = "LittleProxyServer"
    }

    @Volatile private var proxyServer: org.littleshoot.proxy.HttpProxyServer? = null

    /**
     * Builds the CA Authority pointing to the app's private files directory.
     * The keystore and PEM will be created there on first launch and reused
     * on subsequent launches.
     */
    private fun buildAuthority(): Authority {
        val dir = context.filesDir
        return Authority(
            dir,
            "adblocker-ca",                        // alias (also filename prefix)
            "AdBlockerCA_2024!".toCharArray(),      // keystore password
            "AdBlocker Root CA",                   // cert CN
            "AdBlocker",                           // organization
            "Certificate Authority",               // OU
            "AdBlocker MITM",                      // cert org
            "AdBlocker TLS Interception"           // cert OU
        )
    }

    fun start() {
        Logger.i(TAG, "Starting LittleProxy on port $port")

        val authority = buildAuthority()

        // Build the MITM manager — this generates the root CA on first launch
        val mitmManager = try {
            CertificateSniffingMitmManager(authority).also {
                Logger.i(TAG, "Root CA ready at ${authority.aliasFile(".pem").absolutePath}")
                Logger.i(TAG, "Install the CA cert to enable HTTPS filtering: " +
                              "Settings → Security → Install certificate → " +
                              authority.aliasFile(".pem").absolutePath)
            }
        } catch (e: Exception) {
            Logger.e(TAG, "MITM manager init failed — HTTPS interception disabled", e)
            null
        }

        val filtersSource = object : HttpFiltersSourceAdapter() {
            override fun filterRequest(
                originalRequest: HttpRequest,
                ctx: ChannelHandlerContext
            ): HttpFilters {
                return AdBlockerHttpFilters(originalRequest, ctx, filterEngine)
            }

            // Buffer full request so clientToProxyRequest() sees the complete URL
            override fun getMaximumRequestBufferSizeInBytes(): Int = 10 * 1024 * 1024
        }

        val bootstrap = DefaultHttpProxyServer.bootstrap()
            .withAddress(InetSocketAddress("127.0.0.1", port))
            .withFiltersSource(filtersSource)
            .withAllowLocalOnly(true)   // strictly bind to loopback
            .withTransparent(false)     // standard proxy mode

        if (mitmManager != null) {
            bootstrap.withManInTheMiddle(mitmManager)
            Logger.i(TAG, "MITM enabled — HTTPS traffic will be intercepted")
        } else {
            Logger.w(TAG, "MITM disabled — HTTP-only filtering active")
        }

        proxyServer = bootstrap.start()
        Logger.i(TAG, "LittleProxy listening on 127.0.0.1:$port")
    }

    fun stop() {
        proxyServer?.stop()
        proxyServer = null
        Logger.i(TAG, "LittleProxy stopped")
    }

    /**
     * Returns the path to the PEM root CA file so the UI can display/share it.
     */
    fun getCaPemFile(): File = buildAuthority().aliasFile(".pem")
}
