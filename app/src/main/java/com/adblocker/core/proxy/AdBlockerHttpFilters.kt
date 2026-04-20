package com.adblocker.core.proxy

import com.adblocker.filter.engine.FilterEngine
import com.adblocker.ui.log.RequestLogEntry
import com.adblocker.ui.main.MainViewModel
import com.adblocker.utils.Logger
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.http.DefaultFullHttpResponse
import io.netty.handler.codec.http.HttpHeaders
import io.netty.handler.codec.http.HttpObject
import io.netty.handler.codec.http.HttpRequest
import io.netty.handler.codec.http.HttpResponse
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpVersion
import org.littleshoot.proxy.HttpFiltersAdapter
import java.net.InetSocketAddress
import java.time.Instant

/**
 * core.proxy — AdBlockerHttpFilters
 *
 * Called by LittleProxy for EVERY intercepted request (both HTTP and
 * decrypted HTTPS after MITM).
 *
 * clientToProxyRequest() is where we make the block/pass decision:
 *  - Extract host from the Host header or the request URI
 *  - Run through FilterEngine (DomainTrie + substring rules)
 *  - If BLOCKED: return a 204 No Content response immediately
 *    (the upstream server is never contacted)
 *  - If PASSED:  return null (LittleProxy continues normally)
 *
 * Each filter instance is created per-request; it is safe to store
 * request-level state here.
 */
class AdBlockerHttpFilters(
    originalRequest: HttpRequest,
    ctx: ChannelHandlerContext?,
    private val filterEngine: FilterEngine
) : HttpFiltersAdapter(originalRequest, ctx) {

    companion object {
        private const val TAG = "HttpFilters"
    }

    private val startTime = System.currentTimeMillis()
    private var requestHost = ""
    private var requestUrl  = ""

    override fun clientToProxyRequest(httpObject: HttpObject): HttpResponse? {
        if (httpObject !is HttpRequest) return null   // only inspect the initial request line

        val request = httpObject
        val method  = request.method().name()
        val uri     = request.uri()
        val host    = extractHost(request)

        requestHost = host
        requestUrl  = resolveUrl(uri, host)

        Logger.d(TAG, "$method $requestUrl")

        val blocked = filterEngine.shouldBlock(requestUrl, host)
        publishLog(method, blocked, responseCode = if (blocked) 204 else -1)

        return if (blocked) {
            Logger.i(TAG, "BLOCKED: $requestUrl")
            buildBlockResponse()
        } else {
            null   // pass through
        }
    }

    override fun serverToProxyResponse(httpObject: HttpObject): HttpObject {
        // Log the response code when it arrives
        if (httpObject is HttpResponse) {
            publishLog(
                method       = originalRequest.method().name(),
                blocked      = false,
                responseCode = httpObject.status().code()
            )
        }
        return httpObject
    }

    override fun proxyToServerResolutionFailed(hostAndPort: String) {
        Logger.w(TAG, "DNS resolution failed: $hostAndPort")
    }

    override fun proxyToServerConnectionFailed() {
        Logger.w(TAG, "Upstream connection failed for $requestUrl")
    }

    // -------------------------------------------------------------------------
    //  Response builders
    // -------------------------------------------------------------------------

    /**
     * A 204 No Content response with Connection: close so the browser
     * doesn't reuse the connection for something else.
     */
    private fun buildBlockResponse(): HttpResponse {
        val resp = DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1,
            HttpResponseStatus.NO_CONTENT
        )
        resp.headers().apply {
            set(HttpHeaders.Names.CONTENT_LENGTH, "0")
            set(HttpHeaders.Names.CONNECTION, "close")
            set("X-AdBlocker", "blocked")
        }
        return resp
    }

    // -------------------------------------------------------------------------
    //  Logging
    // -------------------------------------------------------------------------

    private fun publishLog(method: String, blocked: Boolean, responseCode: Int) {
        val duration = System.currentTimeMillis() - startTime
        val entry = RequestLogEntry(
            timestamp    = Instant.now(),
            method       = method,
            host         = requestHost,
            url          = requestUrl,
            blocked      = blocked,
            responseCode = responseCode,
            durationMs   = duration
        )
        MainViewModel.onRequestIntercepted?.invoke(entry)
    }

    // -------------------------------------------------------------------------
    //  Helpers
    // -------------------------------------------------------------------------

    private fun extractHost(request: HttpRequest): String {
        val hostHeader = request.headers().get(HttpHeaders.Names.HOST) ?: ""
        if (hostHeader.isNotBlank()) return hostHeader.substringBefore(':').lowercase()
        // Fall back to URI if no Host header
        return try {
            java.net.URI(request.uri()).host?.lowercase() ?: ""
        } catch (_: Exception) { "" }
    }

    private fun resolveUrl(uri: String, host: String): String {
        return when {
            uri.startsWith("http://") || uri.startsWith("https://") -> uri
            uri.startsWith("/") && host.isNotBlank() -> "http://$host$uri"
            else -> uri
        }
    }
}
