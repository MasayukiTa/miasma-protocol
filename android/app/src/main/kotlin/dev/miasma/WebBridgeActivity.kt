package dev.miasma

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import dev.miasma.uniffi.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * WebView-hosted Miasma web UI with a message bridge to native FFI.
 *
 * Loads the web app from app assets through `WebViewAssetLoader`
 * (`https://appassets.androidplatform.net/assets/web/index.html`): ES module
 * scripts cannot be loaded from `file://` URLs, and file access stays disabled.
 *
 * Native operations are reached through `WebViewCompat.addWebMessageListener`
 * restricted to the exact origin of the bundled client, not through
 * `addJavascriptInterface`. The page posts `{id, method, args}` to
 * `window.miasma.postMessage` and receives `{id, result}` / `{id, error}` on
 * `window.miasma.onmessage` (see [WebBridgeProtocol]). Every message is
 * size-checked and type-checked against a fixed per-method table before
 * anything is decoded or executed. `wipe` additionally needs a native
 * confirmation dialog that the page cannot answer. Content from the device
 * reaches the page only through the system document picker
 * ([WebChromeClient.onShowFileChooser]); no method takes a file path.
 *
 * If the installed WebView cannot do this (no `WEB_MESSAGE_LISTENER`), the page
 * is not loaded at all and a message is shown; there is no fallback to an open
 * interface.
 */
private const val APP_HOST = "appassets.androidplatform.net"
private const val APP_PATH_PREFIX = "/assets/web/"

/** Only the bundled web client's own https origin may be shown while the bridge is attached. */
private fun isAllowedAppUrl(uri: Uri?): Boolean {
    if (uri == null || uri.scheme != "https" || uri.host != APP_HOST || uri.port != -1) return false
    if (!uri.userInfo.isNullOrEmpty()) return false
    val path = uri.path ?: return false
    if (!path.startsWith(APP_PATH_PREFIX)) return false
    return path.split('/').none { it == ".." }
}

/** The exact origin (scheme, host, no port) of the bundled client. */
internal fun isAllowedBridgeOrigin(origin: Uri?): Boolean =
    origin != null &&
        origin.scheme == "https" &&
        origin.host == APP_HOST &&
        origin.port == -1 &&
        origin.userInfo.isNullOrEmpty() &&
        (origin.path.isNullOrEmpty() || origin.path == "/")

class WebBridgeActivity : ComponentActivity() {

    private var webView: WebView? = null
    private val dataDir: String by lazy { filesDir.absolutePath }
    private val mainHandler = Handler(Looper.getMainLooper())

    // Up to 4 operations run at once so that status polling still answers during a
    // long transfer; a fifth is refused so queued messages cannot pile up in memory.
    private val executor: ExecutorService = Executors.newFixedThreadPool(MAX_INFLIGHT)
    private val inflight = AtomicInteger(0)
    private val wipeDialogOpen = AtomicBoolean(false)

    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private val pickFile = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        filePathCallback?.onReceiveValue(if (uri != null) arrayOf(uri) else null)
        filePathCallback = null
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ScreenPrivacy.apply(this)

        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            // The old WebView cannot restrict messages to one origin. Do not load the
            // page and do not expose an unrestricted interface.
            setContentView(
                TextView(this).apply {
                    text = getString(R.string.webview_unsupported)
                    gravity = Gravity.CENTER
                    setPadding(48, 48, 48, 48)
                    textSize = 16f
                }
            )
            return
        }

        // Explicit: remote inspection of page contents is only for debuggable builds.
        val debuggable = (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        WebView.setWebContentsDebuggingEnabled(debuggable)

        val view = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            if (WebViewFeature.isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
                WebSettingsCompat.setSafeBrowsingEnabled(settings, true)
            }
            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    webView: WebView?,
                    callback: ValueCallback<Array<Uri>>?,
                    params: FileChooserParams?,
                ): Boolean {
                    // Replace any chooser the page left open, then use the system picker.
                    filePathCallback?.onReceiveValue(null)
                    filePathCallback = callback
                    return try {
                        pickFile.launch("*/*")
                        true
                    } catch (_: Exception) {
                        filePathCallback?.onReceiveValue(null)
                        filePathCallback = null
                        false
                    }
                }
            }
            webViewClient = LocalAssetsOnlyWebViewClient(
                WebViewAssetLoader.Builder()
                    .setDomain(APP_HOST)
                    .addPathHandler("/assets/", BundledAssetsPathHandler(applicationContext))
                    .build()
            )
        }
        webView = view

        WebViewCompat.addWebMessageListener(
            view,
            WebBridgeProtocol.JS_OBJECT_NAME,
            setOf(WebBridgeProtocol.ALLOWED_ORIGIN),
            BridgeListener(),
        )
        setContentView(view)
        view.loadUrl("https://$APP_HOST/assets/web/index.html")
    }

    /**
     * Native operations are privileged: never let a remote document become the
     * top-level page while the listener is attached. The bundled PWA has a
     * restrictive CSP as a second layer, but navigation is enforced natively too.
     */
    private class LocalAssetsOnlyWebViewClient(
        private val assetLoader: WebViewAssetLoader,
    ) : WebViewClient() {
        override fun shouldInterceptRequest(
            view: WebView?,
            request: WebResourceRequest,
        ): WebResourceResponse? =
            if (isAllowedAppUrl(request.url)) {
                assetLoader.shouldInterceptRequest(request.url)
            } else {
                // Nothing outside the bundled origin is ever fetched.
                WebResourceResponse("text/plain", "utf-8", 403, "Forbidden", emptyMap(), null)
            }

        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean =
            !isAllowedAppUrl(request.url)

        @Suppress("DEPRECATION")
        override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean =
            !isAllowedAppUrl(url?.let(Uri::parse))
    }

    /** Serves files from the app's bundled `web/` assets with explicit MIME types. */
    private class BundledAssetsPathHandler(
        private val context: android.content.Context,
    ) : WebViewAssetLoader.PathHandler {
        override fun handle(path: String): WebResourceResponse? {
            if (!path.startsWith("web/") || path.split('/').any { it == ".." || it.isEmpty() }) return null
            val stream = try {
                context.assets.open(path)
            } catch (_: java.io.IOException) {
                return null
            }
            val response = WebResourceResponse(mimeFor(path), if (isText(path)) "utf-8" else null, stream)
            response.responseHeaders = mapOf("Cache-Control" to "no-store")
            return response
        }

        private fun mimeFor(path: String): String = when (path.substringAfterLast('.', "").lowercase()) {
            "html" -> "text/html"
            "js", "mjs" -> "text/javascript"
            "css" -> "text/css"
            "json", "webmanifest" -> "application/json"
            "wasm" -> "application/wasm"
            "png" -> "image/png"
            "svg" -> "image/svg+xml"
            else -> "application/octet-stream"
        }

        private fun isText(path: String): Boolean = mimeFor(path).let {
            it.startsWith("text/") || it == "application/json"
        }
    }

    override fun onDestroy() {
        filePathCallback?.onReceiveValue(null)
        filePathCallback = null
        executor.shutdown()
        webView?.let {
            try {
                WebViewCompat.removeWebMessageListener(it, WebBridgeProtocol.JS_OBJECT_NAME)
            } catch (_: Exception) {
            }
            it.destroy()
        }
        webView = null
        super.onDestroy()
    }

    // ── Message handling ────────────────────────────────────────────────

    private fun reply(proxy: JavaScriptReplyProxy, json: String) {
        mainHandler.post {
            try {
                proxy.postMessage(json)
            } catch (_: Exception) {
                // The page is gone; nothing to answer.
            }
        }
    }

    private inner class BridgeListener : WebViewCompat.WebMessageListener {
        override fun onPostMessage(
            view: WebView,
            message: WebMessageCompat,
            sourceOrigin: Uri,
            isMainFrame: Boolean,
            replyProxy: JavaScriptReplyProxy,
        ) {
            // The allowed-origin rule already filters; check again here and answer nothing
            // to any other sender, so there is no oracle for a foreign frame.
            if (!isMainFrame || !isAllowedBridgeOrigin(sourceOrigin)) return

            val raw = if (message.type == WebMessageCompat.TYPE_STRING) message.data else null
            when (val parsed = WebBridgeProtocol.parse(raw)) {
                is Rejected -> reply(replyProxy, WebBridgeProtocol.errorResponse(parsed.id, parsed.message))
                is Request -> handle(parsed, replyProxy)
            }
        }
    }

    private fun handle(req: Request, proxy: JavaScriptReplyProxy) {
        if (req.spec.capability in WebBridgeProtocol.CONFIRMED_CAPABILITIES) {
            confirmThenRun(req, proxy)
            return
        }
        runLimited(req, proxy)
    }

    private fun runLimited(req: Request, proxy: JavaScriptReplyProxy) {
        if (inflight.incrementAndGet() > MAX_INFLIGHT) {
            inflight.decrementAndGet()
            reply(proxy, WebBridgeProtocol.errorResponse(req.id, "busy"))
            return
        }
        try {
            executor.execute {
                val out = try {
                    WebBridgeProtocol.okResponse(req.id, NativeOps(dataDir).invoke(req.spec.name, req.args))
                } catch (e: Exception) {
                    WebBridgeProtocol.errorResponse(req.id, e.message ?: "operation failed")
                } finally {
                    inflight.decrementAndGet()
                }
                reply(proxy, out)
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            inflight.decrementAndGet()
        }
    }

    /** Destructive methods run only after the user taps the native dialog. */
    private fun confirmThenRun(req: Request, proxy: JavaScriptReplyProxy) {
        if (!wipeDialogOpen.compareAndSet(false, true)) {
            reply(proxy, WebBridgeProtocol.errorResponse(req.id, "busy"))
            return
        }
        runOnUiThread {
            if (isFinishing || isDestroyed) {
                wipeDialogOpen.set(false)
                reply(proxy, WebBridgeProtocol.errorResponse(req.id, "cancelled"))
                return@runOnUiThread
            }
            val answered = AtomicBoolean(false)
            fun cancel() {
                if (answered.compareAndSet(false, true)) {
                    wipeDialogOpen.set(false)
                    reply(proxy, WebBridgeProtocol.errorResponse(req.id, "cancelled"))
                }
            }
            AlertDialog.Builder(this)
                .setTitle(R.string.wipe_title)
                .setMessage(R.string.wipe_message)
                .setPositiveButton(R.string.wipe_now) { _, _ ->
                    if (answered.compareAndSet(false, true)) {
                        wipeDialogOpen.set(false)
                        runLimited(req, proxy)
                    }
                }
                .setNegativeButton(R.string.cancel) { _, _ -> cancel() }
                .setOnCancelListener { cancel() }
                .show()
        }
    }

    /**
     * The native operations behind the protocol. Arguments have already been
     * validated by [WebBridgeProtocol.parse]; results are JSON text. Direct FFI
     * calls block the calling (worker) thread until Rust returns; the Rust side
     * owns its shared Tokio runtime for async protocol work.
     */
    private inner class NativeOps(private val dataDir: String) {

        private fun errorJson(message: String?): String =
            JSONObject().put("error", message ?: "operation failed").toString()

        private fun okJson(): String = JSONObject().put("ok", true).toString()

        private fun daemonUnavailable(): String = errorJson("daemon not running")

        private fun httpPort(): Int = getDaemonHttpPort().toInt()

        /** Decodes Base64 content. The length cap is enforced again here, before decoding. */
        private fun decodeBounded(text: String): ByteArray {
            require(WebBridgeProtocol.base64LengthOk(text)) { "argument too large" }
            return android.util.Base64.decode(text, android.util.Base64.DEFAULT)
        }

        fun invoke(method: String, a: List<Any?>): String = try {
            when (method) {
                "ping" -> okJson()
                "status" -> status()
                "dissolve" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        val bytes = decodeBounded(a[0] as String)
                        val mid = DirectedApi.publishBytes(dataDir, port, bytes, a[1] as Int, a[2] as Int)
                        JSONObject().put("mid", mid).toString()
                    }
                }
                "retrieve" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        val bytes = DirectedApi.retrieveBytes(dataDir, port, a[0] as String, a[1] as Int, a[2] as Int)
                        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                        JSONObject().put("data", b64).toString()
                    }
                }
                "wipe" -> wipe()
                "sharingKey" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        val result = DirectedApi.sharingKey(dataDir, port)
                        JSONObject().apply {
                            put("key", result.key)
                            put("contact", result.contact)
                        }.toString()
                    }
                }
                "directedInbox" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else envelopeList(DirectedApi.inbox(dataDir, port))
                }
                "directedOutbox" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else envelopeList(DirectedApi.outbox(dataDir, port))
                }
                "directedSend" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        val data = decodeBounded(a[1] as String)
                        val envelopeId = DirectedApi.send(
                            dataDir, port, a[0] as String, data, a[2] as String, a[3] as Long, a[4] as String?,
                        )
                        JSONObject().put("envelope_id", envelopeId).toString()
                    }
                }
                "directedConfirm" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        DirectedApi.confirm(dataDir, port, a[0] as String, a[1] as String)
                        okJson()
                    }
                }
                "directedRetrieve" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        val result = DirectedApi.retrieve(dataDir, port, a[0] as String, a[1] as String)
                        val b64 = android.util.Base64.encodeToString(result.data, android.util.Base64.NO_WRAP)
                        JSONObject().apply {
                            put("data", b64)
                            if (result.filename != null) put("filename", result.filename)
                        }.toString()
                    }
                }
                "directedRevoke" -> {
                    val port = httpPort()
                    if (port == 0) daemonUnavailable() else {
                        DirectedApi.revoke(dataDir, port, a[0] as String)
                        okJson()
                    }
                }
                else -> errorJson("unknown method")
            }
        } catch (e: Exception) {
            errorJson(e.message)
        }

        private fun status(): String {
            val port = httpPort()
            if (port > 0) {
                try {
                    return DirectedApi.status(dataDir, port).apply {
                        put("network_ready", true)
                    }.toString()
                } catch (_: Exception) {
                    // The embedded daemon may be between lifecycle states. Fall through
                    // to a local snapshot without claiming network connectivity.
                }
            }

            val s = getNodeStatus(dataDir)
            return JSONObject().apply {
                put("network_ready", false)
                put("peer_count", 0)
                put("share_count", s.shareCount.toLong())
                put("storage_used_bytes", (s.usedMb * 1024 * 1024).toLong())
                put("listen_addrs", org.json.JSONArray())
                put("peer_id", "")
            }.toString()
        }

        private fun wipe(): String {
            var warning = false
            try {
                NativeWipe.wipeKeys(dataDir)
            } catch (_: Exception) {
                warning = true
            }
            try {
                MiasmaService.stopNode(this@WebBridgeActivity)
            } catch (_: Exception) {
                warning = true
            }
            // WebView storage, cookies and cache must be cleared on the main thread.
            val done = java.util.concurrent.CountDownLatch(1)
            var cleared = false
            mainHandler.post {
                try {
                    cleared = NativeWipe.clearWebData(webView)
                } finally {
                    done.countDown()
                }
            }
            if (!done.await(10, java.util.concurrent.TimeUnit.SECONDS) || !cleared) warning = true
            return if (warning) errorJson("wipe completed with warnings") else okJson()
        }

        private fun envelopeList(items: List<DirectedApi.EnvelopeItem>): String =
            org.json.JSONArray().also { arr ->
                items.forEach { item ->
                    arr.put(JSONObject().apply {
                        put("envelope_id", item.envelopeId)
                        put("sender_pubkey", item.senderPubkey)
                        put("sender_peer_id", item.senderPeerId ?: JSONObject.NULL)
                        put("recipient_pubkey", item.recipientPubkey)
                        put("state", item.state)
                        put("created_at", item.createdAt)
                        put("expires_at", item.expiresAt)
                        put("retention_secs", item.retentionSecs)
                        put("challenge_code", item.challengeCode ?: JSONObject.NULL)
                        put("filename", item.filename ?: JSONObject.NULL)
                        put("file_size", item.fileSize)
                    })
                }
            }.toString()
    }

    private companion object {
        const val MAX_INFLIGHT = 4
    }
}
