package dev.miasma

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import org.json.JSONObject
import dev.miasma.uniffi.*

/**
 * WebView-hosted Miasma web UI with a JavaScript bridge to native FFI.
 *
 * Loads the web app from app assets (`file:///android_asset/web/index.html`)
 * and injects `window.miasma` with methods that call through to the
 * UniFFI-generated Kotlin bindings and the HTTP bridge for directed sharing.
 *
 * The bridge exposes: ping(), status(), dissolve(data, k, n),
 * retrieve(mid, k, n), wipe(), plus directed sharing methods:
 * sharingKey(), directedSend(), directedConfirm(), directedRetrieve(),
 * directedRevoke(), directedInbox(), directedOutbox().
 */
class WebBridgeActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private val dataDir: String by lazy { filesDir.absolutePath }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.setSupportMultipleWindows(false)
            webChromeClient = WebChromeClient()
            webViewClient = LocalAssetsOnlyWebViewClient()
        }

        webView.addJavascriptInterface(MiasmaBridge(), "miasma")
        setContentView(webView)
        webView.loadUrl("file:///android_asset/web/index.html")
    }

    /**
     * The JavaScript interface is privileged: never let a remote document become
     * the top-level page while that interface is attached. The bundled PWA has a
     * restrictive CSP as a second layer, but navigation is enforced natively too.
     */
    private class LocalAssetsOnlyWebViewClient : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean =
            !isAllowedAppUrl(request.url)

        @Suppress("DEPRECATION")
        override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean =
            !isAllowedAppUrl(url?.let(Uri::parse))

        companion object {
            private const val APP_ASSET_PATH_PREFIX = "/android_asset/web/"

            private fun isAllowedAppUrl(uri: Uri?): Boolean {
                if (uri == null || uri.scheme != "file" || !uri.authority.isNullOrEmpty()) return false
                val path = uri.path ?: return false
                if (!path.startsWith(APP_ASSET_PATH_PREFIX)) return false
                return path.split('/').none { it == ".." }
            }
        }
    }

    override fun onDestroy() {
        webView.removeJavascriptInterface("miasma")
        webView.destroy()
        super.onDestroy()
    }

    /**
     * JavaScript bridge interface.
     *
     * All methods are synchronous from JavaScript's perspective. Android invokes
     * `@JavascriptInterface` methods on the WebView Java bridge thread rather than
     * the UI thread; direct FFI calls block that bridge thread until Rust returns.
     * The Rust side owns its shared Tokio runtime for async protocol work.
     */
    inner class MiasmaBridge {

        private fun errorJson(message: String?): String =
            JSONObject().put("error", message ?: "operation failed").toString()

        private fun okJson(): String = JSONObject().put("ok", true).toString()

        private fun daemonUnavailable(): String = errorJson("daemon not running")

        @JavascriptInterface
        fun ping(): String = okJson()

        @JavascriptInterface
        fun status(): String {
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

            return try {
                val s = getNodeStatus(dataDir)
                JSONObject().apply {
                    put("network_ready", false)
                    put("peer_count", 0)
                    put("share_count", s.shareCount.toLong())
                    put("storage_used_bytes", (s.usedMb * 1024 * 1024).toLong())
                    put("listen_addrs", org.json.JSONArray())
                    put("peer_id", "")
                }.toString()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun dissolve(dataBase64: String, k: Int, n: Int): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val bytes = android.util.Base64.decode(dataBase64, android.util.Base64.DEFAULT)
                val mid = DirectedApi.publishBytes(dataDir, port, bytes, k, n)
                JSONObject().put("mid", mid).toString()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun retrieve(mid: String, k: Int, n: Int): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val bytes = DirectedApi.retrieveBytes(dataDir, port, mid, k, n)
                val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                JSONObject().put("data", b64).toString()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun wipe(): String {
            var warning = false
            try {
                distressWipe(dataDir)
            } catch (_: Exception) {
                warning = true
            }

            // Rust erases the plaintext and wrapped blobs; Android must also
            // destroy the non-exportable wrapping key held by AndroidKeyStore.
            try {
                KeystoreHelper.deleteKey()
            } catch (_: Exception) {
                warning = true
            }
            try {
                MiasmaService.stopNode(this@WebBridgeActivity)
            } catch (_: Exception) {
                warning = true
            }

            return if (warning) errorJson("wipe completed with warnings") else okJson()
        }

        // ── Directed sharing (via HTTP bridge) ──────────────────────────

        private fun httpPort(): Int = getDaemonHttpPort().toInt()

        @JavascriptInterface
        fun sharingKey(): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val result = DirectedApi.sharingKey(dataDir, port)
                JSONObject().apply {
                    put("key", result.key)
                    put("contact", result.contact)
                }.toString()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun directedInbox(): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val items = DirectedApi.inbox(dataDir, port)
                org.json.JSONArray().also { arr ->
                    items.forEach { item ->
                        arr.put(JSONObject().apply {
                            put("envelope_id", item.envelopeId)
                            put("sender_pubkey", item.senderPubkey)
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
            } catch (e: Exception) {
                "[]"
            }
        }

        @JavascriptInterface
        fun directedOutbox(): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val items = DirectedApi.outbox(dataDir, port)
                org.json.JSONArray().also { arr ->
                    items.forEach { item ->
                        arr.put(JSONObject().apply {
                            put("envelope_id", item.envelopeId)
                            put("sender_pubkey", item.senderPubkey)
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
            } catch (e: Exception) {
                "[]"
            }
        }

        @JavascriptInterface
        fun directedSend(recipientContact: String, dataBase64: String, password: String, retentionSecs: Long, filename: String?): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val data = android.util.Base64.decode(dataBase64, android.util.Base64.DEFAULT)
                val envelopeId = DirectedApi.send(dataDir, port, recipientContact, data, password, retentionSecs, filename)
                JSONObject().put("envelope_id", envelopeId).toString()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun directedConfirm(envelopeId: String, challengeCode: String): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                DirectedApi.confirm(dataDir, port, envelopeId, challengeCode)
                okJson()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun directedRetrieve(envelopeId: String, password: String): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                val result = DirectedApi.retrieve(dataDir, port, envelopeId, password)
                val b64 = android.util.Base64.encodeToString(result.data, android.util.Base64.NO_WRAP)
                JSONObject().apply {
                    put("data", b64)
                    if (result.filename != null) put("filename", result.filename)
                }.toString()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }

        @JavascriptInterface
        fun directedRevoke(envelopeId: String): String {
            return try {
                val port = httpPort()
                if (port == 0) return daemonUnavailable()
                DirectedApi.revoke(dataDir, port, envelopeId)
                okJson()
            } catch (e: Exception) {
                errorJson(e.message)
            }
        }
    }
}
