package dev.miasma

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.miasma_ffi.*
import dev.miasma.uniffi.getDaemonHttpPort

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
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val dataDir: String by lazy { filesDir.absolutePath }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            webChromeClient = WebChromeClient()
            webViewClient = WebViewClient()
        }

        webView.addJavascriptInterface(MiasmaBridge(this), "miasma")
        setContentView(webView)
        webView.loadUrl("file:///android_asset/web/index.html")
    }

    override fun onDestroy() {
        webView.removeJavascriptInterface("miasma")
        webView.destroy()
        super.onDestroy()
    }

    /**
     * JavaScript bridge interface.
     *
     * All methods are synchronous from the JS perspective — they block on
     * the WebView's internal thread while the FFI call runs on IO.  This is
     * acceptable because the user expects to wait for dissolve/retrieve
     * operations.
     *
     * Note: `@JavascriptInterface` methods run on a binder thread, not the
     * main thread.  FFI calls are safe to make here (they use a shared
     * tokio runtime internally).
     */
    inner class MiasmaBridge(private val activity: WebBridgeActivity) {

        @JavascriptInterface
        fun ping(): String = """{"ok":true}"""

        @JavascriptInterface
        fun status(): String {
            return try {
                val s = getNodeStatus(dataDir)
                JSONObject().apply {
                    put("peer_count", 0) // FFI status is local-only for now
                    put("share_count", s.shareCount)
                    put("storage_used_bytes", (s.usedMb * 1024 * 1024).toLong())
                    put("listen_addrs", org.json.JSONArray())
                    put("peer_id", "")
                }.toString()
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun dissolve(dataBase64: String, k: Int, n: Int): String {
            return try {
                val bytes = android.util.Base64.decode(dataBase64, android.util.Base64.DEFAULT)
                val mid = dissolveBytes(dataDir, bytes)
                """{"mid":"$mid"}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun retrieve(mid: String, k: Int, n: Int): String {
            return try {
                val bytes = retrieveBytes(dataDir, mid)
                val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
                """{"data":"$b64"}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun wipe(): String {
            return try {
                distressWipe(dataDir)
                """{"ok":true}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        // ── Directed sharing (via HTTP bridge) ──────────────────────────

        private fun httpPort(): Int = getDaemonHttpPort().toInt()

        @JavascriptInterface
        fun sharingKey(): String {
            return try {
                val port = httpPort()
                if (port == 0) return """{"error":"daemon not running"}"""
                val result = DirectedApi.sharingKey(port)
                """{"key":"${result.key}","contact":"${result.contact}"}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun directedInbox(): String {
            return try {
                val port = httpPort()
                if (port == 0) return "[]"
                val items = DirectedApi.inbox(port)
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
                if (port == 0) return "[]"
                val items = DirectedApi.outbox(port)
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
                if (port == 0) return """{"error":"daemon not running"}"""
                val data = android.util.Base64.decode(dataBase64, android.util.Base64.DEFAULT)
                val envelopeId = DirectedApi.send(port, recipientContact, data, password, retentionSecs, filename)
                """{"envelope_id":"$envelopeId"}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun directedConfirm(envelopeId: String, challengeCode: String): String {
            return try {
                val port = httpPort()
                if (port == 0) return """{"error":"daemon not running"}"""
                DirectedApi.confirm(port, envelopeId, challengeCode)
                """{"ok":true}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun directedRetrieve(envelopeId: String, password: String): String {
            return try {
                val port = httpPort()
                if (port == 0) return """{"error":"daemon not running"}"""
                val result = DirectedApi.retrieve(port, envelopeId, password)
                val b64 = android.util.Base64.encodeToString(result.data, android.util.Base64.NO_WRAP)
                """{"data":"$b64"${if (result.filename != null) ""","filename":"${result.filename}"""" else ""}}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }

        @JavascriptInterface
        fun directedRevoke(envelopeId: String): String {
            return try {
                val port = httpPort()
                if (port == 0) return """{"error":"daemon not running"}"""
                DirectedApi.revoke(port, envelopeId)
                """{"ok":true}"""
            } catch (e: Exception) {
                """{"error":"${e.message?.replace("\"", "\\\"")}"}"""
            }
        }
    }
}
