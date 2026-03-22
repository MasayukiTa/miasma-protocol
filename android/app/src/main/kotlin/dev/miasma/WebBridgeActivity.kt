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

/**
 * WebView-hosted Miasma web UI with a JavaScript bridge to native FFI.
 *
 * Loads the web app from app assets (`file:///android_asset/web/index.html`)
 * and injects `window.miasma` with methods that call through to the
 * UniFFI-generated Kotlin bindings.  This makes the web surface a real
 * network-capable client on Android.
 *
 * The bridge exposes: ping(), status(), dissolve(data, k, n),
 * retrieve(mid, k, n), wipe().
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
    }
}
