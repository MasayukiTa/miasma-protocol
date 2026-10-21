package dev.miasma

import android.webkit.CookieManager
import android.webkit.WebStorage
import android.webkit.WebView
import dev.miasma.uniffi.distressWipe as ffiDistressWipe

/** Steps shared by every wipe entry point (Compose screens and the WebView bridge). */
object NativeWipe {

    /**
     * Rust key wipe, then the Android Keystore wrapping key and the wrapped key
     * blobs. The Keystore and blob cleanup always runs, even if the Rust wipe
     * throws. Throws if the Rust wipe failed, or if cleanup was incomplete.
     * Blocking: call off the main thread.
     */
    fun wipeKeys(dataDir: String) {
        var cleanupFailed = false
        try {
            ffiDistressWipe(dataDir)
        } finally {
            // Each step is isolated so a failure cannot hide the original error.
            if (runCatching { KeystoreHelper.deleteKey() }.isFailure) {
                cleanupFailed = true
            }
            val dataFile = java.io.File(dataDir)
            for (name in listOf("master.key.enc", "master.key.iv")) {
                val removed = runCatching {
                    val f = dataFile.resolve(name)
                    !f.exists() || f.delete()
                }.getOrDefault(false)
                if (!removed) cleanupFailed = true
            }
        }
        // Reached only if the Rust wipe succeeded.
        if (cleanupFailed) throw IllegalStateException("wipe cleanup incomplete")
    }

    /**
     * Clears what the WebView keeps for the app's web origin: local storage,
     * IndexedDB, Cache Storage and service worker registrations
     * ([WebStorage.deleteAllData]), cookies, and the HTTP cache and history of
     * [webView] when there is one. Must run on the main thread.
     * Returns false if any step failed.
     */
    fun clearWebData(webView: WebView?): Boolean {
        var ok = true
        if (runCatching { WebStorage.getInstance().deleteAllData() }.isFailure) ok = false
        if (runCatching {
                val cm = CookieManager.getInstance()
                cm.removeAllCookies(null)
                cm.flush()
            }.isFailure
        ) ok = false
        if (webView != null && runCatching {
                webView.clearCache(true)
                webView.clearHistory()
                webView.clearFormData()
            }.isFailure
        ) ok = false
        return ok
    }
}

/** Optional `FLAG_SECURE` for the app's windows (screenshots, recents thumbnails, screen sharing). */
object ScreenPrivacy {
    fun apply(activity: android.app.Activity) {
        val window = activity.window
        if (Prefs.screenPrivacy(activity)) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
