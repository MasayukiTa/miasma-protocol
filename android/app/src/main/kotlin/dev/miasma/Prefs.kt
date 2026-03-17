package dev.miasma

import android.content.Context
import androidx.core.content.edit

/**
 * Thin wrapper around SharedPreferences for persistent node settings.
 * All values are read/written synchronously on the calling thread — callers
 * on background threads (Dispatchers.IO) are fine; UI reads are cheap.
 */
object Prefs {

    private const val PREF_FILE = "miasma_prefs"
    private const val KEY_STORAGE_MB = "storage_mb"
    private const val KEY_BANDWIDTH_MB_DAY = "bandwidth_mb_day"
    private const val KEY_BOOTSTRAP_PEERS = "bootstrap_peers"

    // ──── Defaults ───────────────────────────────────────────────────────────

    const val DEFAULT_STORAGE_MB      = 512L
    const val DEFAULT_BANDWIDTH_MB_DAY = 100L

    // ──── Accessors ──────────────────────────────────────────────────────────

    fun storageMb(ctx: Context): Long =
        ctx.prefs().getLong(KEY_STORAGE_MB, DEFAULT_STORAGE_MB)

    fun bandwidthMbDay(ctx: Context): Long =
        ctx.prefs().getLong(KEY_BANDWIDTH_MB_DAY, DEFAULT_BANDWIDTH_MB_DAY)

    /** Newline-separated list of bootstrap multiaddrs. */
    fun bootstrapPeers(ctx: Context): List<String> =
        ctx.prefs().getString(KEY_BOOTSTRAP_PEERS, "")
            ?.lines()?.filter { it.isNotBlank() } ?: emptyList()

    fun setStorageMb(ctx: Context, value: Long) =
        ctx.prefs().edit { putLong(KEY_STORAGE_MB, value) }

    fun setBandwidthMbDay(ctx: Context, value: Long) =
        ctx.prefs().edit { putLong(KEY_BANDWIDTH_MB_DAY, value) }

    fun setBootstrapPeers(ctx: Context, peers: List<String>) =
        ctx.prefs().edit { putString(KEY_BOOTSTRAP_PEERS, peers.joinToString("\n")) }

    // ──── Private helper ─────────────────────────────────────────────────────

    private fun Context.prefs() =
        getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
}
