package dev.miasma

import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import dev.miasma.uniffi.EmbeddedDaemonStatus
import dev.miasma.uniffi.NodeStatusFfi
import dev.miasma.uniffi.getNodeStatus
import dev.miasma.uniffi.initializeNode
import dev.miasma.uniffi.startEmbeddedDaemon
import dev.miasma.uniffi.stopEmbeddedDaemon
import dev.miasma.uniffi.isDaemonRunning
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Foreground Service that keeps the Miasma node alive while the app is in the
 * background.  The node itself runs on a coroutine (Dispatchers.IO); this
 * service just owns the lifecycle.
 *
 * Start via [startNode] / stop via [stopNode] companion helpers.
 */
class MiasmaService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // ──── Lifecycle ──────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val dataDir = intent?.getStringExtra(EXTRA_DATA_DIR) ?: filesDir.absolutePath
        val storageMb = intent?.getLongExtra(EXTRA_STORAGE_MB, DEFAULT_STORAGE_MB) ?: DEFAULT_STORAGE_MB
        val bandwidthMbDay = intent?.getLongExtra(EXTRA_BANDWIDTH_MB_DAY, DEFAULT_BANDWIDTH_MB_DAY)
            ?: DEFAULT_BANDWIDTH_MB_DAY

        startForeground(NOTIF_ID, buildNotification("Starting…"))

        scope.launch {
            // Ensure Android Keystore wrapping key exists.
            try { KeystoreHelper.ensureKey() } catch (_: Exception) { }

            // Start the embedded daemon (initialises node + networking + HTTP bridge).
            try {
                val daemonStatus = startEmbeddedDaemon(dataDir, storageMb, bandwidthMbDay)
                updateNotification("Connected · port ${daemonStatus.httpPort}")
                // Notify the ViewModel if the activity is active.
                lastDaemonStatus = daemonStatus
            } catch (e: Exception) {
                updateNotification("Daemon error: ${e.message}")
                // Fall back to local-only initialisation.
                try { initializeNode(dataDir, storageMb, bandwidthMbDay) } catch (_: Exception) { }
            }

            // Poll status and update the notification every 30 s.
            while (true) {
                try {
                    val status = getNodeStatus(dataDir)
                    updateNotification(statusSummary(status))
                } catch (_: Exception) { /* node not ready yet */ }
                delay(30_000)
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        // Stop the embedded daemon gracefully.
        try { stopEmbeddedDaemon() } catch (_: Exception) { }
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ──── Notification helpers ───────────────────────────────────────────────

    private fun buildNotification(text: String) =
        NotificationCompat.Builder(this, MiasmaApp.CHANNEL_DAEMON)
            .setSmallIcon(android.R.drawable.ic_dialog_info)   // replace with real icon in assets
            .setContentTitle("Miasma Node")
            .setContentText(text)
            .setOngoing(true)
            .setSilent(true)
            // Hide details on lock screen — only show "Miasma Node" title.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(
                NotificationCompat.Builder(this, MiasmaApp.CHANNEL_DAEMON)
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setContentTitle("Miasma Node")
                    .setContentText("Running")
                    .build()
            )
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                )
            )
            .build()

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun statusSummary(s: NodeStatusFfi) =
        "${s.shareCount} shares · ${"%.1f".format(s.usedMb)} / ${s.quotaMb} MiB"

    // ──── Companion ──────────────────────────────────────────────────────────

    companion object {
        private const val NOTIF_ID = 1001
        private const val EXTRA_DATA_DIR = "data_dir"
        private const val EXTRA_STORAGE_MB = "storage_mb"
        private const val EXTRA_BANDWIDTH_MB_DAY = "bandwidth_mb_day"
        private const val DEFAULT_STORAGE_MB = 512L
        private const val DEFAULT_BANDWIDTH_MB_DAY = 100L

        /** Last daemon status, accessible from ViewModel to get HTTP port. */
        @Volatile
        var lastDaemonStatus: EmbeddedDaemonStatus? = null
            private set

        fun startNode(
            context: Context,
            dataDir: String,
            storageMb: Long = DEFAULT_STORAGE_MB,
            bandwidthMbDay: Long = DEFAULT_BANDWIDTH_MB_DAY,
        ) {
            val intent = Intent(context, MiasmaService::class.java).apply {
                putExtra(EXTRA_DATA_DIR, dataDir)
                putExtra(EXTRA_STORAGE_MB, storageMb)
                putExtra(EXTRA_BANDWIDTH_MB_DAY, bandwidthMbDay)
            }
            context.startForegroundService(intent)
        }

        fun stopNode(context: Context) {
            context.stopService(Intent(context, MiasmaService::class.java))
        }
    }
}
