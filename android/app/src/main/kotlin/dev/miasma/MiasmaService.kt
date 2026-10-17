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
import dev.miasma.uniffi.setBootstrapPeers
import dev.miasma.uniffi.startEmbeddedDaemon
import dev.miasma.uniffi.stopEmbeddedDaemon
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Foreground Service that owns the embedded Miasma node while Android permits
 * the data-sync foreground-service session. Android 15+ applies a background
 * time budget to this service type, so the app must tolerate a clean stop and
 * restart the node when the user returns.
 *
 * Start via [startNode] / stop via [stopNode] companion helpers.
 */
class MiasmaService : Service() {

    private data class NodeRequest(
        val dataDir: String,
        val storageMb: Long,
        val bandwidthMbDay: Long,
        val bootstrapPeers: List<String>,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var nodeJob: Job? = null
    private var currentRequest: NodeRequest? = null

    // ──── Lifecycle ──────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            lastDaemonStatus = null
            lastDaemonError = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(startId)
            return START_NOT_STICKY
        }

        val request = NodeRequest(
            dataDir = intent?.getStringExtra(EXTRA_DATA_DIR) ?: filesDir.absolutePath,
            storageMb = intent?.getLongExtra(EXTRA_STORAGE_MB, DEFAULT_STORAGE_MB) ?: DEFAULT_STORAGE_MB,
            bandwidthMbDay = intent?.getLongExtra(EXTRA_BANDWIDTH_MB_DAY, DEFAULT_BANDWIDTH_MB_DAY)
                ?: DEFAULT_BANDWIDTH_MB_DAY,
            bootstrapPeers = intent?.getStringArrayListExtra(EXTRA_BOOTSTRAP_PEERS)?.toList()
                ?: emptyList(),
        )

        startForeground(NOTIF_ID, buildNotification("Starting..."))

        // Activity recreation can send startForegroundService() again while the node is
        // already healthy. Treat an identical request as idempotent instead of creating
        // a second polling loop or daemon start attempt.
        if (currentRequest == request && nodeJob?.isActive == true && lastDaemonError == null) {
            return START_NOT_STICKY
        }

        val previousJob = nodeJob
        currentRequest = request
        nodeJob = scope.launch {
            previousJob?.cancelAndJoin()
            try { stopEmbeddedDaemon() } catch (_: Exception) { }

            val dataDir = request.dataDir
            val storageMb = request.storageMb
            val bandwidthMbDay = request.bandwidthMbDay
            val bootstrapPeers = request.bootstrapPeers
            lastDaemonStatus = null
            lastDaemonError = null

            // Ensure Android Keystore wrapping key exists.
            try { KeystoreHelper.ensureKey() } catch (_: Exception) { }

            val dataDirFile = java.io.File(dataDir)
            val masterKeyFile = dataDirFile.resolve("master.key")

            // If master.key is missing but wrapped blob exists, unwrap from Keystore.
            if (!masterKeyFile.exists()) {
                try {
                    val unwrapped = KeystoreHelper.unwrapKey(dataDirFile)
                    if (unwrapped != null) {
                        masterKeyFile.writeBytes(unwrapped)
                    }
                } catch (_: Exception) { /* Keystore may not have key yet on first run */ }
            }

            // Persist the mobile settings first. initializeNode is intentionally
            // idempotent and now preserves network/transport config across restarts.
            try {
                initializeNode(dataDir, storageMb.toULong(), bandwidthMbDay.toULong())
                setBootstrapPeers(dataDir, bootstrapPeers)
                val daemonStatus = startEmbeddedDaemon(dataDir, storageMb.toULong(), bandwidthMbDay.toULong())
                updateNotification("Connected · port ${daemonStatus.httpPort}")
                // Notify the ViewModel if the activity is active.
                lastDaemonStatus = daemonStatus
                lastDaemonError = null

                // Wrap the master key into Keystore (idempotent — overwrites existing blob).
                // This ensures the key is Keystore-backed even if it was just created by FFI.
                if (masterKeyFile.exists()) {
                    try {
                        KeystoreHelper.wrapKey(dataDirFile, masterKeyFile.readBytes())
                    } catch (_: Exception) { /* Keystore wrapping failure is non-fatal for now */ }
                }
            } catch (e: Exception) {
                updateNotification("Daemon error: ${e.message}")
                lastDaemonError = e.message
                // Fall back to local-only initialisation.
                try { initializeNode(dataDir, storageMb.toULong(), bandwidthMbDay.toULong()) } catch (_: Exception) { }
            }

            // Poll status and update the notification every 30 s.
            while (isActive) {
                try {
                    val status = getNodeStatus(dataDir)
                    updateNotification(statusSummary(status))
                } catch (_: Exception) { /* node not ready yet */ }
                delay(30_000)
            }
        }

        return START_NOT_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        // Android 15+ limits background time for dataSync foreground services.
        // Stop promptly instead of waiting for the system to escalate this to an ANR.
        lastDaemonStatus = null
        lastDaemonError = "Background node session ended by Android. Open Miasma to restart."
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    override fun onDestroy() {
        // Stop the embedded daemon gracefully and make stale ports invisible to the UI.
        lastDaemonStatus = null
        currentRequest = null
        nodeJob?.cancel()
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
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop node",
                PendingIntent.getService(
                    this,
                    1,
                    Intent(this, MiasmaService::class.java).setAction(ACTION_STOP),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
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
        private const val ACTION_STOP = "dev.miasma.action.STOP_NODE"
        private const val EXTRA_DATA_DIR = "data_dir"
        private const val EXTRA_STORAGE_MB = "storage_mb"
        private const val EXTRA_BANDWIDTH_MB_DAY = "bandwidth_mb_day"
        private const val EXTRA_BOOTSTRAP_PEERS = "bootstrap_peers"
        private const val DEFAULT_STORAGE_MB = 512L
        private const val DEFAULT_BANDWIDTH_MB_DAY = 100L

        /** Last daemon status, accessible from ViewModel to get HTTP port. */
        @Volatile
        var lastDaemonStatus: EmbeddedDaemonStatus? = null
            private set

        @Volatile
        var lastDaemonError: String? = null
            private set

        fun startNode(
            context: Context,
            dataDir: String,
            storageMb: Long = DEFAULT_STORAGE_MB,
            bandwidthMbDay: Long = DEFAULT_BANDWIDTH_MB_DAY,
            bootstrapPeers: List<String> = emptyList(),
        ) {
            val intent = Intent(context, MiasmaService::class.java).apply {
                putExtra(EXTRA_DATA_DIR, dataDir)
                putExtra(EXTRA_STORAGE_MB, storageMb)
                putExtra(EXTRA_BANDWIDTH_MB_DAY, bandwidthMbDay)
                putStringArrayListExtra(EXTRA_BOOTSTRAP_PEERS, ArrayList(bootstrapPeers))
            }
            context.startForegroundService(intent)
        }

        fun stopNode(context: Context) {
            context.stopService(Intent(context, MiasmaService::class.java))
        }
    }
}
