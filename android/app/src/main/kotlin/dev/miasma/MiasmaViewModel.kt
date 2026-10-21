package dev.miasma

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.miasma.uniffi.MiasmaFfiException
import dev.miasma.uniffi.NodeStatusFfi
import dev.miasma.uniffi.dissolveBytes
import dev.miasma.uniffi.getNodeStatus
import dev.miasma.uniffi.publishFile as ffiPublishFile
import dev.miasma.uniffi.retrieveBytes
import dev.miasma.uniffi.retrieveToFile as ffiRetrieveToFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class UiState(
    val isLoading: Boolean = false,
    val nodeStatus: NodeStatusFfi? = null,
    val lastMid: String? = null,
    val retrievedBytes: ByteArray? = null,
    val error: String? = null,
)

class MiasmaViewModel(app: Application) : AndroidViewModel(app) {

    private val dataDir: String
        get() = getApplication<MiasmaApp>().filesDir.absolutePath

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    // ──── Embedded daemon state ───────────────────────────────────────────

    private val _daemonHttpPort = MutableStateFlow(0)
    val daemonHttpPort: StateFlow<Int> = _daemonHttpPort.asStateFlow()

    private val _sharingContact = MutableStateFlow("")
    val sharingContact: StateFlow<String> = _sharingContact.asStateFlow()

    private val _inboxItems = MutableStateFlow<List<DirectedApi.EnvelopeItem>>(emptyList())
    val inboxItems: StateFlow<List<DirectedApi.EnvelopeItem>> = _inboxItems.asStateFlow()

    private val _outboxItems = MutableStateFlow<List<DirectedApi.EnvelopeItem>>(emptyList())
    val outboxItems: StateFlow<List<DirectedApi.EnvelopeItem>> = _outboxItems.asStateFlow()

    /** Called by MiasmaService after daemon starts. */
    fun onDaemonStarted(httpPort: Int, contact: String) {
        _daemonHttpPort.value = httpPort
        _sharingContact.value = contact
        if (httpPort == 0) {
            _inboxItems.value = emptyList()
            _outboxItems.value = emptyList()
        }
    }

    fun onDaemonError(error: String) {
        _ui.value = _ui.value.copy(error = "Daemon: $error")
    }

    // ──── Status ─────────────────────────────────────────────────────────────

    fun refreshStatus() {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, error = null)
            try {
                val status = withContext(Dispatchers.IO) { getNodeStatus(dataDir) }
                _ui.value = _ui.value.copy(isLoading = false, nodeStatus = status)
            } catch (e: MiasmaFfiException.NotInitialized) {
                _ui.value = _ui.value.copy(isLoading = false, nodeStatus = null)
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
            }
        }
    }

    // ──── Dissolve ───────────────────────────────────────────────────────────

    fun dissolve(data: ByteArray) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, error = null, lastMid = null)
            try {
                val port = _daemonHttpPort.value
                val mid = withContext(Dispatchers.IO) {
                    if (port > 0) DirectedApi.publishBytes(dataDir, port, data)
                    else dissolveBytes(dataDir, data)
                }
                _ui.value = _ui.value.copy(isLoading = false, lastMid = mid)
                refreshStatus()
            } catch (e: MiasmaFfiException) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message ?: "Dissolution failed")
            }
        }
    }

    fun dissolveFile(filePath: String, callback: (mid: String?, error: String?) -> Unit) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback(null, "Daemon not running")
            return
        }
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, error = null, lastMid = null)
            try {
                val mid = withContext(Dispatchers.IO) { ffiPublishFile(dataDir, filePath) }
                _ui.value = _ui.value.copy(isLoading = false, lastMid = mid)
                refreshStatus()
                callback(mid, null)
            } catch (e: Exception) {
                val message = e.message ?: "Dissolution failed"
                _ui.value = _ui.value.copy(isLoading = false, error = message)
                callback(null, message)
            }
        }
    }

    // ──── Retrieve ───────────────────────────────────────────────────────────

    fun retrieve(mid: String) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, error = null, retrievedBytes = null)
            try {
                val bytes = withContext(Dispatchers.IO) { retrieveBytes(dataDir, mid) }
                _ui.value = _ui.value.copy(isLoading = false, retrievedBytes = bytes)
            } catch (e: MiasmaFfiException.InsufficientShares) {
                _ui.value = _ui.value.copy(
                    isLoading = false,
                    error = "Not enough shares: need ${e.need}, found ${e.got}",
                )
            } catch (e: MiasmaFfiException) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(isLoading = false, error = "Retrieval failed")
            }
        }
    }

    // ──── Distress wipe ──────────────────────────────────────────────────────

    fun retrieveMidToFile(
        mid: String,
        outputPath: String,
        callback: (result: DirectedApi.RetrieveMidToFileResult?, error: String?) -> Unit,
    ) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback(null, "Daemon not running")
            return
        }
        viewModelScope.launch {
            try {
                val ffiResult = withContext(Dispatchers.IO) {
                    ffiRetrieveToFile(dataDir, mid, outputPath)
                }
                val result = DirectedApi.RetrieveMidToFileResult(
                    outputPath = ffiResult.outputPath,
                    bytesWritten = ffiResult.bytesWritten.toLong(),
                )
                callback(result, null)
            } catch (e: Exception) {
                callback(null, e.message ?: "Retrieval failed")
            }
        }
    }

    /**
     * Emergency distress wipe:
     *   1. Rust FFI — zeroes and deletes master.key (≤5s per ADR-003).
     *   2. Android Keystore — deletes hardware-backed wrapping key so
     *      master.key.enc is cryptographically unrecoverable.
     *   3. Stops the background daemon.
     *   4. Resets all UI state.
     */
    fun distressWipe() {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, error = null)
            val ctx: Context = getApplication()
            try {
                // Key wipe always runs the Keystore and blob cleanup; a failure
                // anywhere is reported through the same warning path.
                var webCleared = true
                try {
                    withContext(Dispatchers.IO) { NativeWipe.wipeKeys(dataDir) }
                } finally {
                    // WebView site data (storage, cookies, service workers) goes too,
                    // whether or not the key wipe reported a problem.
                    webCleared = NativeWipe.clearWebData(null)
                }
                if (!webCleared) throw IllegalStateException("wipe cleanup incomplete")
                MiasmaService.stopNode(ctx)
                // Clear all sensitive state including any retrieved bytes.
                val prev = _ui.value.retrievedBytes
                _ui.value = UiState()
                prev?.fill(0)
            } catch (e: Exception) {
                // Wipe should never show internal error details.
                _ui.value = _ui.value.copy(isLoading = false, error = "Wipe operation completed with warnings")
                // Still try to stop the service even on error.
                try { MiasmaService.stopNode(ctx) } catch (_: Exception) { }
            }
        }
    }

    /** Clear retrieved bytes from memory to limit exposure time. */
    fun clearRetrievedBytes() {
        val prev = _ui.value.retrievedBytes
        _ui.value = _ui.value.copy(retrievedBytes = null)
        // Best-effort zeroing of the ByteArray (JVM may still have copies).
        prev?.fill(0)
    }

    fun clearError() {
        _ui.value = _ui.value.copy(error = null)
    }

    // ──── Directed sharing operations ─────────────────────────────────────

    fun refreshInbox() {
        val port = _daemonHttpPort.value
        if (port == 0) return
        viewModelScope.launch {
            try {
                val items = withContext(Dispatchers.IO) { DirectedApi.inbox(dataDir, port) }
                _inboxItems.value = items
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(error = "Inbox refresh failed: ${e.message}")
            }
        }
    }

    fun refreshOutbox() {
        val port = _daemonHttpPort.value
        if (port == 0) return
        viewModelScope.launch {
            try {
                val items = withContext(Dispatchers.IO) { DirectedApi.outbox(dataDir, port) }
                _outboxItems.value = items
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(error = "Outbox refresh failed: ${e.message}")
            }
        }
    }

    fun sendDirected(
        recipientContact: String,
        data: ByteArray,
        password: String,
        retentionSecs: Long,
        filename: String? = null,
        callback: (envelopeId: String?, error: String?) -> Unit,
    ) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback(null, "Daemon not running")
            return
        }
        viewModelScope.launch {
            try {
                val envelopeId = withContext(Dispatchers.IO) {
                    DirectedApi.send(dataDir, port, recipientContact, data, password, retentionSecs, filename)
                }
                refreshOutbox()
                callback(envelopeId, null)
            } catch (e: Exception) {
                callback(null, e.message ?: "Send failed")
            }
        }
    }

    fun sendDirectedFile(
        recipientContact: String,
        filePath: String,
        password: String,
        retentionSecs: Long,
        filename: String?,
        callback: (envelopeId: String?, error: String?) -> Unit,
    ) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback(null, "Daemon not running")
            return
        }
        viewModelScope.launch {
            try {
                val envelopeId = withContext(Dispatchers.IO) {
                    DirectedApi.sendFile(
                        dataDir, port, recipientContact, filePath, password, retentionSecs, filename
                    )
                }
                refreshOutbox()
                callback(envelopeId, null)
            } catch (e: Exception) {
                callback(null, e.message ?: "Send failed")
            }
        }
    }

    fun confirmDirected(envelopeId: String, challengeCode: String, callback: (error: String?) -> Unit) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback("Daemon not running")
            return
        }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { DirectedApi.confirm(dataDir, port, envelopeId, challengeCode) }
                refreshOutbox()
                callback(null)
            } catch (e: Exception) {
                callback(e.message ?: "Confirm failed")
            }
        }
    }

    fun retrieveDirected(envelopeId: String, password: String, callback: (error: String?) -> Unit) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback("Daemon not running")
            return
        }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    DirectedApi.retrieve(dataDir, port, envelopeId, password)
                }
                // Store retrieved bytes in UI state for display/export.
                _ui.value = _ui.value.copy(retrievedBytes = result.data)
                refreshInbox()
                callback(null)
            } catch (e: Exception) {
                callback(e.message ?: "Retrieve failed")
            }
        }
    }

    fun retrieveDirectedToFile(
        envelopeId: String,
        password: String,
        outputPath: String,
        callback: (result: DirectedApi.RetrieveToFileResult?, error: String?) -> Unit,
    ) {
        val port = _daemonHttpPort.value
        if (port == 0) {
            callback(null, "Daemon not running")
            return
        }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    DirectedApi.retrieveToFile(dataDir, port, envelopeId, password, outputPath)
                }
                refreshInbox()
                callback(result, null)
            } catch (e: Exception) {
                callback(null, e.message ?: "Retrieve failed")
            }
        }
    }

    fun revokeDirected(envelopeId: String) {
        val port = _daemonHttpPort.value
        if (port == 0) return
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { DirectedApi.revoke(dataDir, port, envelopeId) }
                refreshOutbox()
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(error = "Revoke failed: ${e.message}")
            }
        }
    }

    fun deleteDirectedEnvelope(envelopeId: String, isInbox: Boolean) {
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    dev.miasma.uniffi.deleteDirectedEnvelope(dataDir, envelopeId)
                }
                if (isInbox) refreshInbox() else refreshOutbox()
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(error = "Delete failed: ${e.message}")
            }
        }
    }
}
