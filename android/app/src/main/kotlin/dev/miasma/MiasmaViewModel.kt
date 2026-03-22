package dev.miasma

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.miasma.uniffi.MiasmaFfiException
import dev.miasma.uniffi.NodeStatusFfi
import dev.miasma.uniffi.dissolveBytes
import dev.miasma.uniffi.getNodeStatus
import dev.miasma.uniffi.retrieveBytes
import dev.miasma.uniffi.distressWipe as ffiDistressWipe
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
                val mid = withContext(Dispatchers.IO) { dissolveBytes(dataDir, data) }
                _ui.value = _ui.value.copy(isLoading = false, lastMid = mid)
                refreshStatus()
            } catch (e: MiasmaFfiException) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
            } catch (e: Exception) {
                // Sanitize unexpected exception messages before showing in UI.
                _ui.value = _ui.value.copy(isLoading = false, error = "Dissolution failed")
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
                withContext(Dispatchers.IO) {
                    ffiDistressWipe(dataDir)
                    KeystoreHelper.deleteKey()
                    // Delete wrapped key blobs on the Kotlin side too.
                    val dataFile = java.io.File(dataDir)
                    dataFile.resolve("master.key.enc").delete()
                    dataFile.resolve("master.key.iv").delete()
                }
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
}
