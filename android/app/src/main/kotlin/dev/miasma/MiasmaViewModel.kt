package dev.miasma

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.miasma.uniffi.MiasmaFfiException
import dev.miasma.uniffi.NodeStatusFfi
import dev.miasma.uniffi.dissolveBytes
import dev.miasma.uniffi.getNodeStatus
import dev.miasma.uniffi.retrieveBytes
import dev.miasma.uniffi.distressWipe
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
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
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
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
            }
        }
    }

    // ──── Distress wipe ──────────────────────────────────────────────────────

    fun distressWipe() {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, error = null)
            try {
                withContext(Dispatchers.IO) { distressWipe(dataDir) }
                _ui.value = UiState() // reset all state
            } catch (e: Exception) {
                _ui.value = _ui.value.copy(isLoading = false, error = e.message)
            }
        }
    }

    fun clearError() {
        _ui.value = _ui.value.copy(error = null)
    }
}
