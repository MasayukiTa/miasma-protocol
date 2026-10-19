package dev.miasma.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.miasma.MiasmaViewModel
import dev.miasma.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun RetrieveScreen(vm: MiasmaViewModel) {
    val daemonPort by vm.daemonHttpPort.collectAsState()
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    var midInput by remember { mutableStateOf("") }
    var isRetrieving by remember { mutableStateOf(false) }
    var retrieveError by remember { mutableStateOf<String?>(null) }
    var retrieveResult by remember { mutableStateOf<String?>(null) }

    val invalidMidText = stringResource(R.string.retrieve_invalid_mid)
    val destinationOpenFailedText = stringResource(R.string.destination_open_failed)
    val saveFailedText = stringResource(R.string.save_retrieved_failed)
    val defaultFilename = stringResource(R.string.retrieved_file_default)
    val scanPrompt = stringResource(R.string.retrieve_scan_prompt)

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            cleanupOldStagingFiles(context.cacheDir, "miasma-retrieve-mid")
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { scanned ->
            if (isValidMidInput(scanned)) {
                midInput = scanned
            } else {
                Toast.makeText(context, invalidMidText, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val mid = midInput.trim()
        if (!isValidMidInput(mid)) {
            Toast.makeText(context, invalidMidText, Toast.LENGTH_SHORT).show()
            return@rememberLauncherForActivityResult
        }

        val temp = newPrivateTempFile(context, "miasma-retrieve-mid")
        isRetrieving = true
        retrieveError = null
        retrieveResult = null
        vm.retrieveMidToFile(mid, temp.absolutePath) { result, error ->
            if (error != null || result == null) {
                temp.delete()
                try {
                    context.contentResolver.delete(uri, null, null)
                } catch (_: Exception) {
                    // The provider may leave an empty document; retrieval still failed safely.
                }
                isRetrieving = false
                retrieveError = error ?: context.getString(R.string.retrieve_failed)
            } else {
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            copyFileToUri(context, temp, uri, destinationOpenFailedText)
                        }
                        retrieveResult = context.getString(
                            R.string.saved_size,
                            formatStagedFileSize(result.bytesWritten),
                        )
                    } catch (e: Exception) {
                        retrieveError = e.message ?: saveFailedText
                        try {
                            context.contentResolver.delete(uri, null, null)
                        } catch (_: Exception) {
                            // The provider may not support delete. Keep the original error.
                        }
                    } finally {
                        temp.delete()
                        isRetrieving = false
                    }
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
    ) {
        Text(stringResource(R.string.retrieve_title), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.retrieve_description),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(20.dp))

        if (daemonPort == 0) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    stringResource(R.string.retrieve_daemon_unavailable),
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            Spacer(Modifier.height(12.dp))
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    stringResource(R.string.retrieve_content_id),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = midInput,
                    onValueChange = {
                        midInput = it
                        retrieveError = null
                        retrieveResult = null
                    },
                    placeholder = { Text("miasma:...") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                    trailingIcon = {
                        IconButton(
                            onClick = {
                                clipboardManager.getText()?.text?.let { text ->
                                    if (isValidMidInput(text)) {
                                        midInput = text
                                    } else {
                                        Toast.makeText(context, invalidMidText, Toast.LENGTH_SHORT).show()
                                    }
                                }
                            },
                        ) {
                            Icon(
                                Icons.Outlined.ContentCopy,
                                contentDescription = stringResource(R.string.retrieve_paste),
                                modifier = Modifier.size(20.dp),
                            )
                        }
                    },
                )

                Spacer(Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = {
                            val mid = midInput.trim()
                            if (isValidMidInput(mid)) {
                                retrieveError = null
                                retrieveResult = null
                                saveLauncher.launch(defaultFilename)
                            } else {
                                Toast.makeText(context, invalidMidText, Toast.LENGTH_SHORT).show()
                            }
                        },
                        enabled = daemonPort > 0 && midInput.isNotBlank() && !isRetrieving,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Icon(Icons.Outlined.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.retrieve_save_to_device))
                    }

                    FilledTonalButton(
                        onClick = {
                            scanLauncher.launch(
                                ScanOptions().apply {
                                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    setPrompt(scanPrompt)
                                    setBeepEnabled(false)
                                },
                            )
                        },
                        enabled = !isRetrieving,
                        shape = RoundedCornerShape(8.dp),
                    ) {
                        Icon(Icons.Outlined.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(stringResource(R.string.retrieve_scan))
                    }
                }
            }
        }

        if (isRetrieving) {
            Spacer(Modifier.height(24.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(12.dp))
                Text(stringResource(R.string.retrieve_in_progress), style = MaterialTheme.typography.bodyMedium)
            }
        }

        retrieveError?.let { error ->
            Spacer(Modifier.height(16.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.error.copy(alpha = 0.1f),
                ),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text(
                    error,
                    modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        retrieveResult?.let { result ->
            Spacer(Modifier.height(16.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                shape = RoundedCornerShape(8.dp),
            ) {
                Text(
                    result,
                    modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

private fun isValidMidInput(value: String): Boolean {
    val trimmed = value.trim()
    return trimmed.startsWith("miasma:") && trimmed.length in 8..128
}
