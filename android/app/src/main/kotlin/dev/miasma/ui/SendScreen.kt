package dev.miasma.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.miasma.MiasmaViewModel
import dev.miasma.R
import java.io.File
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SendScreen(vm: MiasmaViewModel) {
    val daemonPort by vm.daemonHttpPort.collectAsState()
    val sharingContact by vm.sharingContact.collectAsState()
    val context = LocalContext.current

    val fileTooLargeText = stringResource(R.string.send_file_too_large)
    val fileOpenFailedText = stringResource(R.string.send_file_open_failed)
    val fileReadFailedText = stringResource(R.string.send_file_read_failed)
    val recipientInvalidText = stringResource(R.string.send_recipient_invalid)

    var recipientContact by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var selectedFile by remember { mutableStateOf<StagedFile?>(null) }
    var isStagingFile by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var retentionHours by remember { mutableStateOf("24") }
    var isSending by remember { mutableStateOf(false) }
    var sendResult by remember { mutableStateOf<String?>(null) }
    var sendError by remember { mutableStateOf<String?>(null) }
    var recipientFormatError by remember { mutableStateOf<String?>(null) }
    var retentionFallbackUsed by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) { cleanupOldStagingFiles(context.cacheDir, "miasma-send") }
    }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        isStagingFile = true
        sendError = null
        scope.launch {
            try {
                val staged = withContext(Dispatchers.IO) { stageSelectedFile(context, uri, fileTooLargeText, fileOpenFailedText) }
                val previous = selectedFile
                selectedFile = staged
                if (previous != null && previous.path != staged.path) File(previous.path).delete()
                message = ""
            } catch (e: Exception) {
                sendError = e.message ?: fileReadFailedText
            } finally {
                isStagingFile = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        Text(stringResource(R.string.send_title), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))

        if (daemonPort == 0) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    stringResource(R.string.send_daemon_unavailable),
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            return
        }

        // Show own sharing contact for copy
        if (sharingContact.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.send_your_contact), style = MaterialTheme.typography.labelSmall)
                    Text(
                        sharingContact,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 2,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
        }

        // Recipient
        OutlinedTextField(
            value = recipientContact,
            onValueChange = {
                recipientContact = it
                recipientFormatError = if (it.isNotBlank() && (!it.trimStart().startsWith("msk:") || !it.contains("@"))) {
                    recipientInvalidText
                } else null
            },
            label = { Text(stringResource(R.string.send_recipient_contact)) },
            singleLine = true,
            isError = recipientFormatError != null,
            modifier = Modifier.fillMaxWidth(),
        )
        if (recipientFormatError != null) {
            Text(
                recipientFormatError!!,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 4.dp),
            )
        }
        Spacer(Modifier.height(8.dp))

        // Message content
        OutlinedTextField(
            value = message,
            onValueChange = { message = it },
            label = { Text(stringResource(R.string.send_message_content)) },
            modifier = Modifier.fillMaxWidth().height(120.dp),
            maxLines = 6,
            enabled = selectedFile == null && !isStagingFile,
        )
        Spacer(Modifier.height(8.dp))

        OutlinedButton(
            onClick = { filePicker.launch("*/*") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isSending && !isStagingFile,
        ) {
            if (isStagingFile) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(stringResource(if (selectedFile == null) R.string.send_choose_file else R.string.send_change_file))
        }
        selectedFile?.let { file ->
            Text(
                stringResource(R.string.send_selected_file, file.name, formatSelectedFileSize(file.size)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            TextButton(onClick = {
                File(file.path).delete()
                selectedFile = null
            }) { Text(stringResource(R.string.send_use_text)) }
        }
        Spacer(Modifier.height(8.dp))

        // Password
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(stringResource(R.string.send_password)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))

        // Retention
        OutlinedTextField(
            value = retentionHours,
            onValueChange = {
                retentionHours = it.filter { c -> c.isDigit() }
                retentionFallbackUsed = false
            },
            label = { Text(stringResource(R.string.send_retention_hours)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(0.5f),
        )
        if (retentionFallbackUsed) {
            Text(
                stringResource(R.string.send_retention_default),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 4.dp),
            )
        }
        Spacer(Modifier.height(12.dp))

        // Send button
        Button(
            onClick = {
                isSending = true
                sendResult = null
                sendError = null
                val parsedHours = retentionHours.toLongOrNull()
                if (parsedHours == null) retentionFallbackUsed = true
                val retSecs = (parsedHours ?: 24) * 3600
                val staged = selectedFile
                val callback: (String?, String?) -> Unit = { envelopeId, error ->
                    isSending = false
                    sendResult = envelopeId
                    sendError = error
                    if (envelopeId != null && error == null && staged != null) {
                        File(staged.path).delete()
                        if (selectedFile?.path == staged.path) selectedFile = null
                    }
                }
                if (staged != null) {
                    vm.sendDirectedFile(
                        recipientContact = recipientContact.trim(),
                        filePath = staged.path,
                        password = password,
                        retentionSecs = retSecs,
                        filename = staged.name,
                        callback = callback,
                    )
                } else {
                    vm.sendDirected(
                        recipientContact = recipientContact.trim(),
                        data = message.toByteArray(Charsets.UTF_8),
                        password = password,
                        retentionSecs = retSecs,
                        callback = callback,
                    )
                }
            },
            enabled = recipientContact.isNotBlank() && recipientFormatError == null &&
                (message.isNotBlank() || selectedFile != null) && password.isNotBlank() && !isSending && !isStagingFile,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (isSending) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(stringResource(R.string.send_securely))
        }

        // Result
        if (sendResult != null) {
            Spacer(Modifier.height(8.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.send_sent), style = MaterialTheme.typography.labelMedium)
                    Text(
                        stringResource(R.string.send_envelope, sendResult!!.take(16)),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    Text(
                        stringResource(R.string.send_confirm_hint),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        if (sendError != null) {
            Spacer(Modifier.height(8.dp))
            Text(sendError!!, color = MaterialTheme.colorScheme.error)
        }
    }
}

private const val MAX_DIRECTED_FILE_BYTES = 100L * 1024 * 1024

private data class StagedFile(
    val path: String,
    val name: String,
    val size: Long,
)

private fun stageSelectedFile(context: Context, uri: Uri, tooLargeText: String, openFailedText: String): StagedFile {
    val resolver = context.contentResolver
    var displayName: String? = null
    var declaredSize = -1L
    resolver.query(
        uri,
        arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
        null,
        null,
        null,
    )?.use { cursor ->
        if (cursor.moveToFirst()) {
            val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (nameColumn >= 0 && !cursor.isNull(nameColumn)) displayName = cursor.getString(nameColumn)
            if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) declaredSize = cursor.getLong(sizeColumn)
        }
    }
    if (declaredSize > MAX_DIRECTED_FILE_BYTES) {
        throw IOException(tooLargeText)
    }

    val safeName = (displayName ?: uri.lastPathSegment ?: "miasma-file")
        .substringAfterLast('/')
        .substringAfterLast('\\')
        .replace("\u0000", "")
        .take(255)
        .ifBlank { "miasma-file" }

    val stagingDir = File(context.cacheDir, "miasma-send").apply { mkdirs() }
    val staged = File(stagingDir, "${UUID.randomUUID()}.tmp")
    var total = 0L
    try {
        val input = resolver.openInputStream(uri) ?: throw IOException(openFailedText)
        input.buffered().use { source ->
            staged.outputStream().buffered().use { target ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_DIRECTED_FILE_BYTES) {
                        throw IOException(tooLargeText)
                    }
                    target.write(buffer, 0, read)
                }
            }
        }
        return StagedFile(staged.absolutePath, safeName, total)
    } catch (e: Exception) {
        staged.delete()
        throw e
    }
}

private fun formatSelectedFileSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KiB".format(bytes / 1024.0)
    else -> "%.1f MiB".format(bytes / 1024.0 / 1024.0)
}

private fun cleanupOldStagingFiles(cacheDir: File, directory: String) {
    val cutoff = System.currentTimeMillis() - 24L * 60 * 60 * 1000
    File(cacheDir, directory).listFiles()?.forEach { file ->
        if (file.isFile && file.lastModified() < cutoff) file.delete()
    }
}
