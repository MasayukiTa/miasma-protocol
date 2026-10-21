package dev.miasma.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import dev.miasma.DirectedApi
import dev.miasma.MiasmaViewModel
import dev.miasma.R
import java.io.File
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun InboxScreen(vm: MiasmaViewModel) {
    val ui by vm.ui.collectAsState()
    val inboxItems by vm.inboxItems.collectAsState()
    val daemonPort by vm.daemonHttpPort.collectAsState()

    LaunchedEffect(daemonPort) {
        if (daemonPort > 0) vm.refreshInbox()
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.inbox_title), style = MaterialTheme.typography.headlineMedium)
            IconButton(onClick = { vm.refreshInbox() }) {
                Icon(Icons.Outlined.Refresh, contentDescription = stringResource(R.string.refresh))
            }
        }

        if (daemonPort == 0) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    stringResource(R.string.directed_daemon_unavailable),
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }

        if (inboxItems.isEmpty() && daemonPort > 0) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Text(stringResource(R.string.inbox_empty), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(inboxItems, key = { it.envelopeId }) { item ->
                    InboxCard(item, vm)
                }
            }
        }
    }
}

@Composable
private fun InboxCard(item: DirectedApi.EnvelopeItem, vm: MiasmaViewModel) {
    val context = LocalContext.current
    var password by remember { mutableStateOf("") }
    var retrieveError by remember { mutableStateOf<String?>(null) }
    var retrieveResult by remember { mutableStateOf<String?>(null) }
    var isRetrieving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    val retrieveFailedText = stringResource(R.string.retrieve_failed)
    val saveFailedText = stringResource(R.string.save_retrieved_failed)
    val destinationOpenFailedText = stringResource(R.string.destination_open_failed)
    val retrievedFileDefault = stringResource(R.string.retrieved_file_default)

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) { cleanupOldRetrieveFiles(context.cacheDir) }
    }

    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val dir = File(context.cacheDir, "miasma-retrieve").apply { mkdirs() }
        val temp = File(dir, "${UUID.randomUUID()}.tmp")
        isRetrieving = true
        retrieveError = null
        retrieveResult = null
        vm.retrieveDirectedToFile(item.envelopeId, password, temp.absolutePath) { result, error ->
            if (error != null || result == null) {
                temp.delete()
                isRetrieving = false
                retrieveError = error ?: retrieveFailedText
            } else {
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) { copyRetrievedFile(context, temp, uri, destinationOpenFailedText) }
                        retrieveResult = context.getString(R.string.saved_size, formatBytes(result.bytesWritten))
                    } catch (e: Exception) {
                        retrieveError = e.message ?: saveFailedText
                    } finally {
                        temp.delete()
                        isRetrieving = false
                    }
                }
            }
        }
    }

    val (badgeColor, badgeLabelRes) = inboxStateBadge(item.state)
    val badgeLabel = stringResource(badgeLabelRes)

    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(2.dp),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            // Header: state badge + envelope ID
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    badgeLabel,
                    color = Color.White,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier
                        .background(badgeColor, RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    item.envelopeId.take(16) + "…",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(6.dp))

            // Sender
            // The PeerId seen on the connection is verified; the key inside the
            // envelope is only a claim by the sender.
            val peerId = item.senderPeerId
            Text(
                when {
                    !peerId.isNullOrBlank() ->
                        stringResource(R.string.inbox_from_verified, peerId.take(20))
                    item.senderPubkey.isNotBlank() ->
                        stringResource(R.string.inbox_from_unverified, item.senderPubkey.take(20))
                    else -> stringResource(R.string.inbox_from_unknown)
                },
                style = MaterialTheme.typography.bodySmall,
            )

            // Filename & size
            if (!item.filename.isNullOrEmpty()) {
                Text(stringResource(R.string.file_label, item.filename!!), style = MaterialTheme.typography.bodySmall)
            }
            if (item.fileSize > 0) {
                Text(stringResource(R.string.size_label, formatBytes(item.fileSize)), style = MaterialTheme.typography.bodySmall)
            }

            // Challenge code (for recipient to share with sender)
            if (!item.challengeCode.isNullOrEmpty() && item.state == "ChallengeIssued") {
                Spacer(Modifier.height(6.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                    ),
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        Text(
                            stringResource(R.string.challenge_share_sender),
                            style = MaterialTheme.typography.labelSmall,
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                item.challengeCode,
                                style = MaterialTheme.typography.titleMedium,
                                fontFamily = FontFamily.Monospace,
                            )
                            Spacer(Modifier.width(4.dp))
                            IconButton(
                                onClick = {
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    cm.setPrimaryClip(ClipData.newPlainText("challenge", item.challengeCode))
                                },
                                modifier = Modifier.size(28.dp),
                            ) {
                                Text("\uD83D\uDCCB", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }

            // Password-gated retrieval for Confirmed state
            if (item.state == "Confirmed") {
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.password)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(4.dp))
                Button(
                    onClick = {
                        retrieveError = null
                        retrieveResult = null
                        saveLauncher.launch(item.filename?.takeIf { it.isNotBlank() } ?: retrievedFileDefault)
                    },
                    enabled = password.isNotEmpty() && !isRetrieving,
                ) {
                    if (isRetrieving) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(stringResource(R.string.retrieve))
                }
                if (retrieveError != null) {
                    Text(retrieveError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                if (retrieveResult != null) {
                    Text(retrieveResult!!, color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
                }
            }

            // Terminal state messages
            when (item.state) {
                "Retrieved" -> Text(stringResource(R.string.content_retrieved), color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
                "Expired" -> Text(stringResource(R.string.expired), color = Color(0xFFFF9800), style = MaterialTheme.typography.bodySmall)
                "SenderRevoked" -> Text(stringResource(R.string.revoked_by_sender), color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
                "ChallengeFailed" -> Text(stringResource(R.string.challenge_failed), color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
                "PasswordFailed" -> Text(stringResource(R.string.password_exhausted), color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
            }

            // Delete button (non-terminal only)
            if (!isTerminal(item.state)) {
                Spacer(Modifier.height(6.dp))
                OutlinedButton(
                    onClick = { vm.deleteDirectedEnvelope(item.envelopeId, isInbox = true) },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) {
                    Text(stringResource(R.string.delete))
                }
            }
        }
    }
}

private fun inboxStateBadge(state: String): Pair<Color, Int> = when (state) {
    "Pending" -> Color(0xFFFF9800) to R.string.status_pending
    "ChallengeIssued" -> Color(0xFFFF9800) to R.string.status_challenge
    "Confirmed" -> Color(0xFF4CAF50) to R.string.status_confirmed
    "Retrieved" -> Color(0xFF4CAF50) to R.string.status_retrieved
    "Expired" -> Color(0xFF9E9E9E) to R.string.status_expired
    "SenderRevoked" -> Color(0xFFF44336) to R.string.status_revoked
    "RecipientDeleted" -> Color(0xFF9E9E9E) to R.string.status_deleted
    "ChallengeFailed" -> Color(0xFFF44336) to R.string.status_failed
    "PasswordFailed" -> Color(0xFFF44336) to R.string.status_failed
    else -> Color(0xFF9E9E9E) to R.string.status_failed
}

private fun isTerminal(state: String): Boolean = state in setOf(
    "Retrieved", "Expired", "SenderRevoked", "RecipientDeleted", "ChallengeFailed", "PasswordFailed"
)

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KiB"
    else -> "${"%.1f".format(bytes / 1024.0 / 1024.0)} MiB"
}

private fun copyRetrievedFile(context: Context, source: File, destination: android.net.Uri, openFailedText: String) {
    val output = context.contentResolver.openOutputStream(destination, "w")
        ?: throw IOException(openFailedText)
    source.inputStream().buffered().use { input ->
        output.buffered().use { out ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                out.write(buffer, 0, read)
            }
        }
    }
}

private fun cleanupOldRetrieveFiles(cacheDir: File) {
    val cutoff = System.currentTimeMillis() - 24L * 60 * 60 * 1000
    File(cacheDir, "miasma-retrieve").listFiles()?.forEach { file ->
        if (file.isFile && file.lastModified() < cutoff) file.delete()
    }
}
