package dev.miasma.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.miasma.DirectedApi
import dev.miasma.MiasmaViewModel

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
            Text("Inbox", style = MaterialTheme.typography.headlineMedium)
            IconButton(onClick = { vm.refreshInbox() }) {
                Text("↻", style = MaterialTheme.typography.titleLarge)
            }
        }

        if (daemonPort == 0) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    "Daemon not running — directed sharing unavailable",
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
                Text("No incoming shares", color = MaterialTheme.colorScheme.onSurfaceVariant)
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
    var password by remember { mutableStateOf("") }
    var retrieveError by remember { mutableStateOf<String?>(null) }
    var isRetrieving by remember { mutableStateOf(false) }

    val (badgeColor, badgeLabel) = inboxStateBadge(item.state)

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
            Text(
                "From: ${item.senderPubkey.take(20)}…",
                style = MaterialTheme.typography.bodySmall,
            )

            // Filename & size
            if (!item.filename.isNullOrEmpty()) {
                Text("File: ${item.filename}", style = MaterialTheme.typography.bodySmall)
            }
            if (item.fileSize > 0) {
                Text("Size: ${formatBytes(item.fileSize)}", style = MaterialTheme.typography.bodySmall)
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
                            "Challenge code (share with sender):",
                            style = MaterialTheme.typography.labelSmall,
                        )
                        Text(
                            item.challengeCode,
                            style = MaterialTheme.typography.titleMedium,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }

            // Password-gated retrieval for Confirmed state
            if (item.state == "Confirmed") {
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(4.dp))
                Button(
                    onClick = {
                        isRetrieving = true
                        retrieveError = null
                        vm.retrieveDirected(item.envelopeId, password) { error ->
                            isRetrieving = false
                            retrieveError = error
                        }
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
                    Text("Retrieve")
                }
                if (retrieveError != null) {
                    Text(retrieveError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }

            // Terminal state messages
            when (item.state) {
                "Retrieved" -> Text("✓ Content retrieved", color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
                "Expired" -> Text("Expired", color = Color(0xFFFF9800), style = MaterialTheme.typography.bodySmall)
                "SenderRevoked" -> Text("Revoked by sender", color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
                "ChallengeFailed" -> Text("Challenge failed", color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
                "PasswordFailed" -> Text("Password attempts exhausted", color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
            }

            // Delete button (non-terminal only)
            if (!isTerminal(item.state)) {
                Spacer(Modifier.height(6.dp))
                OutlinedButton(
                    onClick = { vm.deleteDirectedEnvelope(item.envelopeId, isInbox = true) },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) {
                    Text("Delete")
                }
            }
        }
    }
}

private fun inboxStateBadge(state: String): Pair<Color, String> = when (state) {
    "Pending" -> Color(0xFFFF9800) to "Pending"
    "ChallengeIssued" -> Color(0xFFFF9800) to "Challenge"
    "Confirmed" -> Color(0xFF4CAF50) to "Confirmed"
    "Retrieved" -> Color(0xFF4CAF50) to "Retrieved"
    "Expired" -> Color(0xFF9E9E9E) to "Expired"
    "SenderRevoked" -> Color(0xFFF44336) to "Revoked"
    "RecipientDeleted" -> Color(0xFF9E9E9E) to "Deleted"
    "ChallengeFailed" -> Color(0xFFF44336) to "Failed"
    "PasswordFailed" -> Color(0xFFF44336) to "Failed"
    else -> Color(0xFF9E9E9E) to state
}

private fun isTerminal(state: String): Boolean = state in setOf(
    "Retrieved", "Expired", "SenderRevoked", "RecipientDeleted", "ChallengeFailed", "PasswordFailed"
)

private fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KiB"
    else -> "${"%.1f".format(bytes / 1024.0 / 1024.0)} MiB"
}
