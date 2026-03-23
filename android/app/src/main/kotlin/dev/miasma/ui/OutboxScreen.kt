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
fun OutboxScreen(vm: MiasmaViewModel) {
    val outboxItems by vm.outboxItems.collectAsState()
    val daemonPort by vm.daemonHttpPort.collectAsState()

    LaunchedEffect(daemonPort) {
        if (daemonPort > 0) vm.refreshOutbox()
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Outbox", style = MaterialTheme.typography.headlineMedium)
            IconButton(onClick = { vm.refreshOutbox() }) {
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

        if (outboxItems.isEmpty() && daemonPort > 0) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Text("No outgoing shares", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(outboxItems, key = { it.envelopeId }) { item ->
                    OutboxCard(item, vm)
                }
            }
        }
    }
}

@Composable
private fun OutboxCard(item: DirectedApi.EnvelopeItem, vm: MiasmaViewModel) {
    var challengeInput by remember { mutableStateOf("") }
    var confirmError by remember { mutableStateOf<String?>(null) }
    var confirmSuccess by remember { mutableStateOf(false) }
    var showRevokeDialog by remember { mutableStateOf(false) }

    val (badgeColor, badgeLabel) = outboxStateBadge(item.state)

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

            // Recipient
            Text(
                "To: ${item.recipientPubkey.take(20)}…",
                style = MaterialTheme.typography.bodySmall,
            )

            // Filename
            if (!item.filename.isNullOrEmpty()) {
                Text("File: ${item.filename}", style = MaterialTheme.typography.bodySmall)
            }

            // Challenge confirmation (sender confirms with code from recipient)
            if (item.state == "ChallengeIssued") {
                Spacer(Modifier.height(6.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    ),
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        Text(
                            "Enter the challenge code from recipient:",
                            style = MaterialTheme.typography.labelSmall,
                        )
                        Spacer(Modifier.height(4.dp))
                        OutlinedTextField(
                            value = challengeInput,
                            onValueChange = { challengeInput = it.uppercase().take(9) },
                            label = { Text("XXXX-XXXX") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
                        )
                        Spacer(Modifier.height(4.dp))
                        Button(
                            onClick = {
                                confirmError = null
                                confirmSuccess = false
                                vm.confirmDirected(item.envelopeId, challengeInput) { error ->
                                    confirmError = error
                                    if (error == null) confirmSuccess = true
                                }
                            },
                            enabled = challengeInput.length >= 9,
                        ) {
                            Text("Confirm")
                        }
                        if (confirmSuccess) {
                            Text(
                                "Confirmed",
                                color = Color(0xFF4CAF50),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        if (confirmError != null) {
                            Text(
                                confirmError!!,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }

            // Terminal state messages
            when (item.state) {
                "Confirmed" -> Text("✓ Confirmed — waiting for retrieval", color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
                "Retrieved" -> Text("✓ Content retrieved by recipient", color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
                "Expired" -> Text("Expired", color = Color(0xFFFF9800), style = MaterialTheme.typography.bodySmall)
                "SenderRevoked" -> Text("You revoked this share", color = Color(0xFF9E9E9E), style = MaterialTheme.typography.bodySmall)
                "RecipientDeleted" -> Text("Deleted by recipient", color = Color(0xFF9E9E9E), style = MaterialTheme.typography.bodySmall)
                "ChallengeFailed" -> Text("Challenge failed", color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
                "PasswordFailed" -> Text("Password attempts exhausted", color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
            }

            // Actions for non-terminal
            if (item.state !in setOf("Retrieved", "Expired", "SenderRevoked", "RecipientDeleted", "ChallengeFailed", "PasswordFailed")) {
                Spacer(Modifier.height(6.dp))
                OutlinedButton(
                    onClick = { showRevokeDialog = true },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) {
                    Text("Revoke")
                }
            }

            if (showRevokeDialog) {
                AlertDialog(
                    onDismissRequest = { showRevokeDialog = false },
                    title = { Text("Revoke share?") },
                    text = { Text("Are you sure? This cannot be undone.") },
                    confirmButton = {
                        TextButton(onClick = {
                            showRevokeDialog = false
                            vm.revokeDirected(item.envelopeId)
                        }) {
                            Text("Revoke", color = MaterialTheme.colorScheme.error)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showRevokeDialog = false }) {
                            Text("Cancel")
                        }
                    },
                )
            }
        }
    }
}

private fun outboxStateBadge(state: String): Pair<Color, String> = when (state) {
    "Pending" -> Color(0xFFFF9800) to "Waiting"
    "ChallengeIssued" -> Color(0xFFFF9800) to "Confirm"
    "Confirmed" -> Color(0xFF4CAF50) to "Confirmed"
    "Retrieved" -> Color(0xFF4CAF50) to "Retrieved"
    "Expired" -> Color(0xFF9E9E9E) to "Expired"
    "SenderRevoked" -> Color(0xFFF44336) to "Revoked"
    "RecipientDeleted" -> Color(0xFF9E9E9E) to "Deleted"
    "ChallengeFailed" -> Color(0xFFF44336) to "Failed"
    "PasswordFailed" -> Color(0xFFF44336) to "Failed"
    else -> Color(0xFF9E9E9E) to state
}
