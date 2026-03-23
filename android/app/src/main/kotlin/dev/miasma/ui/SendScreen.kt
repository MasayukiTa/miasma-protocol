package dev.miasma.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.miasma.MiasmaViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SendScreen(vm: MiasmaViewModel) {
    val daemonPort by vm.daemonHttpPort.collectAsState()
    val sharingContact by vm.sharingContact.collectAsState()

    var recipientContact by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var retentionHours by remember { mutableStateOf("24") }
    var isSending by remember { mutableStateOf(false) }
    var sendResult by remember { mutableStateOf<String?>(null) }
    var sendError by remember { mutableStateOf<String?>(null) }
    var recipientFormatError by remember { mutableStateOf<String?>(null) }
    var retentionFallbackUsed by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        Text("Send", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))

        if (daemonPort == 0) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    "Daemon not running — sending unavailable",
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
                    Text("Your sharing contact:", style = MaterialTheme.typography.labelSmall)
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
                    "Must start with \"msk:\" and contain \"@\" separator"
                } else null
            },
            label = { Text("Recipient contact (msk:…@PeerId)") },
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
            label = { Text("Message / content") },
            modifier = Modifier.fillMaxWidth().height(120.dp),
            maxLines = 6,
        )
        Spacer(Modifier.height(8.dp))

        // Password
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password (shared with recipient)") },
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
            label = { Text("Retention (hours)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(0.5f),
        )
        if (retentionFallbackUsed) {
            Text(
                "Invalid hours — defaulting to 24",
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
                vm.sendDirected(
                    recipientContact = recipientContact.trim(),
                    data = message.toByteArray(Charsets.UTF_8),
                    password = password,
                    retentionSecs = retSecs,
                ) { envelopeId, error ->
                    isSending = false
                    sendResult = envelopeId
                    sendError = error
                }
            },
            enabled = recipientContact.isNotBlank() && recipientFormatError == null && message.isNotBlank() && password.isNotBlank() && !isSending,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (isSending) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text("Send Directed Share")
        }

        // Result
        if (sendResult != null) {
            Spacer(Modifier.height(8.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Sent!", style = MaterialTheme.typography.labelMedium)
                    Text(
                        "Envelope: ${sendResult!!.take(16)}…",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    Text(
                        "Check Outbox to confirm when the recipient provides their challenge code.",
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
