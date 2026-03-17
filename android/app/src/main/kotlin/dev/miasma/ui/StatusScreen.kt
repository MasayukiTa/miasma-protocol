package dev.miasma.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.miasma.MiasmaViewModel

@Composable
fun StatusScreen(vm: MiasmaViewModel) {
    val ui by vm.ui.collectAsState()
    var showWipeDialog by remember { mutableStateOf(false) }

    // Refresh on first composition.
    LaunchedEffect(Unit) { vm.refreshStatus() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Node Status", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        if (ui.nodeStatus == null) {
            Text(
                "Node not initialised — tap Dissolve to start.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            val s = ui.nodeStatus!!
            StatusCard {
                StatusRow("Shares stored", s.shareCount.toString())
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                StatusRow("Storage used", "${"%.1f".format(s.usedMb)} MiB")
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                StatusRow("Storage quota", "${s.quotaMb} MiB")
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                StatusRow("Listen addr", s.listenAddr)
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                StatusRow("Bootstrap peers", s.bootstrapCount.toString())
            }
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = { vm.refreshStatus() },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Refresh") }

        Spacer(Modifier.height(32.dp))

        // Distress wipe — destructive action.
        Button(
            onClick = { showWipeDialog = true },
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Emergency Wipe") }

        ui.error?.let { err ->
            Spacer(Modifier.height(16.dp))
            Text(err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
    }

    if (showWipeDialog) {
        AlertDialog(
            onDismissRequest = { showWipeDialog = false },
            title = { Text("Emergency Wipe") },
            text = {
                Text(
                    "This will zero and delete the master key. All stored shares become permanently " +
                    "unreadable. The app directory is kept so the app appears normally installed.\n\n" +
                    "This action CANNOT be undone."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showWipeDialog = false
                        vm.distressWipe()
                    },
                ) { Text("WIPE NOW", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showWipeDialog = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun StatusCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(2.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) { content() }
    }
}

@Composable
private fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
