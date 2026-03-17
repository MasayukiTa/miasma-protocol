package dev.miasma.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.miasma.MiasmaViewModel

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(vm: MiasmaViewModel) {
    val ui by vm.ui.collectAsState()
    var showEmergencyDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        // 3-second long-press on the title triggers the emergency wipe gesture.
        Text(
            text = "Miasma",
            style = MaterialTheme.typography.displayMedium,
            modifier = Modifier.combinedClickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = {},
                onLongClick = { showEmergencyDialog = true },
            ),
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = "Plausibly-deniable distributed storage",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = "Long-press title for emergency wipe",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
        )

        if (ui.nodeStatus != null) {
            Spacer(Modifier.height(32.dp))
            val s = ui.nodeStatus!!
            Text(
                text = "${s.shareCount} shares · ${"%.1f".format(s.usedMb)} / ${s.quotaMb} MiB used",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }

        ui.error?.let { err ->
            Spacer(Modifier.height(16.dp))
            Text(
                text = err,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center,
            )
        }
    }

    // Emergency wipe confirmation dialog (same flow as StatusScreen but faster).
    if (showEmergencyDialog) {
        AlertDialog(
            onDismissRequest = { showEmergencyDialog = false },
            title = { Text("Emergency Wipe") },
            text = {
                Text(
                    "Destroy the master key NOW?\n\n" +
                    "All locally stored shares become permanently unreadable. " +
                    "This CANNOT be undone."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showEmergencyDialog = false
                        vm.distressWipe()
                    },
                ) { Text("WIPE NOW", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showEmergencyDialog = false }) { Text("Cancel") }
            },
        )
    }
}
