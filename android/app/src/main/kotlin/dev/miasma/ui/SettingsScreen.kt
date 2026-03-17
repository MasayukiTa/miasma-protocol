package dev.miasma.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.miasma.MiasmaService
import dev.miasma.Prefs
import kotlinx.coroutines.launch
import kotlin.math.roundToLong

/**
 * Settings screen — lets the user configure:
 *  • Storage quota (MiB) via slider (64 MiB – 10 240 MiB)
 *  • Daily bandwidth quota (MiB/day) via slider (10 MiB – 1 000 MiB)
 *  • Bootstrap peer multiaddrs (one per line)
 *
 * Changes are persisted to SharedPreferences and the Miasma daemon is
 * restarted with the new values.
 */
@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

    // Initialise from persisted prefs.
    var storageMb by remember {
        mutableFloatStateOf(Prefs.storageMb(context).toFloat())
    }
    var bandwidthMbDay by remember {
        mutableFloatStateOf(Prefs.bandwidthMbDay(context).toFloat())
    }
    var bootstrapText by remember {
        mutableStateOf(Prefs.bootstrapPeers(context).joinToString("\n"))
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(24.dp))

        // ── Storage quota ─────────────────────────────────────────────────
        LabelRow("Storage quota", "${storageMb.roundToLong()} MiB")
        Slider(
            value = storageMb,
            onValueChange = { storageMb = it },
            valueRange = 64f..10_240f,
            steps = 0,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        // ── Bandwidth quota ───────────────────────────────────────────────
        LabelRow("Daily bandwidth", "${bandwidthMbDay.roundToLong()} MiB/day")
        Slider(
            value = bandwidthMbDay,
            onValueChange = { bandwidthMbDay = it },
            valueRange = 10f..1_000f,
            steps = 0,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))

        // ── Bootstrap peers ───────────────────────────────────────────────
        Text("Bootstrap peers (one multiaddr per line)",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = bootstrapText,
            onValueChange = { bootstrapText = it },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 8,
            placeholder = { Text("/ip4/1.2.3.4/udp/9000/quic-v1/p2p/12D3Koo…") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        )

        Spacer(Modifier.height(24.dp))

        // ── Save + restart ────────────────────────────────────────────────
        Button(
            onClick = {
                val sMb = storageMb.roundToLong()
                val bMb = bandwidthMbDay.roundToLong()
                val peers = bootstrapText.lines().filter { it.isNotBlank() }

                Prefs.setStorageMb(context, sMb)
                Prefs.setBandwidthMbDay(context, bMb)
                Prefs.setBootstrapPeers(context, peers)

                // Restart daemon with new settings.
                MiasmaService.stopNode(context)
                MiasmaService.startNode(context,
                    context.filesDir.absolutePath, sMb, bMb)

                scope.launch {
                    snackbarHostState.showSnackbar("Settings saved — daemon restarted")
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Save & restart daemon") }

        Spacer(Modifier.height(8.dp))
        SnackbarHost(hostState = snackbarHostState)
    }
}

@Composable
private fun LabelRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
