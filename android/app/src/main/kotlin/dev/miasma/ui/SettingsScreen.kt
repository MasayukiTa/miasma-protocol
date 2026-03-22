package dev.miasma.ui

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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.RestartAlt
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
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
import android.content.Intent
import dev.miasma.MiasmaService
import dev.miasma.Prefs
import dev.miasma.WebBridgeActivity
import kotlinx.coroutines.launch
import kotlin.math.roundToLong

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }

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
            .padding(20.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            "Configure your node",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(20.dp))

        // ── Storage quota ──
        SettingsSection(
            icon = Icons.Outlined.Storage,
            title = "Storage Quota",
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Local storage limit",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "${storageMb.roundToLong()} MiB",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(4.dp))
            Slider(
                value = storageMb,
                onValueChange = { storageMb = it },
                valueRange = 64f..10_240f,
                modifier = Modifier.fillMaxWidth(),
                colors = SliderDefaults.colors(
                    thumbColor = MaterialTheme.colorScheme.primary,
                    activeTrackColor = MaterialTheme.colorScheme.primary,
                ),
            )
            Text(
                "Range: 64 MiB – 10,240 MiB (10 GiB)",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
            )
        }

        Spacer(Modifier.height(12.dp))

        // ── Bandwidth quota ──
        SettingsSection(
            icon = Icons.Outlined.Speed,
            title = "Bandwidth",
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Daily transfer limit",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    "${bandwidthMbDay.roundToLong()} MiB/day",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(4.dp))
            Slider(
                value = bandwidthMbDay,
                onValueChange = { bandwidthMbDay = it },
                valueRange = 10f..1_000f,
                modifier = Modifier.fillMaxWidth(),
                colors = SliderDefaults.colors(
                    thumbColor = MaterialTheme.colorScheme.primary,
                    activeTrackColor = MaterialTheme.colorScheme.primary,
                ),
            )
        }

        Spacer(Modifier.height(12.dp))

        // ── Bootstrap peers ──
        SettingsSection(
            icon = Icons.Outlined.Hub,
            title = "Bootstrap Peers",
        ) {
            Text(
                "One multiaddr per line",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = bootstrapText,
                onValueChange = { bootstrapText = it },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
                maxLines = 8,
                placeholder = { Text("/ip4/1.2.3.4/udp/9000/quic-v1/p2p/12D3Koo...") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                shape = RoundedCornerShape(8.dp),
                textStyle = MaterialTheme.typography.bodySmall,
            )
        }

        Spacer(Modifier.height(24.dp))

        // ── Save & restart ──
        Button(
            onClick = {
                val sMb = storageMb.roundToLong()
                val bMb = bandwidthMbDay.roundToLong()
                val peers = bootstrapText.lines().filter { it.isNotBlank() }

                Prefs.setStorageMb(context, sMb)
                Prefs.setBandwidthMbDay(context, bMb)
                Prefs.setBootstrapPeers(context, peers)

                MiasmaService.stopNode(context)
                MiasmaService.startNode(context, context.filesDir.absolutePath, sMb, bMb)

                scope.launch {
                    snackbarHostState.showSnackbar("Settings saved — daemon restarted")
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
        ) {
            Icon(Icons.Outlined.RestartAlt, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text("Save & Restart")
        }

        Spacer(Modifier.height(8.dp))

        // ── Web View ──
        Button(
            onClick = {
                context.startActivity(Intent(context, WebBridgeActivity::class.java))
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
        ) {
            Icon(Icons.Outlined.Hub, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text("Open Web View")
        }

        Spacer(Modifier.height(8.dp))
        SnackbarHost(hostState = snackbarHostState)

        // ── About ──
        Spacer(Modifier.height(24.dp))
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
            ),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Outlined.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "About",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Miasma v0.3.1 Beta\n" +
                    "Plausibly-deniable distributed storage protocol\n" +
                    "AGPL-3.0 License",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                )
            }
        }
    }
}

@Composable
private fun SettingsSection(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(title, style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(12.dp))
            content()
        }
    }
}
