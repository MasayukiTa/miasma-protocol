package dev.miasma.ui

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.miasma.MiasmaViewModel

@Composable
fun RetrieveScreen(vm: MiasmaViewModel) {
    val ui by vm.ui.collectAsState()
    val context = LocalContext.current
    var midInput by remember { mutableStateOf("") }

    // QR scanner launcher — fills midInput with scanned MID.
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { midInput = it }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Retrieve", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = midInput,
            onValueChange = { midInput = it },
            label = { Text("MID  (e.g. miasma:<base58>)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(Modifier.height(8.dp))

        // Scan QR code to populate the MID field.
        Button(
            onClick = {
                scanLauncher.launch(
                    ScanOptions().apply {
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setPrompt("Scan Miasma MID QR code")
                        setBeepEnabled(false)
                    }
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Scan QR code") }

        Spacer(Modifier.height(8.dp))

        Button(
            onClick = { vm.retrieve(midInput.trim()) },
            enabled = midInput.isNotBlank() && !ui.isLoading,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Retrieve") }

        if (ui.isLoading) {
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator()
        }

        ui.error?.let { err ->
            Spacer(Modifier.height(16.dp))
            Text(err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        ui.retrievedBytes?.let { bytes ->
            Spacer(Modifier.height(24.dp))
            Text("Retrieved ${bytes.size} bytes", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))

            // Share via Android share sheet.
            val shareText = try { bytes.toString(Charsets.UTF_8) } catch (_: Exception) { null }
            if (shareText != null) {
                Button(
                    onClick = {
                        val sendIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, shareText)
                        }
                        context.startActivity(Intent.createChooser(sendIntent, "Share content"))
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Share as text") }
            }
        }
    }
}
