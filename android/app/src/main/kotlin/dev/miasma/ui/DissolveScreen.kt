package dev.miasma.ui

import android.graphics.Bitmap
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import dev.miasma.MiasmaViewModel

@Composable
fun DissolveScreen(vm: MiasmaViewModel) {
    val ui by vm.ui.collectAsState()
    val context = LocalContext.current
    var inputText by remember { mutableStateOf("") }
    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }

    // Generate QR code whenever lastMid changes.
    LaunchedEffect(ui.lastMid) {
        qrBitmap = ui.lastMid?.let { mid ->
            try {
                BarcodeEncoder().encodeBitmap(mid, BarcodeFormat.QR_CODE, 400, 400)
            } catch (_: Exception) { null }
        }
    }

    // File picker — reads bytes and dissolves them.
    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            val bytes = context.contentResolver.openInputStream(it)?.readBytes()
            if (bytes != null) vm.dissolve(bytes)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Dissolve", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        // Option A: type or paste raw text.
        OutlinedTextField(
            value = inputText,
            onValueChange = { inputText = it },
            label = { Text("Paste text to dissolve") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { if (inputText.isNotBlank()) vm.dissolve(inputText.encodeToByteArray()) },
            enabled = inputText.isNotBlank() && !ui.isLoading,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Dissolve text") }

        Spacer(Modifier.height(8.dp))

        // Option B: pick a file.
        Button(
            onClick = { filePicker.launch("*/*") },
            enabled = !ui.isLoading,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Pick file…") }

        if (ui.isLoading) {
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator()
        }

        ui.error?.let { err ->
            Spacer(Modifier.height(16.dp))
            Text(err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        // Show MID and QR code on success.
        ui.lastMid?.let { mid ->
            Spacer(Modifier.height(24.dp))
            Text("MID (share this):", style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                text = mid,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(horizontal = 8.dp),
            )
            qrBitmap?.let { bmp ->
                Spacer(Modifier.height(16.dp))
                Image(
                    bitmap = bmp.asImageBitmap(),
                    contentDescription = "QR code for MID",
                    modifier = Modifier.size(220.dp),
                )
            }
        }
    }
}
