package dev.miasma.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.miasma.R

/**
 * Easy-mode task hub. The detailed Send/Inbox/Outbox/Save/Get Back routes remain independent
 * internally; the bottom navigation exposes one Files destination instead of protocol state.
 */
@Composable
fun FilesScreen(
    onSend: () -> Unit,
    onInbox: () -> Unit,
    onOutbox: () -> Unit,
    onSave: () -> Unit,
    onRetrieve: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(stringResource(R.string.files_title), style = MaterialTheme.typography.headlineMedium)
        Text(
            stringResource(R.string.files_description),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Button(onClick = onSend, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_send_file))
        }
        OutlinedButton(onClick = onInbox, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.files_inbox))
        }
        OutlinedButton(onClick = onOutbox, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.files_outbox))
        }
        OutlinedButton(onClick = onSave, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_save_securely))
        }
        OutlinedButton(onClick = onRetrieve, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.files_get_back))
        }
    }
}
