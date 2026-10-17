package dev.miasma.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.io.IOException
import java.util.UUID

internal const val MAX_UI_STAGED_FILE_BYTES = 100L * 1024 * 1024

internal data class StagedContentFile(
    val path: String,
    val name: String,
    val size: Long,
)

/**
 * Copy a Storage Access Framework URI into app-private cache using a bounded buffer.
 *
 * The daemon needs a normal filesystem path. Keeping the SAF -> daemon boundary in a
 * temporary private file avoids putting the whole payload in a Kotlin ByteArray or JSON.
 */
internal fun stageContentUri(
    context: Context,
    uri: Uri,
    directory: String,
    maxBytes: Long = MAX_UI_STAGED_FILE_BYTES,
    tooLargeText: String,
    openFailedText: String,
): StagedContentFile {
    val resolver = context.contentResolver
    var displayName: String? = null
    var declaredSize = -1L
    resolver.query(
        uri,
        arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
        null,
        null,
        null,
    )?.use { cursor ->
        if (cursor.moveToFirst()) {
            val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (nameColumn >= 0 && !cursor.isNull(nameColumn)) displayName = cursor.getString(nameColumn)
            if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) declaredSize = cursor.getLong(sizeColumn)
        }
    }
    if (declaredSize > maxBytes) throw IOException(tooLargeText)

    val safeName = (displayName ?: uri.lastPathSegment ?: "miasma-file")
        .substringAfterLast('/')
        .substringAfterLast('\\')
        .replace("\u0000", "")
        .take(255)
        .ifBlank { "miasma-file" }

    val stagingDir = File(context.cacheDir, directory).apply { mkdirs() }
    val staged = File(stagingDir, "${UUID.randomUUID()}.tmp")
    var total = 0L
    try {
        val input = resolver.openInputStream(uri) ?: throw IOException(openFailedText)
        input.buffered().use { source ->
            staged.outputStream().buffered().use { target ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = source.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > maxBytes) throw IOException(tooLargeText)
                    target.write(buffer, 0, read)
                }
            }
        }
        return StagedContentFile(staged.absolutePath, safeName, total)
    } catch (e: Exception) {
        staged.delete()
        throw e
    }
}

internal fun newPrivateTempFile(context: Context, directory: String): File {
    val dir = File(context.cacheDir, directory).apply { mkdirs() }
    return File(dir, "${UUID.randomUUID()}.tmp")
}

internal fun copyFileToUri(
    context: Context,
    source: File,
    destination: Uri,
    openFailedText: String,
) {
    val output = context.contentResolver.openOutputStream(destination, "w")
        ?: throw IOException(openFailedText)
    source.inputStream().buffered().use { input ->
        output.buffered().use { out ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                out.write(buffer, 0, read)
            }
        }
    }
}

internal fun cleanupOldStagingFiles(cacheDir: File, directory: String) {
    val cutoff = System.currentTimeMillis() - 24L * 60 * 60 * 1000
    File(cacheDir, directory).listFiles()?.forEach { file ->
        if (file.isFile && file.lastModified() < cutoff) file.delete()
    }
}

internal fun formatStagedFileSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KiB".format(bytes / 1024.0)
    else -> "%.1f MiB".format(bytes / 1024.0 / 1024.0)
}
