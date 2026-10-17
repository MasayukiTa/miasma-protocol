package dev.miasma

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * HTTP bridge client for directed sharing operations.
 *
 * Connects to the local daemon's HTTP bridge on 127.0.0.1 to perform
 * directed sharing operations that require network access (send, confirm,
 * retrieve, revoke, inbox, outbox).
 */
object DirectedApi {

    private const val FILE_OPERATION_TIMEOUT_MS = 30 * 60 * 1000

    private fun bridgeUrl(port: Int, path: String): URL =
        URL("http://127.0.0.1:$port$path")

    private fun authenticatedConnection(dataDir: String, port: Int, path: String): HttpURLConnection {
        val token = try {
            File(dataDir, "daemon.token").readText(Charsets.UTF_8).trim()
        } catch (_: Exception) {
            throw IOException("Daemon authorization unavailable")
        }
        if (token.length != 64 || token.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) {
            throw IOException("Daemon authorization unavailable")
        }
        return (bridgeUrl(port, path).openConnection() as HttpURLConnection).apply {
            setRequestProperty("Authorization", "Bearer $token")
        }
    }

    // ─── GET helpers ────────────────────────────────────────────────────

    private fun httpGet(dataDir: String, port: Int, path: String): JSONObject {
        val conn = authenticatedConnection(dataDir, port, path)
        conn.requestMethod = "GET"
        conn.connectTimeout = 5_000
        conn.readTimeout = 30_000
        try {
            val code = conn.responseCode
            val body = if (code in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: """{"error":"HTTP $code"}"""
            }
            return try {
                JSONObject(body)
            } catch (_: org.json.JSONException) {
                JSONObject().apply { put("error", "Malformed response") }
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun httpGetArray(dataDir: String, port: Int, path: String): JSONArray {
        val conn = authenticatedConnection(dataDir, port, path)
        conn.requestMethod = "GET"
        conn.connectTimeout = 5_000
        conn.readTimeout = 30_000
        try {
            val code = conn.responseCode
            val body = if (code in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                "[]"
            }
            return try {
                JSONArray(body)
            } catch (_: org.json.JSONException) {
                JSONArray()
            }
        } finally {
            conn.disconnect()
        }
    }

    // ─── POST helper ────────────────────────────────────────────────────

    private fun httpPost(
        dataDir: String,
        port: Int,
        path: String,
        body: JSONObject,
        readTimeoutMs: Int = 60_000,
    ): JSONObject {
        val conn = authenticatedConnection(dataDir, port, path)
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = 5_000
        conn.readTimeout = readTimeoutMs
        try {
            OutputStreamWriter(conn.outputStream).use { it.write(body.toString()) }
            val code = conn.responseCode
            val respBody = if (code in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: """{"error":"HTTP $code"}"""
            }
            return try {
                JSONObject(respBody)
            } catch (_: org.json.JSONException) {
                JSONObject().apply { put("error", "Malformed response") }
            }
        } finally {
            conn.disconnect()
        }
    }

    // ─── Directed sharing operations ────────────────────────────────────

    // Network content operations. File variants keep payload bytes out of JSON/base64.
    fun publishBytes(dataDir: String, port: Int, data: ByteArray, k: Int = 10, n: Int = 20): String {
        val body = JSONObject().apply {
            put("data", Base64.encodeToString(data, Base64.NO_WRAP))
            put("data_shards", k)
            put("total_shards", n)
        }
        val resp = httpPost(dataDir, port, "/api/publish", body, FILE_OPERATION_TIMEOUT_MS)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return resp.getString("mid")
    }

    fun publishFile(dataDir: String, port: Int, filePath: String, k: Int = 10, n: Int = 20): String {
        val body = JSONObject().apply {
            put("file_path", filePath)
            put("data_shards", k)
            put("total_shards", n)
        }
        val resp = httpPost(dataDir, port, "/api/publish-file", body, FILE_OPERATION_TIMEOUT_MS)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return resp.getString("mid")
    }

    fun retrieveMidToFile(
        dataDir: String,
        port: Int,
        mid: String,
        outputPath: String,
        k: Int = 10,
        n: Int = 20,
    ): RetrieveMidToFileResult {
        val body = JSONObject().apply {
            put("mid", mid)
            put("output_path", outputPath)
            put("data_shards", k)
            put("total_shards", n)
        }
        val resp = httpPost(dataDir, port, "/api/retrieve-to-file", body, FILE_OPERATION_TIMEOUT_MS)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return RetrieveMidToFileResult(
            outputPath = resp.getString("output_path"),
            bytesWritten = resp.optLong("bytes_written", 0),
        )
    }

    data class RetrieveMidToFileResult(val outputPath: String, val bytesWritten: Long)

    /** Get sharing key and contact. */
    fun sharingKey(dataDir: String, port: Int): SharingKeyResult {
        val resp = httpGet(dataDir, port, "/api/sharing-key")
        return SharingKeyResult(
            key = resp.optString("key", ""),
            contact = resp.optString("contact", ""),
        )
    }

    /** List incoming directed envelopes. */
    fun inbox(dataDir: String, port: Int): List<EnvelopeItem> {
        val arr = httpGetArray(dataDir, port, "/api/directed/inbox")
        return parseEnvelopes(arr)
    }

    /** List outgoing directed envelopes. */
    fun outbox(dataDir: String, port: Int): List<EnvelopeItem> {
        val arr = httpGetArray(dataDir, port, "/api/directed/outbox")
        return parseEnvelopes(arr)
    }

    /** Send a directed share. */
    fun send(
        dataDir: String,
        port: Int,
        recipientContact: String,
        data: ByteArray,
        password: String,
        retentionSecs: Long,
        filename: String? = null,
    ): String {
        val b64 = android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP)
        val body = JSONObject().apply {
            put("recipient_contact", recipientContact)
            put("data", b64)
            put("password", password)
            put("retention_secs", retentionSecs)
            if (filename != null) put("filename", filename)
        }
        val resp = httpPost(dataDir, port, "/api/directed/send", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return resp.getString("envelope_id")
    }

    /** Send a directed share from a daemon-readable local file. */
    fun sendFile(
        dataDir: String,
        port: Int,
        recipientContact: String,
        filePath: String,
        password: String,
        retentionSecs: Long,
        filename: String? = null,
    ): String {
        val body = JSONObject().apply {
            put("recipient_contact", recipientContact)
            put("file_path", filePath)
            put("password", password)
            put("retention_secs", retentionSecs)
            if (filename != null) put("filename", filename)
        }
        val resp = httpPost(dataDir, port, "/api/directed/send-file", body, FILE_OPERATION_TIMEOUT_MS)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return resp.getString("envelope_id")
    }

    /** Confirm a challenge code (sender confirms recipient). */
    fun confirm(dataDir: String, port: Int, envelopeId: String, challengeCode: String) {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
            put("challenge_code", challengeCode)
        }
        val resp = httpPost(dataDir, port, "/api/directed/confirm", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
    }

    /** Retrieve directed content with password. */
    fun retrieve(dataDir: String, port: Int, envelopeId: String, password: String): RetrieveResult {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
            put("password", password)
        }
        val resp = httpPost(dataDir, port, "/api/directed/retrieve", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        val dataB64 = resp.getString("data")
        val data = android.util.Base64.decode(dataB64, android.util.Base64.DEFAULT)
        return RetrieveResult(
            data = data,
            filename = resp.optString("filename", null),
        )
    }

    /** Retrieve directed content directly into a daemon-readable file path. */
    fun retrieveToFile(
        dataDir: String,
        port: Int,
        envelopeId: String,
        password: String,
        outputPath: String,
    ): RetrieveToFileResult {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
            put("password", password)
            put("output_path", outputPath)
        }
        val resp = httpPost(dataDir, port, "/api/directed/retrieve-to-file", body, FILE_OPERATION_TIMEOUT_MS)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return RetrieveToFileResult(
            outputPath = resp.getString("output_path"),
            filename = resp.optString("filename", null),
            bytesWritten = resp.optLong("bytes_written", 0),
        )
    }

    /** Revoke a directed share. */
    fun revoke(dataDir: String, port: Int, envelopeId: String) {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
        }
        val resp = httpPost(dataDir, port, "/api/directed/revoke", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
    }

    // ─── Types ──────────────────────────────────────────────────────────

    data class SharingKeyResult(val key: String, val contact: String)
    data class RetrieveResult(val data: ByteArray, val filename: String?)
    data class RetrieveToFileResult(val outputPath: String, val filename: String?, val bytesWritten: Long)

    data class EnvelopeItem(
        val envelopeId: String,
        val senderPubkey: String,
        val recipientPubkey: String,
        val state: String,
        val createdAt: Long,
        val expiresAt: Long,
        val retentionSecs: Long,
        val challengeCode: String?,
        val filename: String?,
        val fileSize: Long,
    )

    private fun parseEnvelopes(arr: JSONArray): List<EnvelopeItem> {
        val list = mutableListOf<EnvelopeItem>()
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            list.add(
                EnvelopeItem(
                    envelopeId = obj.optString("envelope_id", ""),
                    senderPubkey = obj.optString("sender_pubkey", ""),
                    recipientPubkey = obj.optString("recipient_pubkey", ""),
                    state = obj.optString("state", "Unknown"),
                    createdAt = obj.optLong("created_at", 0),
                    expiresAt = obj.optLong("expires_at", 0),
                    retentionSecs = obj.optLong("retention_secs", 0),
                    challengeCode = obj.optString("challenge_code", null),
                    filename = obj.optString("filename", null),
                    fileSize = obj.optLong("file_size", 0),
                )
            )
        }
        return list
    }
}
