package dev.miasma

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
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

    private fun bridgeUrl(port: Int, path: String): URL =
        URL("http://127.0.0.1:$port$path")

    // ─── GET helpers ────────────────────────────────────────────────────

    private fun httpGet(port: Int, path: String): JSONObject {
        val conn = bridgeUrl(port, path).openConnection() as HttpURLConnection
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

    private fun httpGetArray(port: Int, path: String): JSONArray {
        val conn = bridgeUrl(port, path).openConnection() as HttpURLConnection
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

    private fun httpPost(port: Int, path: String, body: JSONObject): JSONObject {
        val conn = bridgeUrl(port, path).openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = 5_000
        conn.readTimeout = 60_000
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

    /** Get sharing key and contact. */
    fun sharingKey(port: Int): SharingKeyResult {
        val resp = httpGet(port, "/api/sharing-key")
        return SharingKeyResult(
            key = resp.optString("key", ""),
            contact = resp.optString("contact", ""),
        )
    }

    /** List incoming directed envelopes. */
    fun inbox(port: Int): List<EnvelopeItem> {
        val arr = httpGetArray(port, "/api/directed/inbox")
        return parseEnvelopes(arr)
    }

    /** List outgoing directed envelopes. */
    fun outbox(port: Int): List<EnvelopeItem> {
        val arr = httpGetArray(port, "/api/directed/outbox")
        return parseEnvelopes(arr)
    }

    /** Send a directed share. */
    fun send(
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
        val resp = httpPost(port, "/api/directed/send", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        return resp.getString("envelope_id")
    }

    /** Confirm a challenge code (sender confirms recipient). */
    fun confirm(port: Int, envelopeId: String, challengeCode: String) {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
            put("challenge_code", challengeCode)
        }
        val resp = httpPost(port, "/api/directed/confirm", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
    }

    /** Retrieve directed content with password. */
    fun retrieve(port: Int, envelopeId: String, password: String): RetrieveResult {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
            put("password", password)
        }
        val resp = httpPost(port, "/api/directed/retrieve", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
        val dataB64 = resp.getString("data")
        val data = android.util.Base64.decode(dataB64, android.util.Base64.DEFAULT)
        return RetrieveResult(
            data = data,
            filename = resp.optString("filename", null),
        )
    }

    /** Revoke a directed share. */
    fun revoke(port: Int, envelopeId: String) {
        val body = JSONObject().apply {
            put("envelope_id", envelopeId)
        }
        val resp = httpPost(port, "/api/directed/revoke", body)
        if (resp.has("error")) throw RuntimeException(resp.getString("error"))
    }

    // ─── Types ──────────────────────────────────────────────────────────

    data class SharingKeyResult(val key: String, val contact: String)
    data class RetrieveResult(val data: ByteArray, val filename: String?)

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
