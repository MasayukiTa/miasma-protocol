package dev.miasma

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Message protocol between the bundled web client and the native host.
 *
 * Request  (page -> native): `{"id": <int>, "method": "<name>", "args": [ ... ]}`
 * Response (native -> page): `{"id": <int>, "result": <json>}` or `{"id": <int|null>, "error": "<text>"}`
 *
 * This file has no Android dependencies so that it can be unit tested on the JVM.
 * Everything here runs BEFORE any Base64 decode or native call: a message is
 * length-checked, parsed and type-checked against a fixed per-method table, and
 * anything else is rejected. Message payloads are never logged.
 */
enum class Capability {
    /** Read-only node and mailbox state. */
    STATUS,

    /** Store or fetch content by id through the node. */
    TRANSFER,

    /** Directed (recipient-bound) sharing operations. */
    DIRECTED,

    /** Irreversible data destruction. Needs a native confirmation dialog. */
    DESTRUCTIVE,
}

sealed class ArgSpec {
    /** Short text field (ids, contact strings, passwords, file names). */
    data class Str(val optional: Boolean = false) : ArgSpec()

    /** 32-bit integer. */
    object Int32 : ArgSpec()

    /** 64-bit integer. */
    object Int64 : ArgSpec()

    /** Base64 text carrying content; its length is capped before decoding. */
    object Base64Data : ArgSpec()
}

data class MethodSpec(val name: String, val capability: Capability, val args: List<ArgSpec>)

sealed class ParseResult
data class Request(val id: Long, val spec: MethodSpec, val args: List<Any?>) : ParseResult()
data class Rejected(val id: Long?, val message: String) : ParseResult()

object WebBridgeProtocol {

    /** The origin of the bundled web client. The only origin the listener accepts. */
    const val ALLOWED_ORIGIN = "https://appassets.androidplatform.net"

    /** Name of the injected JavaScript object. */
    const val JS_OBJECT_NAME = "miasma"

    /** Largest request body the daemon's HTTP bridge accepts (`MAX_BODY` in daemon/http_bridge.rs). */
    const val MAX_BODY_BYTES = 16 * 1024 * 1024

    /** Longest Base64 text that can decode to at most [MAX_BODY_BYTES] bytes. */
    const val MAX_BASE64_CHARS = ((MAX_BODY_BYTES + 2) / 3) * 4

    /**
     * Cap for every non-payload text field. The longest legitimate field is the
     * recipient contact string (a few hundred characters).
     */
    const val MAX_SHORT_TEXT_CHARS = 4096

    /** Cap for the method name. */
    const val MAX_METHOD_CHARS = 64

    /** Whole-message cap: one payload field plus room for the other fields and the JSON framing. */
    const val MAX_MESSAGE_CHARS = MAX_BASE64_CHARS + 8 * MAX_SHORT_TEXT_CHARS

    /** Capabilities that need a native confirmation dialog before they run. */
    val CONFIRMED_CAPABILITIES: Set<Capability> = setOf(Capability.DESTRUCTIVE)

    private val STR = ArgSpec.Str()

    val METHODS: Map<String, MethodSpec> = listOf(
        // status / read
        MethodSpec("ping", Capability.STATUS, emptyList()),
        MethodSpec("status", Capability.STATUS, emptyList()),
        MethodSpec("sharingKey", Capability.STATUS, emptyList()),
        MethodSpec("directedInbox", Capability.STATUS, emptyList()),
        MethodSpec("directedOutbox", Capability.STATUS, emptyList()),
        // transfer
        MethodSpec("dissolve", Capability.TRANSFER, listOf(ArgSpec.Base64Data, ArgSpec.Int32, ArgSpec.Int32)),
        MethodSpec("retrieve", Capability.TRANSFER, listOf(STR, ArgSpec.Int32, ArgSpec.Int32)),
        // directed
        MethodSpec(
            "directedSend", Capability.DIRECTED,
            listOf(STR, ArgSpec.Base64Data, STR, ArgSpec.Int64, ArgSpec.Str(optional = true)),
        ),
        MethodSpec("directedConfirm", Capability.DIRECTED, listOf(STR, STR)),
        MethodSpec("directedRetrieve", Capability.DIRECTED, listOf(STR, STR)),
        MethodSpec("directedRevoke", Capability.DIRECTED, listOf(STR)),
        // destructive
        MethodSpec("wipe", Capability.DESTRUCTIVE, emptyList()),
    ).associateBy { it.name }

    /** True when a Base64 text is short enough to be decoded. Call this before every decode. */
    fun base64LengthOk(text: String): Boolean = text.length <= MAX_BASE64_CHARS

    fun parse(raw: String?): ParseResult {
        if (raw == null) return Rejected(null, "unsupported message")
        // Size first: nothing below allocates proportionally to an oversized message.
        if (raw.length > MAX_MESSAGE_CHARS) return Rejected(null, "message too large")

        val obj = try {
            JSONObject(raw)
        } catch (_: JSONException) {
            return Rejected(null, "malformed message")
        }

        val idValue = obj.opt("id")
        val id: Long = when (idValue) {
            is Int -> idValue.toLong()
            is Long -> idValue
            else -> return Rejected(null, "malformed message")
        }
        if (id < 0) return Rejected(null, "malformed message")

        val name = obj.opt("method") as? String ?: return Rejected(id, "malformed message")
        if (name.length > MAX_METHOD_CHARS) return Rejected(id, "unknown method")
        val spec = METHODS[name] ?: return Rejected(id, "unknown method")

        val argsValue = obj.opt("args")
        val arr = (argsValue as? JSONArray) ?: if (argsValue == null) JSONArray() else return Rejected(id, "malformed message")
        if (arr.length() != spec.args.size) return Rejected(id, "wrong argument count")

        val out = ArrayList<Any?>(spec.args.size)
        for ((i, a) in spec.args.withIndex()) {
            val v = arr.opt(i)
            when (a) {
                is ArgSpec.Str -> {
                    if (v == null || v == JSONObject.NULL) {
                        if (!a.optional) return Rejected(id, "bad argument")
                        out.add(null)
                    } else {
                        val s = v as? String ?: return Rejected(id, "bad argument")
                        if (s.length > MAX_SHORT_TEXT_CHARS) return Rejected(id, "argument too large")
                        out.add(s)
                    }
                }
                ArgSpec.Base64Data -> {
                    val s = v as? String ?: return Rejected(id, "bad argument")
                    if (!base64LengthOk(s)) return Rejected(id, "argument too large")
                    out.add(s)
                }
                ArgSpec.Int32 -> {
                    val n: Long = when (v) {
                        is Int -> v.toLong()
                        is Long -> v
                        else -> return Rejected(id, "bad argument")
                    }
                    if (n < Int.MIN_VALUE || n > Int.MAX_VALUE) return Rejected(id, "bad argument")
                    out.add(n.toInt())
                }
                ArgSpec.Int64 -> {
                    when (v) {
                        is Int -> out.add(v.toLong())
                        is Long -> out.add(v)
                        else -> return Rejected(id, "bad argument")
                    }
                }
            }
        }
        return Request(id, spec, out)
    }

    /** Success response. [resultJson] must be JSON text produced by this app (an object or array). */
    fun okResponse(id: Long, resultJson: String): String = "{\"id\":$id,\"result\":$resultJson}"

    /** Protocol-level error response. */
    fun errorResponse(id: Long?, message: String): String =
        JSONObject().put("id", id ?: JSONObject.NULL).put("error", message).toString()
}
