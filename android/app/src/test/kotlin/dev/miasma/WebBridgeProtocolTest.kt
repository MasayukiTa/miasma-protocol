package dev.miasma

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebBridgeProtocolTest {

    private fun msg(id: Any?, method: Any?, args: JSONArray?): String =
        JSONObject().apply {
            if (id != null) put("id", id)
            if (method != null) put("method", method)
            if (args != null) put("args", args)
        }.toString()

    private fun rejected(raw: String?, expected: String) {
        val r = WebBridgeProtocol.parse(raw)
        assertTrue("expected Rejected, got $r", r is Rejected)
        assertEquals(expected, (r as Rejected).message)
    }

    @Test
    fun pingParses() {
        val r = WebBridgeProtocol.parse(msg(1, "ping", JSONArray()))
        assertTrue(r is Request)
        r as Request
        assertEquals(1L, r.id)
        assertEquals(Capability.STATUS, r.spec.capability)
    }

    @Test
    fun missingArgsMeansNoArgs() {
        assertTrue(WebBridgeProtocol.parse(msg(2, "status", null)) is Request)
    }

    @Test
    fun capabilitySplit() {
        val m = WebBridgeProtocol.METHODS
        assertEquals(Capability.DESTRUCTIVE, m["wipe"]!!.capability)
        assertEquals(setOf("wipe"), m.values.filter { it.capability == Capability.DESTRUCTIVE }.map { it.name }.toSet())
        assertEquals(
            setOf("ping", "status", "sharingKey", "directedInbox", "directedOutbox"),
            m.values.filter { it.capability == Capability.STATUS }.map { it.name }.toSet(),
        )
        assertEquals(setOf("dissolve", "retrieve"), m.values.filter { it.capability == Capability.TRANSFER }.map { it.name }.toSet())
        assertEquals(
            setOf("directedSend", "directedConfirm", "directedRetrieve", "directedRevoke"),
            m.values.filter { it.capability == Capability.DIRECTED }.map { it.name }.toSet(),
        )
        assertEquals(setOf(Capability.DESTRUCTIVE), WebBridgeProtocol.CONFIRMED_CAPABILITIES)
    }

    @Test
    fun noMethodTakesAPath() {
        // Content reaches native code only as Base64 data; no argument is a file path.
        for (spec in WebBridgeProtocol.METHODS.values) {
            assertFalse(spec.name, spec.name.contains("File", ignoreCase = true) || spec.name.contains("Path", ignoreCase = true))
        }
    }

    @Test
    fun unknownMethodIsRejectedWithId() {
        val r = WebBridgeProtocol.parse(msg(7, "evalNative", JSONArray()))
        assertTrue(r is Rejected)
        assertEquals(7L, (r as Rejected).id)
        assertEquals("unknown method", r.message)
    }

    @Test
    fun malformedMessagesAreRejected() {
        rejected(null, "unsupported message")
        rejected("not json", "malformed message")
        rejected("[]", "malformed message")
        rejected("{}", "malformed message")
        rejected(msg("1", "ping", JSONArray()), "malformed message")
        rejected(msg(1.5, "ping", JSONArray()), "malformed message")
        rejected(msg(-1, "ping", JSONArray()), "malformed message")
        val r = WebBridgeProtocol.parse(msg(3, 5, JSONArray()))
        assertEquals("malformed message", (r as Rejected).message)
    }

    @Test
    fun wrongArgumentCountAndTypes() {
        val r1 = WebBridgeProtocol.parse(msg(1, "directedRevoke", JSONArray()))
        assertEquals("wrong argument count", (r1 as Rejected).message)
        val r2 = WebBridgeProtocol.parse(msg(1, "directedRevoke", JSONArray().put(5)))
        assertEquals("bad argument", (r2 as Rejected).message)
        val r3 = WebBridgeProtocol.parse(msg(1, "retrieve", JSONArray().put("mid").put("3").put(5)))
        assertEquals("bad argument", (r3 as Rejected).message)
        val r4 = WebBridgeProtocol.parse(msg(1, "retrieve", JSONArray().put("mid").put(3.5).put(5)))
        assertEquals("bad argument", (r4 as Rejected).message)
        val r5 = WebBridgeProtocol.parse(msg(1, "retrieve", JSONArray().put("mid").put(Long.MAX_VALUE).put(5)))
        assertEquals("bad argument", (r5 as Rejected).message)
        val r6 = WebBridgeProtocol.parse(msg(1, "ping", JSONArray().put("x")))
        assertEquals("wrong argument count", (r6 as Rejected).message)
    }

    @Test
    fun optionalFilenameMayBeNull() {
        val args = JSONArray().put("msk:a@b").put("QUJD").put("pw").put(3600).put(JSONObject.NULL)
        val r = WebBridgeProtocol.parse(msg(9, "directedSend", args))
        assertTrue(r is Request)
        r as Request
        assertEquals(null, r.args[4])
        assertEquals(3600L, r.args[3])
        // A required string may not be null.
        val bad = JSONArray().put(JSONObject.NULL).put("QUJD").put("pw").put(3600).put(JSONObject.NULL)
        assertEquals("bad argument", (WebBridgeProtocol.parse(msg(9, "directedSend", bad)) as Rejected).message)
    }

    @Test
    fun base64LimitDerivesFromBodyLimit() {
        assertEquals(16 * 1024 * 1024, WebBridgeProtocol.MAX_BODY_BYTES)
        // 16 MiB is not a multiple of 3: 5,592,405 groups of 3 bytes plus 1 byte = 5,592,406 groups of 4 chars.
        assertEquals(22_369_624, WebBridgeProtocol.MAX_BASE64_CHARS)
        assertTrue(WebBridgeProtocol.base64LengthOk("A".repeat(WebBridgeProtocol.MAX_BASE64_CHARS)))
        assertFalse(WebBridgeProtocol.base64LengthOk("A".repeat(WebBridgeProtocol.MAX_BASE64_CHARS + 1)))
    }

    @Test
    fun oversizedPayloadRejectedBeforeAnyDecode() {
        val big = "A".repeat(WebBridgeProtocol.MAX_BASE64_CHARS + 1)
        val r = WebBridgeProtocol.parse(msg(4, "dissolve", JSONArray().put(big).put(3).put(5)))
        assertEquals("argument too large", (r as Rejected).message)
        // A message longer than any valid message is refused without being parsed.
        val huge = "x".repeat(WebBridgeProtocol.MAX_MESSAGE_CHARS + 1)
        assertEquals("message too large", (WebBridgeProtocol.parse(huge) as Rejected).message)
    }

    @Test
    fun maximumPayloadIsAccepted() {
        val ok = "A".repeat(WebBridgeProtocol.MAX_BASE64_CHARS)
        val r = WebBridgeProtocol.parse(msg(5, "dissolve", JSONArray().put(ok).put(3).put(5)))
        assertTrue(r is Request)
    }

    @Test
    fun longShortTextFieldsAreRejected() {
        val long = "a".repeat(WebBridgeProtocol.MAX_SHORT_TEXT_CHARS + 1)
        val r = WebBridgeProtocol.parse(msg(6, "directedRevoke", JSONArray().put(long)))
        assertEquals("argument too large", (r as Rejected).message)
    }

    @Test
    fun responses() {
        assertEquals("{\"id\":12,\"result\":{\"ok\":true}}", WebBridgeProtocol.okResponse(12, "{\"ok\":true}"))
        val e = JSONObject(WebBridgeProtocol.errorResponse(null, "busy"))
        assertTrue(e.isNull("id"))
        assertEquals("busy", e.getString("error"))
        val e2 = JSONObject(WebBridgeProtocol.errorResponse(3, "x"))
        assertEquals(3, e2.getInt("id"))
    }

    @Test
    fun allowedOriginIsExact() {
        assertEquals("https://appassets.androidplatform.net", WebBridgeProtocol.ALLOWED_ORIGIN)
    }
}
