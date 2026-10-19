// DEVELOPMENT STUB for the UniFFI-generated Kotlin bindings.
//
// Real Android builds replace this file with bindings generated from
// crates/miasma-ffi. Keep the public types below aligned with UniFFI 0.28's
// Kotlin mapping so ordinary Kotlin compilation catches API drift even on a
// machine without the Android NDK/JNI library.

package dev.miasma.uniffi

// Rust u64/u16 map to Kotlin ULong/UShort in UniFFI 0.28.
data class NodeStatusFfi(
    val shareCount: ULong,
    val usedMb: Double,
    val quotaMb: ULong,
    val listenAddr: String,
    val bootstrapCount: ULong,
)

data class FileReceiveResultFfi(
    val outputPath: String,
    val bytesWritten: ULong,
)

data class EmbeddedDaemonStatus(
    val httpPort: UShort,
    val peerId: String,
    val sharingContact: String,
)

data class EnvelopeSummaryFfi(
    val id: String,
    val senderKey: String,
    val senderPeerId: String?,
    val state: String,
    val challengeCode: String?,
    val createdAt: ULong,
    val expiresAt: ULong,
)

sealed class MiasmaFfiException(message: String) : Exception(message) {
    class NotInitialized(val dataDir: String) :
        MiasmaFfiException("Node not initialised at '$dataDir'. Call initialize_node first.")

    class InvalidMid(val reason: String) :
        MiasmaFfiException("Invalid MID: $reason")

    class InsufficientShares(val need: ULong, val got: ULong) :
        MiasmaFfiException("Insufficient shares: need $need, found $got")

    class InputTooLarge(val size: ULong, val max: ULong) :
        MiasmaFfiException("Input too large")

    class Other(val msg: String) : MiasmaFfiException(msg)
}

private fun ffiNotLoaded(): Nothing =
    throw UnsupportedOperationException("Generated FFI not loaded; build miasma-ffi and run uniffi-bindgen")

@Throws(MiasmaFfiException::class)
fun initializeNode(dataDir: String, storageMb: ULong, bandwidthMbDay: ULong): Unit = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun setBootstrapPeers(dataDir: String, bootstrapPeers: List<String>): Unit = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun dissolveBytes(dataDir: String, data: ByteArray): String = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun retrieveBytes(dataDir: String, midStr: String): ByteArray = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun publishFile(dataDir: String, filePath: String): String = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun retrieveToFile(dataDir: String, midStr: String, outputPath: String): FileReceiveResultFfi = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun getNodeStatus(dataDir: String): NodeStatusFfi = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun distressWipe(dataDir: String): Unit = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun getSharingKey(dataDir: String): String = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun listDirectedInbox(dataDir: String): List<EnvelopeSummaryFfi> = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun listDirectedOutbox(dataDir: String): List<EnvelopeSummaryFfi> = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun deleteDirectedEnvelope(dataDir: String, envelopeId: String): Unit = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun startEmbeddedDaemon(
    dataDir: String,
    storageMb: ULong,
    bandwidthMbDay: ULong,
): EmbeddedDaemonStatus = ffiNotLoaded()

fun stopEmbeddedDaemon(): Unit = ffiNotLoaded()

fun getDaemonHttpPort(): UShort = ffiNotLoaded()

fun isDaemonRunning(): Boolean = ffiNotLoaded()

fun getSharingContact(): String = ffiNotLoaded()


data class PrivacyProfileFfi(
    val stealthMode: Boolean,
    val diagnosticLogging: Boolean,
    val logBufferMib: UInt,
)

data class PrivacyProfileApplyResultFfi(
    val restartRequired: Boolean,
    val writesLogFilesAfterRestart: Boolean,
)

@Throws(MiasmaFfiException::class)
fun getPrivacyProfile(dataDir: String): PrivacyProfileFfi = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun setPrivacyProfile(
    dataDir: String,
    profile: PrivacyProfileFfi,
): PrivacyProfileApplyResultFfi = ffiNotLoaded()
