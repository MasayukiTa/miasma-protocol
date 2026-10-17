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

data class EmbeddedDaemonStatus(
    val httpPort: UShort,
    val peerId: String,
    val sharingContact: String,
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
fun dissolveBytes(dataDir: String, data: ByteArray): String = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun retrieveBytes(dataDir: String, midStr: String): ByteArray = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun getNodeStatus(dataDir: String): NodeStatusFfi = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun distressWipe(dataDir: String): Unit = ffiNotLoaded()

@Throws(MiasmaFfiException::class)
fun startEmbeddedDaemon(
    dataDir: String,
    storageMb: ULong,
    bandwidthMbDay: ULong,
): EmbeddedDaemonStatus = ffiNotLoaded()

fun stopEmbeddedDaemon(): Unit = ffiNotLoaded()

fun getDaemonHttpPort(): UShort = ffiNotLoaded()

fun isDaemonRunning(): Boolean = ffiNotLoaded()
