package dev.miasma

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore — wraps the Miasma node's master key with a hardware-backed
 * AES-GCM key so that:
 *
 *   1. The raw master key never lives in cleartext outside of TEE/SE.
 *   2. Distress wipe just calls [deleteKey] — the Keystore key is destroyed in
 *      the SE/StrongBox and the wrapped blob on disk becomes permanently
 *      unreadable, satisfying the ≤5s wipe requirement.
 *
 * # File layout (inside `dataDir`):
 *   `master.key.enc`  — AES-GCM ciphertext of the 32-byte master key
 *   `master.key.iv`   — 12-byte GCM IV for the blob above
 *
 * The plaintext `master.key` used by the Rust FFI layer is written only during
 * [unwrapToFile] and should be deleted after the Rust node has loaded it if a
 * fully TEE-backed flow is desired in Phase 2.  For Phase 1 the node reads it
 * on every start from the wrapper.
 *
 * # Distress wipe integration
 * The Rust FFI [distressWipe] already zeroes and deletes `master.key`.
 * [deleteKey] additionally removes the Keystore entry so the encrypted blob
 * is also unrecoverable.
 */
object KeystoreHelper {

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS          = "dev.miasma.masterkey"
    private const val AES_GCM_NOPADDING  = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS       = 128
    private const val GCM_IV_BYTES       = 12

    // ──── Keystore key lifecycle ─────────────────────────────────────────────

    /** Generate the wrapping key in the Keystore (idempotent). */
    fun ensureKey() {
        if (keyExists()) return
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)  // OS provides the IV
            .build()

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            .apply { init(spec) }
            .generateKey()
    }

    /**
     * Destroy the Keystore entry.
     *
     * After this call any previously wrapped `master.key.enc` blob is
     * cryptographically unrecoverable.  Called as part of distress wipe.
     */
    fun deleteKey() {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) {
            ks.deleteEntry(KEY_ALIAS)
        }
    }

    // ──── Wrap / unwrap ──────────────────────────────────────────────────────

    /**
     * Encrypt [plaintext] with the Keystore key and write
     * `master.key.enc` + `master.key.iv` into [dataDir].
     */
    fun wrapKey(dataDir: java.io.File, plaintext: ByteArray) {
        ensureKey()
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())

        val ciphertext = cipher.doFinal(plaintext)
        val iv         = cipher.iv   // 12 bytes, OS-generated

        dataDir.resolve("master.key.enc").writeBytes(ciphertext)
        dataDir.resolve("master.key.iv").writeBytes(iv)
    }

    /**
     * Decrypt `master.key.enc` from [dataDir] and return the plaintext.
     * Returns `null` if the blob or Keystore key are absent.
     */
    fun unwrapKey(dataDir: java.io.File): ByteArray? {
        val encFile = dataDir.resolve("master.key.enc")
        val ivFile  = dataDir.resolve("master.key.iv")
        if (!encFile.exists() || !ivFile.exists()) return null
        if (!keyExists()) return null

        val iv         = ivFile.readBytes()
        val ciphertext = encFile.readBytes()
        val spec       = GCMParameterSpec(GCM_TAG_BITS, iv)

        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), spec)
        return cipher.doFinal(ciphertext)
    }

    // ──── Private ────────────────────────────────────────────────────────────

    private fun keyExists(): Boolean {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return ks.containsAlias(KEY_ALIAS)
    }

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return (ks.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }
}
