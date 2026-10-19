package dev.miasma

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore wrapper for the Miasma node master key.
 *
 * A non-exportable AES-GCM key in AndroidKeyStore protects the recovery copy
 * (`master.key.enc` + `master.key.iv`). The current Rust store still reopens
 * `master.key` for local FFI operations, so the plaintext file remains in the
 * app-private directory while the node is usable. This is defense in depth,
 * not a claim that the 32-byte Miasma master key never exists outside TEE/SE.
 *
 * Distress wipe deletes both the Rust plaintext key and the AndroidKeyStore
 * wrapping key. Destroying the wrapping key makes the encrypted recovery blob
 * unusable even if filesystem remnants survive.
 *
 * ByteArrays containing the plaintext are best-effort zeroed by the helpers
 * below after they have been copied to their destination. The JVM/crypto
 * provider may still have transient internal copies.
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

    /**
     * Restore `master.key` from the Keystore-wrapped recovery blob when the
     * plaintext file is absent. Returns true when a key was restored.
     */
    fun restorePlaintextKeyIfNeeded(dataDir: java.io.File): Boolean {
        val masterKeyFile = dataDir.resolve("master.key")
        if (masterKeyFile.exists()) return false
        val plaintext = unwrapKey(dataDir) ?: return false
        return try {
            masterKeyFile.writeBytes(plaintext)
            true
        } finally {
            plaintext.fill(0)
        }
    }

    /**
     * Refresh the Keystore-wrapped recovery blob from the Rust plaintext key.
     * The temporary JVM byte array is zeroed on return.
     */
    fun wrapPlaintextKeyFile(dataDir: java.io.File): Boolean {
        val masterKeyFile = dataDir.resolve("master.key")
        if (!masterKeyFile.exists()) return false
        val plaintext = masterKeyFile.readBytes()
        return try {
            wrapKey(dataDir, plaintext)
            true
        } finally {
            plaintext.fill(0)
        }
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
