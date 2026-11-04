package takagi.ru.monica.cloud.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.text.Normalizer
import java.util.Base64
import java.util.Locale
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Monica Cloud protocol v1 client cryptography (Monica-Cloud/docs/protocol.zh-CN.md §1).
 *
 * Pure JVM code: no android.* imports, so it runs in local unit tests against the shared
 * `test-vectors.json`. Keys are raw 32-byte arrays; callers own them and should wipe them
 * (`fill(0)`) when the vault locks.
 */
object MonicaCloudCrypto {
    const val KDF_PBKDF2 = 0
    const val BLOB_CHUNK_SIZE = 64 * 1024
    const val SEND_PASSWORD_ITERATIONS = 100_000

    private const val ENC_VERSION = "1"
    private const val KEY_BYTES = 32
    private const val GCM_IV = 12
    private const val GCM_TAG = 16
    private const val HMAC = "HmacSHA256"
    private const val WRAP_INFO = "monica-cloud/v1/wrap"
    private const val SEND_INFO = "monica-cloud/v1/send"
    private val BLOB_MAGIC = byteArrayOf('M'.code.toByte(), 'C'.code.toByte(), 'B'.code.toByte(), '1'.code.toByte())

    private val random = SecureRandom()
    private val base64 = Base64.getEncoder()
    private val base64Decoder = Base64.getDecoder()

    class MasterKeys(
        /** Sent to the server in place of the master password. */
        val authHash: String,
        /** Unwraps the account userKey. */
        val wrapKey: ByteArray,
    )

    class EncryptedItem(val key: String, val data: String)

    // ------------------------------------------------------------------ encoding

    fun b64(bytes: ByteArray): String = base64.encodeToString(bytes)

    fun fromB64(value: String): ByteArray = base64Decoder.decode(value)

    fun b64Url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun fromB64Url(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    fun randomBytes(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)

    fun normalizeEmail(email: String): String = email.trim().lowercase(Locale.ROOT)

    // ------------------------------------------------------------------ KDF (§1.1)

    /**
     * PBKDF2-HMAC-SHA256 over raw bytes. `SecretKeyFactory("PBKDF2WithHmacSHA256")` only accepts
     * `char[]` passwords, but the second derivation uses the 32-byte masterKey as password.
     */
    fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int = KEY_BYTES): ByteArray {
        require(iterations >= 1) { "iterations must be positive" }
        require(password.isNotEmpty()) { "password must not be empty" }
        val mac = Mac.getInstance(HMAC).apply { init(SecretKeySpec(password, HMAC)) }
        val hLen = mac.macLength
        val out = ByteArray(length)
        val u = ByteArray(hLen)
        val t = ByteArray(hLen)
        var block = 1
        var offset = 0
        while (offset < length) {
            mac.update(salt)
            mac.update(ByteBuffer.allocate(4).putInt(block).array())
            mac.doFinal(u, 0)
            u.copyInto(t)
            for (i in 1 until iterations) {
                mac.update(u)
                mac.doFinal(u, 0)
                for (j in 0 until hLen) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            val take = minOf(hLen, length - offset)
            t.copyInto(out, offset, 0, take)
            offset += take
            block++
        }
        u.fill(0)
        t.fill(0)
        return out
    }

    /** RFC 5869 HKDF-SHA256 with an empty salt (equivalent to 32 zero bytes). */
    fun hkdfSha256(ikm: ByteArray, info: String, length: Int = KEY_BYTES): ByteArray {
        val mac = Mac.getInstance(HMAC)
        mac.init(SecretKeySpec(ByteArray(mac.macLength), HMAC))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, HMAC))
        val infoBytes = info.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream(length)
        var previous = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            mac.update(previous)
            mac.update(infoBytes)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            out.write(previous)
            counter++
        }
        prk.fill(0)
        return out.toByteArray().copyOf(length)
    }

    fun deriveMasterKeys(email: String, masterPassword: String, iterations: Int): MasterKeys {
        val password = Normalizer.normalize(masterPassword, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val masterKey = pbkdf2Sha256(password, normalizeEmail(email).toByteArray(Charsets.UTF_8), iterations)
        try {
            val authHash = b64(pbkdf2Sha256(masterKey, password, 1))
            return MasterKeys(authHash, hkdfSha256(masterKey, WRAP_INFO))
        } finally {
            masterKey.fill(0)
            password.fill(0)
        }
    }

    // ------------------------------------------------------------------ EncString (§1.4)

    fun encrypt(key: ByteArray, plaintext: ByteArray): String {
        val iv = randomBytes(GCM_IV)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey(key), GCMParameterSpec(GCM_TAG * 8, iv))
        return "$ENC_VERSION.${b64(iv)}.${b64(cipher.doFinal(plaintext))}"
    }

    fun decrypt(key: ByteArray, encString: String): ByteArray {
        val parts = encString.split('.')
        if (parts.size != 3 || parts[0] != ENC_VERSION) {
            throw MonicaCloudCryptoException.UnsupportedFormat()
        }
        val iv = runCatching { fromB64(parts[1]) }.getOrNull()
        val ciphertext = runCatching { fromB64(parts[2]) }.getOrNull()
        if (iv == null || iv.size != GCM_IV || ciphertext == null || ciphertext.size < GCM_TAG) {
            throw MonicaCloudCryptoException.Malformed()
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, aesKey(key), GCMParameterSpec(GCM_TAG * 8, iv))
            cipher.doFinal(ciphertext)
        } catch (e: AEADBadTagException) {
            throw MonicaCloudCryptoException.WrongKey(e)
        }
    }

    fun encryptString(key: ByteArray, value: String): String = encrypt(key, value.toByteArray(Charsets.UTF_8))

    fun decryptString(key: ByteArray, encString: String): String = String(decrypt(key, encString), Charsets.UTF_8)

    // ------------------------------------------------------------------ account and item keys (§1.2, §1.3)

    fun generateKey(): ByteArray = randomBytes(KEY_BYTES)

    /** Unwrap `protectedUserKey`; a wrong master password surfaces as [MonicaCloudCryptoException.WrongKey]. */
    fun unwrapUserKey(wrapKey: ByteArray, protectedUserKey: String): ByteArray {
        val key = decrypt(wrapKey, protectedUserKey)
        if (key.size != KEY_BYTES) throw MonicaCloudCryptoException.Malformed()
        return key
    }

    /**
     * Encrypt an item payload (JSON). Pass the existing [itemKey] when updating so attachments,
     * which are wrapped by the item key, stay readable.
     */
    fun encryptItem(userKey: ByteArray, payloadJson: String, itemKey: ByteArray = generateKey()): EncryptedItem =
        EncryptedItem(key = encrypt(userKey, itemKey), data = encryptString(itemKey, payloadJson))

    fun decryptItemKey(userKey: ByteArray, encryptedItemKey: String): ByteArray {
        val key = decrypt(userKey, encryptedItemKey)
        if (key.size != KEY_BYTES) throw MonicaCloudCryptoException.Malformed()
        return key
    }

    // ------------------------------------------------------------------ chunked files (§1.5)

    fun encryptedBlobSize(plainLength: Long, chunkSize: Int = BLOB_CHUNK_SIZE): Long {
        val chunks = maxOf(1L, (plainLength + chunkSize - 1) / chunkSize)
        return 8L + chunks * (GCM_IV + GCM_TAG) + plainLength
    }

    /** Stream-encrypt [input] into [output]. Returns the number of ciphertext bytes written. */
    fun encryptBlob(key: ByteArray, input: InputStream, output: OutputStream, chunkSize: Int = BLOB_CHUNK_SIZE): Long {
        output.write(BLOB_MAGIC)
        output.write(ByteBuffer.allocate(4).putInt(chunkSize).array())
        var written = 8L
        var current = readFully(input, chunkSize)
        var index = 0L
        while (true) {
            val next = if (current.size == chunkSize) readFully(input, chunkSize) else ByteArray(0)
            val final = next.isEmpty()
            val iv = randomBytes(GCM_IV)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, aesKey(key), GCMParameterSpec(GCM_TAG * 8, iv))
            cipher.updateAAD(chunkAad(index, final))
            val sealed = cipher.doFinal(current)
            output.write(iv)
            output.write(sealed)
            written += iv.size + sealed.size
            if (final) return written
            current = next
            index++
        }
    }

    /** Stream-decrypt; detects tampering, truncation and reordering. */
    fun decryptBlob(key: ByteArray, input: InputStream, output: OutputStream) {
        val header = readFully(input, 8)
        if (header.size != 8 || !header.copyOfRange(0, 4).contentEquals(BLOB_MAGIC)) {
            throw MonicaCloudCryptoException.Malformed()
        }
        val chunkSize = ByteBuffer.wrap(header, 4, 4).int
        if (chunkSize !in 1024..16 * 1024 * 1024) throw MonicaCloudCryptoException.Malformed()
        val stream = PushbackInputStream(input, 1)
        var index = 0L
        while (true) {
            val sealed = readFully(stream, GCM_IV + chunkSize + GCM_TAG)
            if (sealed.size < GCM_IV + GCM_TAG) throw MonicaCloudCryptoException.Malformed()
            val peek = stream.read()
            val final = peek == -1
            if (!final) stream.unread(peek)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, aesKey(key), GCMParameterSpec(GCM_TAG * 8, sealed, 0, GCM_IV))
                cipher.updateAAD(chunkAad(index, final))
                output.write(cipher.doFinal(sealed, GCM_IV, sealed.size - GCM_IV))
            } catch (e: AEADBadTagException) {
                throw MonicaCloudCryptoException.WrongKey(e)
            }
            if (final) return
            index++
        }
    }

    fun encryptBlob(key: ByteArray, plaintext: ByteArray, chunkSize: Int = BLOB_CHUNK_SIZE): ByteArray =
        ByteArrayOutputStream(encryptedBlobSize(plaintext.size.toLong(), chunkSize).toInt()).also {
            encryptBlob(key, ByteArrayInputStream(plaintext), it, chunkSize)
        }.toByteArray()

    fun decryptBlob(key: ByteArray, blob: ByteArray): ByteArray =
        ByteArrayOutputStream(blob.size).also { decryptBlob(key, ByteArrayInputStream(blob), it) }.toByteArray()

    // ------------------------------------------------------------------ Send (§1.6)

    fun sendContentKey(sendKey: ByteArray): ByteArray = hkdfSha256(sendKey, SEND_INFO)

    fun sendPasswordHash(password: String, sendKey: ByteArray): String =
        b64(pbkdf2Sha256(password.toByteArray(Charsets.UTF_8), sendKey, SEND_PASSWORD_ITERATIONS))

    // ------------------------------------------------------------------ helpers

    private fun aesKey(raw: ByteArray): SecretKeySpec {
        require(raw.size == KEY_BYTES) { "AES-256 keys must be 32 bytes" }
        return SecretKeySpec(raw, "AES")
    }

    private fun chunkAad(index: Long, final: Boolean): ByteArray =
        ByteBuffer.allocate(9).putLong(index).put(if (final) 1 else 0).array()

    /** Read up to [length] bytes, returning fewer only at end of stream. */
    private fun readFully(input: InputStream, length: Int): ByteArray {
        val buffer = ByteArray(length)
        var read = 0
        while (read < length) {
            val n = input.read(buffer, read, length - read)
            if (n < 0) break
            read += n
        }
        return if (read == length) buffer else buffer.copyOf(read)
    }
}

sealed class MonicaCloudCryptoException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The ciphertext uses a format version this client does not know; the app needs an update. */
    class UnsupportedFormat : MonicaCloudCryptoException("unsupported Monica Cloud encryption format")

    class Malformed : MonicaCloudCryptoException("malformed Monica Cloud ciphertext")

    /** Authentication failed: wrong key/master password, or the data was modified. */
    class WrongKey(cause: Throwable? = null) : MonicaCloudCryptoException("decryption failed", cause)
}
