package takagi.ru.monica.cloud

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import takagi.ru.monica.cloud.crypto.MonicaCloudCrypto
import takagi.ru.monica.cloud.crypto.MonicaCloudCryptoException

/**
 * Checks the Kotlin implementation against Monica-Cloud/docs/test-vectors.json, the same vectors
 * the WebUI (WebCrypto) and an independent node:crypto implementation agree on.
 */
class MonicaCloudCryptoTest {

    private val vectors: JsonObject by lazy {
        val text = javaClass.classLoader!!.getResourceAsStream("monica-cloud/test-vectors.json")!!
            .bufferedReader().use { it.readText() }
        Json.parseToJsonElement(text).jsonObject
    }

    private fun section(name: String) = vectors[name]!!.jsonObject
    private fun JsonObject.str(name: String) = this[name]!!.jsonPrimitive.content
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun kdfMatchesVectors() {
        val kdf = section("kdf")
        val keys = MonicaCloudCrypto.deriveMasterKeys(kdf.str("email"), kdf.str("password"), kdf["iterations"]!!.jsonPrimitive.int)
        assertEquals(kdf.str("authHash"), keys.authHash)
        assertEquals(kdf.str("wrapKey"), keys.wrapKey.hex())
    }

    @Test
    fun pbkdf2MatchesRfc7914Vector() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd", "salt", 1, 64)
        val out = MonicaCloudCrypto.pbkdf2Sha256("passwd".toByteArray(), "salt".toByteArray(), 1, 64)
        assertEquals(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            out.hex(),
        )
    }

    @Test
    fun userKeyAndItemDecryptFromVectors() {
        val wrapKey = hex(section("kdf").str("wrapKey"))
        val userKey = MonicaCloudCrypto.unwrapUserKey(wrapKey, section("userKey").str("protectedUserKey"))
        assertEquals(section("userKey").str("raw"), userKey.hex())

        val item = section("item")
        val itemKey = MonicaCloudCrypto.decryptItemKey(userKey, item.str("key"))
        assertEquals(item.str("itemKey"), itemKey.hex())
        val payload = Json.parseToJsonElement(MonicaCloudCrypto.decryptString(itemKey, item.str("data")))
        assertEquals(item["payload"], payload)
    }

    @Test
    fun chunkedBlobFromVectors() {
        val blob = section("blob")
        val plain = MonicaCloudCrypto.decryptBlob(hex(blob.str("key")), hex(blob.str("ciphertext")))
        assertEquals(blob.str("plaintext"), plain.hex())
    }

    @Test
    fun sendFromVectors() {
        val send = section("send")
        val sendKey = MonicaCloudCrypto.fromB64Url(send.str("sendKeyUrl"))
        assertEquals(send.str("sendKey"), sendKey.hex())
        val contentKey = MonicaCloudCrypto.sendContentKey(sendKey)
        assertEquals(send.str("contentKey"), contentKey.hex())
        assertEquals(send.str("text"), MonicaCloudCrypto.decryptString(contentKey, send.str("encryptedText")))
        assertEquals(send.str("passwordHash"), MonicaCloudCrypto.sendPasswordHash(send.str("password"), sendKey))
    }

    @Test
    fun wrongMasterPasswordIsReported() {
        val kdf = section("kdf")
        val wrong = MonicaCloudCrypto.deriveMasterKeys(kdf.str("email"), "not the password", kdf["iterations"]!!.jsonPrimitive.int)
        assertThrows(MonicaCloudCryptoException.WrongKey::class.java) {
            MonicaCloudCrypto.unwrapUserKey(wrong.wrapKey, section("userKey").str("protectedUserKey"))
        }
    }

    @Test
    fun unknownFormatVersionIsRejected() {
        val key = MonicaCloudCrypto.generateKey()
        val enc = MonicaCloudCrypto.encryptString(key, "x")
        assertThrows(MonicaCloudCryptoException.UnsupportedFormat::class.java) {
            MonicaCloudCrypto.decryptString(key, "2" + enc.drop(1))
        }
    }

    @Test
    fun itemRoundTripKeepsItemKey() {
        val userKey = MonicaCloudCrypto.generateKey()
        val first = MonicaCloudCrypto.encryptItem(userKey, """{"v":1,"name":"a"}""")
        val itemKey = MonicaCloudCrypto.decryptItemKey(userKey, first.key)
        val second = MonicaCloudCrypto.encryptItem(userKey, """{"v":1,"name":"b"}""", itemKey)
        assertArrayEquals(itemKey, MonicaCloudCrypto.decryptItemKey(userKey, second.key))
        assertNotEquals(first.data, second.data)
        assertEquals("""{"v":1,"name":"b"}""", MonicaCloudCrypto.decryptString(itemKey, second.data))
    }

    @Test
    fun blobRoundTripAndSizes() {
        val key = MonicaCloudCrypto.generateKey()
        for (size in listOf(0, 1, 1024, 65_536, 65_537, 200_000)) {
            val plain = MonicaCloudCrypto.randomBytes(size)
            val sealed = MonicaCloudCrypto.encryptBlob(key, plain)
            assertEquals(MonicaCloudCrypto.encryptedBlobSize(size.toLong()), sealed.size.toLong())
            assertArrayEquals(plain, MonicaCloudCrypto.decryptBlob(key, sealed))
        }
    }

    @Test
    fun blobTruncationAndTamperingAreDetected() {
        val key = MonicaCloudCrypto.generateKey()
        val sealed = MonicaCloudCrypto.encryptBlob(key, MonicaCloudCrypto.randomBytes(140_000))
        val firstTwoChunks = 8 + 2 * (12 + 65_536 + 16)
        assertThrows(MonicaCloudCryptoException.WrongKey::class.java) {
            MonicaCloudCrypto.decryptBlob(key, sealed.copyOf(firstTwoChunks))
        }
        sealed[100] = (sealed[100].toInt() xor 1).toByte()
        assertThrows(MonicaCloudCryptoException.WrongKey::class.java) {
            MonicaCloudCrypto.decryptBlob(key, sealed)
        }
    }
}
