package takagi.ru.monica.cloud

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import takagi.ru.monica.cloud.api.DeviceDto
import takagi.ru.monica.cloud.api.ItemWriteRequest
import takagi.ru.monica.cloud.api.MonicaCloudApiException
import takagi.ru.monica.cloud.api.MonicaCloudClient
import takagi.ru.monica.cloud.api.TokenResponse
import takagi.ru.monica.cloud.crypto.MonicaCloudCrypto
import java.io.ByteArrayOutputStream

/**
 * Runs the Android client code against a real Monica Cloud server. Skipped unless
 * `MONICA_CLOUD_URL` is set, e.g.
 *
 *   MONICA_CLOUD_URL=http://127.0.0.1:8000 ./gradlew :app:testDebugUnitTest --tests '*MonicaCloudInteropTest*'
 *
 * With `MONICA_CLOUD_SEED_EMAIL` / `MONICA_CLOUD_SEED_PASSWORD` it also decrypts a vault that the
 * WebUI (WebCrypto) wrote, proving both clients read each other's data.
 */
class MonicaCloudInteropTest {
    private val url = System.getenv("MONICA_CLOUD_URL")
    private val password = "correct horse battery staple"
    private val device = DeviceDto(identifier = "interop-${System.nanoTime()}", name = "JVM interop test", type = "android", appVersion = "test")

    @Before
    fun requireServer() {
        assumeTrue("MONICA_CLOUD_URL not set", !url.isNullOrBlank())
    }

    @Test
    fun fullClientRoundTrip() = runBlocking {
        val email = "android-${System.nanoTime()}@example.com"
        val persisted = mutableListOf<TokenResponse?>()
        val client = MonicaCloudClient(url!!, onSessionChanged = { persisted += it })

        assertEquals(1, client.config().protocolVersion)
        client.register(email, "Android", password, 100_000)
        val login = client.login(email, password, device)
        val userKey = login.userKey
        assertArrayEquals(userKey, client.unlock(password))

        // Empty vault, then one folder and one item.
        val first = client.sync()
        assertTrue(first.full)
        val folder = client.createFolder(MonicaCloudCrypto.encryptString(userKey, "开发"))
        val payload = """{"v":1,"name":"GitHub","login":{"username":"octocat","password":"hunter2"},"monica":{"sortOrder":3}}"""
        val encrypted = MonicaCloudCrypto.encryptItem(userKey, payload)
        val created = client.createItem(ItemWriteRequest(type = 1, folderId = folder.id, key = encrypted.key, data = encrypted.data))
        assertFalse(created.data.contains("hunter2"))

        val delta = client.sync(first.revisionDate)
        assertFalse(delta.full)
        assertEquals(listOf(created.id), delta.items.map { it.id })
        val itemKey = MonicaCloudCrypto.decryptItemKey(userKey, delta.items[0].key)
        assertEquals(payload, MonicaCloudCrypto.decryptString(itemKey, delta.items[0].data))
        assertEquals("开发", MonicaCloudCrypto.decryptString(userKey, delta.folders[0].name))

        // Optimistic concurrency: a stale edit gets 409 plus the server copy.
        val edit = MonicaCloudCrypto.encryptItem(userKey, """{"v":1,"name":"GitHub (A)"}""", itemKey)
        val updated = client.updateItem(created.id, ItemWriteRequest(type = 1, folderId = folder.id, key = edit.key, data = edit.data, lastKnownRevisionDate = created.revisionDate))
        try {
            client.updateItem(created.id, ItemWriteRequest(type = 1, key = edit.key, data = edit.data, lastKnownRevisionDate = created.revisionDate))
            fail("expected conflict")
        } catch (e: MonicaCloudApiException) {
            assertTrue(e.isConflict)
            assertEquals(updated.revisionDate, e.currentItem()?.revisionDate)
        }

        // Attachment round trip through the chunked format.
        val content = MonicaCloudCrypto.randomBytes(150_000)
        val withFile = client.uploadAttachment(created.id, itemKey, "recovery.txt", content).item
        val out = ByteArrayOutputStream()
        val name = client.downloadAttachment(created.id, itemKey, withFile.attachments.single(), out)
        assertEquals("recovery.txt", name)
        assertArrayEquals(content, out.toByteArray())

        // Refresh rotates the token and the new pair is handed to the app for persistence.
        val before = client.session!!.refreshToken
        client.refresh()
        assertNotEquals(before, client.session!!.refreshToken)
        assertEquals(client.session, persisted.last())

        // Permanent delete shows up as a tombstone.
        val cursor = client.sync().revisionDate
        client.deleteItem(created.id)
        val gone = client.sync(cursor)
        assertEquals(listOf("item" to created.id), gone.deleted.map { it.type to it.id })

        client.logout()
        assertEquals(null, persisted.last())
    }

    @Test
    fun readsVaultWrittenByWebUi() = runBlocking {
        val seedEmail = System.getenv("MONICA_CLOUD_SEED_EMAIL")
        val seedPassword = System.getenv("MONICA_CLOUD_SEED_PASSWORD")
        assumeTrue("seed account not configured", !seedEmail.isNullOrBlank() && !seedPassword.isNullOrBlank())

        val client = MonicaCloudClient(url!!)
        val userKey = client.login(seedEmail!!, seedPassword!!, device).userKey
        val sync = client.sync()
        assertTrue(sync.items.isNotEmpty())
        val names = sync.items.map { item ->
            val itemKey = MonicaCloudCrypto.decryptItemKey(userKey, item.key)
            val json = Json.parseToJsonElement(MonicaCloudCrypto.decryptString(itemKey, item.data)).jsonObject
            if (json["name"]!!.jsonPrimitive.content == "GitHub") {
                assertEquals("gh-9xK!2mPq#Lw", json["login"]!!.jsonObject["password"]!!.jsonPrimitive.content)
                val attachment = item.attachments.single()
                val out = ByteArrayOutputStream()
                assertEquals("github-recovery-codes.txt", client.downloadAttachment(item.id, itemKey, attachment, out))
                assertEquals("abcd-efgh\nijkl-mnop\n", out.toString(Charsets.UTF_8.name()))
            }
            json["name"]!!.jsonPrimitive.content
        }
        assertTrue("GitHub" in names)
        assertNotNull(sync.folders.firstOrNull { MonicaCloudCrypto.decryptString(userKey, it.name) == "财务" })
        client.logout()
    }
}
