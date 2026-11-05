package takagi.ru.monica.cloud

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import takagi.ru.monica.cloud.api.DeviceDto
import takagi.ru.monica.cloud.api.MonicaCloudClient
import takagi.ru.monica.cloud.sync.CloudLink
import takagi.ru.monica.cloud.sync.IncomingRecord
import takagi.ru.monica.cloud.sync.LocalAttachment
import takagi.ru.monica.cloud.sync.LocalFolder
import takagi.ru.monica.cloud.sync.LocalKind
import takagi.ru.monica.cloud.sync.LocalRecord
import takagi.ru.monica.cloud.sync.LocalRef
import takagi.ru.monica.cloud.sync.MonicaCloudLinkStore
import takagi.ru.monica.cloud.sync.MonicaCloudLocalStore
import takagi.ru.monica.cloud.sync.MonicaCloudSyncEngine
import takagi.ru.monica.cloud.sync.MonicaCloudSyncException
import takagi.ru.monica.cloud.sync.MonicaCloudSyncResult

/**
 * Several simulated devices sync one account through a real server. Skipped unless
 * MONICA_CLOUD_URL is set (see MonicaCloudInteropTest).
 */
class MonicaCloudSyncEngineTest {
    private val url = System.getenv("MONICA_CLOUD_URL")
    private val password = "correct horse battery staple"
    private lateinit var email: String

    @Before
    fun setUp() {
        assumeTrue("MONICA_CLOUD_URL not set", !url.isNullOrBlank())
        email = "sync-${System.nanoTime()}@example.com"
        runBlocking { MonicaCloudClient(url!!).register(email, "Sync", password, 100_000) }
    }

    /** One phone: an in-memory vault plus its own sync bookkeeping. */
    private inner class Device(name: String) {
        val records = linkedMapOf<String, LocalRecord>()
        val files = linkedMapOf<String, Pair<LocalAttachment, ByteArray>>()
        val folders = linkedMapOf<String, LocalFolder>()
        private val linkMap = linkedMapOf<String, CloudLink>()
        private var nextId = 1
        var cursor: String? = null
        val client = MonicaCloudClient(url!!)
        private val login = runBlocking { client.login(email, password, DeviceDto("dev-$name-${System.nanoTime()}", name)) }

        val store = object : MonicaCloudLocalStore {
            override suspend fun listRecords() = records.values.toList()
            // Like the Room store, stored records carry a client-specific `monica` section that a
            // server copy written by another client (the WebUI) does not have.
            override suspend fun createRecord(kind: LocalKind, record: IncomingRecord): LocalRecord =
                record.stamped().toLocal(LocalRef(kind, (nextId++).toString())).also { records[it.ref.key] = it }

            override suspend fun updateRecord(ref: LocalRef, record: IncomingRecord): LocalRecord? {
                if (ref.key !in records) return null
                return record.stamped().toLocal(ref).also { records[ref.key] = it }
            }

            override suspend fun previewRecord(kind: LocalKind, record: IncomingRecord): LocalRecord =
                record.stamped().toLocal(LocalRef(kind, "preview"))

            override suspend fun deleteRecord(ref: LocalRef) {
                records.remove(ref.key)
            }

            override suspend fun listFolders() = folders.values.toList()
            override suspend fun createFolder(name: String) = LocalFolder("f${nextId++}", name).also { folders[it.id] = it }
            override suspend fun renameFolder(id: String, name: String) {
                folders[id] = LocalFolder(id, name)
            }

            override suspend fun listAttachments() =
                files.values.map { it.first }.filter { it.owner.key in records }

            override suspend fun readAttachment(id: String) = files.getValue(id).second

            override suspend fun createAttachment(owner: LocalRef, fileName: String, content: ByteArray): LocalAttachment =
                LocalAttachment("a${nextId++}", owner, fileName, content.size.toLong()).also { files[it.id] = it to content }

            override suspend fun deleteAttachment(id: String) {
                files.remove(id)
            }
        }

        fun attach(entry: String, fileName: String, content: String) = runBlocking {
            store.createAttachment(byName(entry)!!.ref, fileName, content.toByteArray())
        }

        fun filesOf(entry: String) = files.values
            .filter { it.first.owner == byName(entry)?.ref }
            .associate { it.first.fileName to String(it.second) }

        val links = object : MonicaCloudLinkStore {
            override suspend fun all() = linkMap.values.toList()
            override suspend fun upsert(link: CloudLink) {
                linkMap[link.cloudId] = link
            }

            override suspend fun delete(cloudId: String) {
                linkMap.remove(cloudId)
            }

            override suspend fun clear() = linkMap.clear()
        }

        fun sync(allowEmpty: Boolean = false): MonicaCloudSyncResult = runBlocking {
            MonicaCloudSyncEngine(client, store, links, " (冲突副本)")
                .sync(login.userKey, login.session.account.id, cursor, allowEmpty)
                .also { cursor = it.cursor }
        }

        fun add(name: String, type: Int = 1, folder: String? = null, secret: String = "pw-$name"): LocalRecord {
            val folderId = folder?.let { f -> folders.values.firstOrNull { it.name == f }?.id ?: runBlocking { store.createFolder(f) }.id }
            val kind = LocalKind.forType(type)!!
            return runBlocking { store.createRecord(kind, IncomingRecord(type, folderId, false, false, false, payload(name, secret))) }
        }

        fun byName(name: String) = records.values.singleOrNull { it.payload["name"]?.jsonPrimitive?.content == name }

        fun names() = records.values.map { it.payload["name"]!!.jsonPrimitive.content }.sorted()

        fun edit(name: String, change: (LocalRecord) -> LocalRecord) {
            val record = byName(name)!!
            records[record.ref.key] = change(record)
        }

        fun folderOf(name: String) = byName(name)?.folderLocalId?.let { folders[it]?.name }
    }

    private fun payload(name: String, secret: String): JsonObject = buildJsonObject {
        put("v", 1)
        put("name", name)
        put("login", buildJsonObject { put("username", "user"); put("password", secret) })
    }

    private fun IncomingRecord.toLocal(ref: LocalRef) = LocalRecord(ref, type, folderLocalId, favorite, archived, trashed, payload)

    private fun IncomingRecord.stamped(): IncomingRecord =
        copy(payload = JsonObject(payload + ("monica" to buildJsonObject { put("kind", "test"); put("stored", true) })))

    private fun LocalRecord.withSecret(secret: String) =
        copy(payload = payload(payload["name"]!!.jsonPrimitive.content, secret))

    private fun LocalRecord.secret() = (payload["login"] as JsonObject)["password"]!!.jsonPrimitive.content

    @Test
    fun devicesConverge() {
        val a = Device("A")
        val b = Device("B")

        // Upload from A, download on B, including folders and types.
        a.add("GitHub", folder = "开发")
        a.add("Wi-Fi", type = 7)
        a.add("Note", type = 2)
        val first = a.sync()
        assertEquals(3, first.pushedCreated)
        val pulled = b.sync()
        assertEquals(3, pulled.pulledCreated)
        assertEquals(a.names(), b.names())
        assertEquals("开发", b.folderOf("GitHub"))
        assertEquals(LocalKind.SECURE_ITEM, b.byName("Note")!!.ref.kind)

        // Nothing changes when nothing changed.
        val idle = a.sync()
        assertEquals(0, idle.pulledUpdated + idle.pushedUpdated + idle.pushedCreated)

        // Edit on B shows up on A.
        b.edit("GitHub") { it.withSecret("new-secret") }
        assertEquals(1, b.sync().pushedUpdated)
        assertEquals(1, a.sync().pulledUpdated)
        assertEquals("new-secret", a.byName("GitHub")!!.secret())

        // Concurrent edits: A wins on the server, B keeps its version as a conflict copy.
        a.edit("GitHub") { it.withSecret("from-A") }
        b.edit("GitHub") { it.withSecret("from-B") }
        a.sync()
        val conflict = b.sync()
        assertEquals(1, conflict.conflicts)
        assertEquals("from-A", b.byName("GitHub")!!.secret())
        assertEquals("from-B", b.byName("GitHub (冲突副本)")!!.secret())
        b.sync() // uploads the copy
        a.sync()
        assertEquals(b.names(), a.names())

        // Trash and permanent delete propagate.
        a.edit("Wi-Fi") { it.copy(trashed = true) }
        a.sync()
        b.sync()
        assertTrue(b.byName("Wi-Fi")!!.trashed)
        a.records.remove(a.byName("Wi-Fi")!!.ref.key)
        assertEquals(1, a.sync().pushedDeleted)
        assertEquals(1, b.sync().pulledDeleted)
        assertNull(b.byName("Wi-Fi"))

        // Folder rename travels too.
        val folderId = a.folders.values.single { it.name == "开发" }.id
        a.folders[folderId] = LocalFolder(folderId, "Dev")
        a.sync()
        b.sync()
        assertEquals("Dev", b.folderOf("GitHub"))
    }

    @Test
    fun attachmentsSyncBothWays() {
        val a = Device("A")
        val b = Device("B")
        a.add("GitHub")
        a.attach("GitHub", "codes.txt", "abcd-1234")
        val first = a.sync()
        assertEquals(1, first.pushedAttachments)

        // Downloaded and stored on the other device.
        assertEquals(1, b.sync().pulledAttachments)
        assertEquals(mapOf("codes.txt" to "abcd-1234"), b.filesOf("GitHub"))

        // Nothing moves when nothing changed (uploads must not look like remote edits).
        val idle = a.sync()
        assertEquals(0, idle.pulledUpdated + idle.pulledAttachments + idle.pushedAttachments)

        // Added on B, deleted on B → mirrored on A.
        b.attach("GitHub", "photo.jpg", "jpeg-bytes")
        b.sync()
        a.sync()
        assertEquals(setOf("codes.txt", "photo.jpg"), a.filesOf("GitHub").keys)
        b.files.entries.removeIf { it.value.first.fileName == "codes.txt" }
        assertEquals(1, b.sync().pushedAttachments)
        a.sync()
        assertEquals(setOf("photo.jpg"), a.filesOf("GitHub").keys)

        // Trashing the entry keeps its attachments on the server.
        a.edit("GitHub") { it.copy(trashed = true) }
        a.sync()
        b.sync()
        assertTrue(b.byName("GitHub")!!.trashed)
        assertEquals(setOf("photo.jpg"), b.filesOf("GitHub").keys)
    }

    @Test
    fun firstLoginAdoptsIdenticalLocalData() {
        val a = Device("A")
        a.add("Shared", secret = "same")
        a.sync()

        // C already has the same entry locally (e.g. restored from a backup) plus one of its own.
        val c = Device("C")
        c.add("Shared", secret = "same")
        c.add("Only on C")
        val result = c.sync()
        assertEquals(0, result.pulledCreated)
        assertEquals(1, result.pushedCreated)
        assertEquals(listOf("Only on C", "Shared"), c.names())
        a.sync()
        assertEquals(listOf("Only on C", "Shared"), a.names())
    }

    @Test
    fun signingOutAndBackInDoesNotDuplicateItemsFromOtherClients() = runBlocking {
        // Items written by another client (no `monica` section on the server).
        val web = Device("Web")
        val key = web.client.unlock(password)
        for (name in listOf("A", "B", "C")) {
            val enc = takagi.ru.monica.cloud.crypto.MonicaCloudCrypto.encryptItem(key, payload(name, "pw-$name").toString())
            web.client.createItem(takagi.ru.monica.cloud.api.ItemWriteRequest(type = 1, key = enc.key, data = enc.data))
        }
        val phone = Device("Phone")
        assertEquals(3, phone.sync().pulledCreated)
        // Sign out: links are forgotten, local entries stay.
        phone.links.clear()
        phone.cursor = null
        val again = phone.sync()
        assertEquals(0, again.pulledCreated)
        assertEquals(0, again.pushedCreated)
        assertEquals(listOf("A", "B", "C"), phone.names())
        assertEquals(3, web.client.sync().items.size)
    }

    @Test
    fun editWinsOverRemoteDelete() {
        val a = Device("A")
        val b = Device("B")
        a.add("Keep me")
        a.sync()
        b.sync()
        a.records.clear()
        a.sync() // deletes on server
        b.edit("Keep me") { it.withSecret("edited") }
        b.sync()
        assertEquals("edited", b.byName("Keep me")!!.secret())
        a.sync()
        assertEquals("edited", a.byName("Keep me")!!.secret())
    }

    @Test
    fun emptyServerVaultIsNotTrustedBlindly() {
        val a = Device("A")
        repeat(MonicaCloudSyncEngine.EMPTY_VAULT_THRESHOLD) { a.add("Item $it") }
        a.sync()
        // Another device wipes everything on the server.
        val b = Device("B")
        b.sync()
        b.records.clear()
        b.sync()
        a.cursor = null // force a full sync
        assertThrows(MonicaCloudSyncException.SuspiciousEmptyVault::class.java) { a.sync() }
        assertEquals(MonicaCloudSyncEngine.EMPTY_VAULT_THRESHOLD, a.records.size)
        a.sync(allowEmpty = true)
        assertTrue(a.records.isEmpty())
    }

    @Test
    fun unsupportedTypesAreLeftAlone(): Unit = runBlocking {
        val a = Device("A")
        val key = a.client.unlock(password)
        val enc = takagi.ru.monica.cloud.crypto.MonicaCloudCrypto.encryptItem(key, payload("Future", "x").toString())
        a.client.createItem(takagi.ru.monica.cloud.api.ItemWriteRequest(type = 42, key = enc.key, data = enc.data))
        val result = a.sync()
        assertEquals(1, result.skippedUnsupported)
        assertTrue(a.records.isEmpty())
        assertEquals(JsonPrimitive(1), payload("x", "y")["v"])
    }
}
