package takagi.ru.monica.cloud.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import takagi.ru.monica.cloud.mapper.MonicaCloudEntityMapper
import takagi.ru.monica.cloud.sync.CloudLink
import takagi.ru.monica.cloud.sync.IncomingRecord
import takagi.ru.monica.cloud.sync.LocalFolder
import takagi.ru.monica.cloud.sync.LocalKind
import takagi.ru.monica.cloud.sync.LocalRecord
import takagi.ru.monica.cloud.sync.LocalRef
import takagi.ru.monica.cloud.sync.MonicaCloudLinkStore
import takagi.ru.monica.cloud.sync.MonicaCloudLocalStore
import takagi.ru.monica.data.Category
import takagi.ru.monica.data.CustomField
import takagi.ru.monica.data.PasskeyEntry
import takagi.ru.monica.data.PasswordDatabase
import takagi.ru.monica.data.PasswordEntry
import takagi.ru.monica.data.SecureItem
import takagi.ru.monica.passkey.PasskeyPrivateKeyStore
import takagi.ru.monica.passkey.PasskeyPrivateKeySupport
import takagi.ru.monica.security.SecurityManager

/**
 * [MonicaCloudLocalStore] over Monica's Room tables.
 *
 * - Only Monica-local entries take part (no KeePass / Bitwarden / MDBX owner).
 * - Passwords are stored encrypted with [SecurityManager] exactly like the editor does; other
 *   fields are read through `decryptDataIfMonicaCiphertext` so legacy encrypted values work too.
 * - Passkey private keys go through [PasskeyPrivateKeyStore]; a key that only exists in Android
 *   Keystore is never overwritten by a payload without one.
 * - Flags a table cannot represent (passkey favorite/trash, secure-item archive) and payload keys
 *   from other clients are kept in `monica_cloud_payload_extras`.
 */
class MonicaCloudRoomStore(
    private val context: Context,
    private val database: PasswordDatabase,
    private val securityManager: SecurityManager,
) : MonicaCloudLocalStore {
    private val dao = database.monicaCloudDao()
    private val passwordDao = database.passwordEntryDao()
    private val secureDao = database.secureItemDao()
    private val passkeyDao = database.passkeyDao()
    private val customFieldDao = database.customFieldDao()
    private val categoryDao = database.categoryDao()
    private val mapper = MonicaCloudEntityMapper
    private val json = Json { ignoreUnknownKeys = true }

    /** Per-record side data: foreign payload keys and flags the table has no column for. */
    private data class Extra(
        val foreign: JsonObject = JsonObject(emptyMap()),
        val favorite: Boolean? = null,
        val archived: Boolean? = null,
        val trashed: Boolean? = null,
    )

    // ------------------------------------------------------------------ records

    override suspend fun listRecords(): List<LocalRecord> = withContext(Dispatchers.IO) {
        val extras = loadExtras()
        val passwords = dao.localPasswords()
        val passwordIds = passwords.map { it.id }.toHashSet()
        val fields = customFieldDao.getAllFieldsSync().filter { it.entryId in passwordIds }.groupBy { it.entryId }
        buildList {
            for (entry in passwords) add(passwordRecord(plain(entry), fields[entry.id].orEmpty(), extras))
            for (item in dao.localSecureItems()) secureRecord(plain(item), extras)?.let(::add)
            for (passkey in dao.localPasskeys()) add(passkeyRecord(passkey, extras))
        }
    }

    override suspend fun createRecord(kind: LocalKind, record: IncomingRecord): LocalRecord = withContext(Dispatchers.IO) {
        write(kind, null, record) ?: error("cannot store item type ${record.type} as $kind")
    }

    override suspend fun updateRecord(ref: LocalRef, record: IncomingRecord): LocalRecord? = withContext(Dispatchers.IO) {
        val id = ref.id.toLongOrNull() ?: return@withContext null
        val exists = when (ref.kind) {
            LocalKind.PASSWORD -> passwordDao.getPasswordEntryById(id) != null
            LocalKind.SECURE_ITEM -> secureDao.getItemById(id) != null
            LocalKind.PASSKEY -> passkeyDao.getPasskeyByRecordId(id) != null
        }
        if (!exists) null else write(ref.kind, id, record)
    }

    override suspend fun deleteRecord(ref: LocalRef) = withContext(Dispatchers.IO) {
        val id = ref.id.toLongOrNull() ?: return@withContext
        when (ref.kind) {
            LocalKind.PASSWORD -> passwordDao.deletePasswordEntryById(id) // custom fields cascade
            LocalKind.SECURE_ITEM -> secureDao.deleteItemById(id)
            LocalKind.PASSKEY -> passkeyDao.deleteByRecordId(id)
        }
        dao.deleteExtra(ref.key)
    }

    override suspend fun previewRecord(kind: LocalKind, record: IncomingRecord): LocalRecord? = withContext(Dispatchers.Default) {
        val categoryId = record.folderLocalId?.toLongOrNull()
        val none = emptyMap<String, Extra>()
        when (kind) {
            LocalKind.PASSWORD -> {
                val (entry, fields) = mapper.applyPassword(
                    null, record.type, record.payload, record.favorite, record.archived, record.trashed, categoryId,
                )
                passwordRecord(entry, fields, none)
            }
            LocalKind.SECURE_ITEM -> mapper.applySecure(null, record.type, record.payload, record.favorite, record.trashed, categoryId)
                ?.let { secureRecord(it, none)?.copy(archived = record.archived) }
            LocalKind.PASSKEY -> mapper.applyPasskey(null, record.payload, categoryId)?.let { (entry, key) ->
                LocalRecord(
                    ref = LocalRef(kind, "preview"),
                    type = MonicaCloudEntityMapper.TYPE_PASSKEY,
                    folderLocalId = entry.categoryId?.toString(),
                    favorite = record.favorite,
                    archived = record.archived,
                    trashed = record.trashed,
                    payload = mapper.passkeyPayload(entry, key),
                )
            }
        }
    }

    private suspend fun write(kind: LocalKind, id: Long?, record: IncomingRecord): LocalRecord? {
        val categoryId = record.folderLocalId?.toLongOrNull()
        return when (kind) {
            LocalKind.PASSWORD -> {
                val base = id?.let { passwordDao.getPasswordEntryById(it) }?.let(::plain)
                val (entry, fields) = mapper.applyPassword(
                    base, record.type, record.payload, record.favorite, record.archived, record.trashed, categoryId,
                )
                val encrypted = entry.copy(password = securityManager.encryptData(entry.password))
                val savedId = if (id == null) {
                    passwordDao.insertPasswordEntry(encrypted.copy(id = 0))
                } else {
                    passwordDao.updatePasswordEntry(encrypted)
                    id
                }
                val savedFields = fields.map { it.copy(id = 0, entryId = savedId) }
                customFieldDao.replaceFieldsForEntry(savedId, savedFields)
                val ref = LocalRef(kind, savedId.toString())
                val extras = saveExtra(ref, Extra(foreign = mapper.foreignKeys(record.payload)))
                passwordRecord(entry.copy(id = savedId), savedFields, extras)
            }
            LocalKind.SECURE_ITEM -> {
                val base = id?.let { secureDao.getItemById(it) }?.let(::plain)
                val item = mapper.applySecure(base, record.type, record.payload, record.favorite, record.trashed, categoryId)
                    ?: return null
                val savedId = if (id == null) secureDao.insertItem(item.copy(id = 0)) else id.also { secureDao.updateItem(item) }
                val ref = LocalRef(kind, savedId.toString())
                val extras = saveExtra(ref, Extra(foreign = mapper.foreignKeys(record.payload), archived = record.archived))
                secureRecord(item.copy(id = savedId), extras)
            }
            LocalKind.PASSKEY -> {
                val base = id?.let { passkeyDao.getPasskeyByRecordId(it) }
                val (entry, key) = mapper.applyPasskey(base, record.payload, categoryId) ?: return null
                val alias = key?.let {
                    PasskeyPrivateKeyStore.protectForStorage(context, entry.credentialId, entry.rpId, entry.userId, it)
                } ?: base?.privateKeyAlias.orEmpty()
                val stored = entry.copy(privateKeyAlias = alias)
                val savedId = if (id == null) dao.insertPasskey(stored.copy(id = 0)) else id.also { passkeyDao.update(stored) }
                val ref = LocalRef(kind, savedId.toString())
                val extras = saveExtra(
                    ref,
                    Extra(
                        foreign = mapper.foreignKeys(record.payload),
                        favorite = record.favorite,
                        archived = record.archived,
                        trashed = record.trashed,
                    ),
                )
                passkeyRecord(stored.copy(id = savedId), extras)
            }
        }
    }

    // ------------------------------------------------------------------ mapping to records

    private fun passwordRecord(entry: PasswordEntry, fields: List<CustomField>, extras: Map<String, Extra>): LocalRecord {
        val ref = LocalRef(LocalKind.PASSWORD, entry.id.toString())
        return LocalRecord(
            ref = ref,
            type = mapper.passwordType(entry),
            folderLocalId = entry.categoryId?.toString(),
            favorite = entry.isFavorite,
            archived = entry.isArchived,
            trashed = entry.isDeleted,
            payload = mapper.withForeignKeys(mapper.passwordPayload(entry, fields), extras[ref.key]?.foreign),
        )
    }

    private fun secureRecord(item: SecureItem, extras: Map<String, Extra>): LocalRecord? {
        val type = mapper.secureType(item.itemType) ?: return null
        val ref = LocalRef(LocalKind.SECURE_ITEM, item.id.toString())
        val extra = extras[ref.key]
        return LocalRecord(
            ref = ref,
            type = type,
            folderLocalId = item.categoryId?.toString(),
            favorite = item.isFavorite,
            archived = extra?.archived ?: false,
            trashed = item.isDeleted,
            payload = mapper.withForeignKeys(mapper.securePayload(item), extra?.foreign),
        )
    }

    private fun passkeyRecord(entry: PasskeyEntry, extras: Map<String, Extra>): LocalRecord {
        val ref = LocalRef(LocalKind.PASSKEY, entry.id.toString())
        val extra = extras[ref.key]
        val pkcs8 = runCatching {
            PasskeyPrivateKeySupport.exportPkcs8Base64(PasskeyPrivateKeyStore.resolve(securityManager, entry.privateKeyAlias))
        }.getOrNull()
        return LocalRecord(
            ref = ref,
            type = MonicaCloudEntityMapper.TYPE_PASSKEY,
            folderLocalId = entry.categoryId?.toString(),
            favorite = extra?.favorite ?: false,
            archived = extra?.archived ?: false,
            trashed = extra?.trashed ?: false,
            payload = mapper.withForeignKeys(mapper.passkeyPayload(entry, pkcs8), extra?.foreign),
        )
    }

    private fun decrypt(value: String): String =
        runCatching { securityManager.decryptDataIfMonicaCiphertext(value) }.getOrDefault(value)

    private fun plain(entry: PasswordEntry) = entry.copy(password = decrypt(entry.password))

    private fun plain(item: SecureItem) = item.copy(itemData = decrypt(item.itemData))

    // ------------------------------------------------------------------ extras

    private suspend fun loadExtras(): Map<String, Extra> = dao.allExtras().associate { row ->
        val obj = runCatching { json.parseToJsonElement(row.extras).jsonObject }.getOrDefault(JsonObject(emptyMap()))
        row.localKey to Extra(
            foreign = (obj["foreign"] as? JsonObject) ?: JsonObject(emptyMap()),
            favorite = (obj["favorite"] as? JsonPrimitive)?.booleanOrNull,
            archived = (obj["archived"] as? JsonPrimitive)?.booleanOrNull,
            trashed = (obj["trashed"] as? JsonPrimitive)?.booleanOrNull,
        )
    }

    private suspend fun saveExtra(ref: LocalRef, extra: Extra): Map<String, Extra> {
        val empty = extra.foreign.isEmpty() && extra.favorite != true && extra.archived != true && extra.trashed != true
        if (empty) {
            dao.deleteExtra(ref.key)
        } else {
            val encoded = buildJsonObject {
                if (extra.foreign.isNotEmpty()) put("foreign", extra.foreign)
                extra.favorite?.let { put("favorite", it) }
                extra.archived?.let { put("archived", it) }
                extra.trashed?.let { put("trashed", it) }
            }
            dao.upsertExtra(MonicaCloudPayloadExtraEntity(ref.key, encoded.toString()))
        }
        return mapOf(ref.key to extra)
    }

    // ------------------------------------------------------------------ folders

    override suspend fun listFolders(): List<LocalFolder> = withContext(Dispatchers.IO) {
        dao.localCategories().map { LocalFolder(it.id.toString(), it.name) }
    }

    override suspend fun createFolder(name: String): LocalFolder = withContext(Dispatchers.IO) {
        val id = categoryDao.insert(Category(name = name))
        LocalFolder(id.toString(), name)
    }

    override suspend fun renameFolder(id: String, name: String) = withContext(Dispatchers.IO) {
        val category = id.toLongOrNull()?.let { categoryDao.getCategoryById(it) } ?: return@withContext
        categoryDao.update(category.copy(name = name))
    }
}

/** [MonicaCloudLinkStore] over the `monica_cloud_links` table. */
class MonicaCloudRoomLinkStore(private val dao: MonicaCloudDao) : MonicaCloudLinkStore {
    override suspend fun all(): List<CloudLink> = withContext(Dispatchers.IO) {
        dao.allLinks().map {
            CloudLink(
                cloudId = it.cloudId,
                objectType = it.objectType,
                localKind = it.localKind?.let { kind -> runCatching { LocalKind.valueOf(kind) }.getOrNull() },
                localId = it.localId,
                revision = it.revision,
                contentHash = it.contentHash,
                trashed = it.trashed,
                encryptedItemKey = it.encryptedItemKey,
            )
        }
    }

    override suspend fun upsert(link: CloudLink) = withContext(Dispatchers.IO) {
        dao.upsertLink(
            MonicaCloudLinkEntity(
                cloudId = link.cloudId,
                objectType = link.objectType,
                localKind = link.localKind?.name,
                localId = link.localId,
                revision = link.revision,
                contentHash = link.contentHash,
                trashed = link.trashed,
                encryptedItemKey = link.encryptedItemKey,
            ),
        )
    }

    override suspend fun delete(cloudId: String) = withContext(Dispatchers.IO) { dao.deleteLink(cloudId) }

    override suspend fun clear() = withContext(Dispatchers.IO) {
        dao.clearLinks()
        dao.clearExtras()
    }
}
