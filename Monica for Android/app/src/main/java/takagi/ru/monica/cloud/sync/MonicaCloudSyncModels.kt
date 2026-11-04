package takagi.ru.monica.cloud.sync

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest

/** Which local table a record lives in. Protocol types map onto these (protocol §2). */
enum class LocalKind {
    PASSWORD,
    SECURE_ITEM,
    PASSKEY;

    companion object {
        /** Local table for a protocol item type, or null when this client cannot store it. */
        fun forType(type: Int): LocalKind? = when (type) {
            1, 7, 8 -> PASSWORD
            2, 3, 4, 5, 9, 10 -> SECURE_ITEM
            6 -> PASSKEY
            else -> null
        }
    }
}

data class LocalRef(val kind: LocalKind, val id: String) {
    val key: String get() = "${kind.name}:$id"
}

/** A Monica-local entry as the protocol sees it: decrypted, with its payload already mapped. */
data class LocalRecord(
    val ref: LocalRef,
    val type: Int,
    val folderLocalId: String?,
    val favorite: Boolean,
    val archived: Boolean,
    val trashed: Boolean,
    val payload: JsonObject,
) {
    /**
     * Fingerprint of the protocol-visible content only (no `monica` section, no trash state).
     * Used to recognise the same entry on two sides before they were ever linked.
     */
    fun identityHash(): String = sha256(
        canonical(
            buildJsonObject {
                put("type", type)
                put("folder", folderLocalId)
                put("favorite", favorite)
                put("archived", archived)
                put("payload", JsonObject(payload - "monica"))
            },
        ),
    )

    /** Content fingerprint used to detect local edits since the last sync. Trash state is tracked separately. */
    fun contentHash(): String = sha256(
        canonical(
            buildJsonObject {
                put("type", type)
                put("folder", folderLocalId)
                put("favorite", favorite)
                put("archived", archived)
                put("payload", payload)
            },
        ),
    )
}

/** What the engine asks the local store to write. */
data class IncomingRecord(
    val type: Int,
    val folderLocalId: String?,
    val favorite: Boolean,
    val archived: Boolean,
    val trashed: Boolean,
    val payload: JsonObject,
)

data class LocalFolder(val id: String, val name: String)

/**
 * Local persistence the engine syncs against. The Android implementation maps Room entities
 * (PasswordEntry / SecureItem / PasskeyEntry / Category); tests use an in-memory map.
 * Only Monica-local entries are exposed: KeePass, Bitwarden and MDBX entries sync on their own.
 */
interface MonicaCloudLocalStore {
    suspend fun listRecords(): List<LocalRecord>

    /** Create a record; returns it as stored (the store may normalise the payload). */
    suspend fun createRecord(kind: LocalKind, record: IncomingRecord): LocalRecord

    /** Overwrite a record; returns it as stored, or null if it no longer exists. */
    suspend fun updateRecord(ref: LocalRef, record: IncomingRecord): LocalRecord?

    suspend fun deleteRecord(ref: LocalRef)

    /**
     * How [record] would look if it were stored as [kind], without writing anything. Lets the
     * engine compare a server item with existing local entries in the local representation.
     */
    suspend fun previewRecord(kind: LocalKind, record: IncomingRecord): LocalRecord?

    suspend fun listFolders(): List<LocalFolder>

    suspend fun createFolder(name: String): LocalFolder

    suspend fun renameFolder(id: String, name: String)
}

/** Sync bookkeeping: which local object corresponds to which server object, as of the last sync. */
data class CloudLink(
    val cloudId: String,
    /** `item` or `folder`. */
    val objectType: String,
    val localKind: LocalKind?,
    val localId: String,
    /** Server revisionDate last seen for this object (sent back as lastKnownRevisionDate). */
    val revision: String,
    /** [LocalRecord.contentHash] (items) or folder name hash at the last sync. */
    val contentHash: String,
    val trashed: Boolean = false,
    /** Item key as stored on the server (EncString under the account key), so edits keep it. */
    val encryptedItemKey: String? = null,
) {
    val localRef: LocalRef? get() = localKind?.let { LocalRef(it, localId) }

    companion object {
        const val ITEM = "item"
        const val FOLDER = "folder"
    }
}

interface MonicaCloudLinkStore {
    suspend fun all(): List<CloudLink>

    suspend fun upsert(link: CloudLink)

    suspend fun delete(cloudId: String)

    suspend fun clear()
}

data class MonicaCloudSyncResult(
    val cursor: String,
    val pulledCreated: Int = 0,
    val pulledUpdated: Int = 0,
    val pulledDeleted: Int = 0,
    val pushedCreated: Int = 0,
    val pushedUpdated: Int = 0,
    val pushedDeleted: Int = 0,
    val conflicts: Int = 0,
    val skippedUnsupported: Int = 0,
)

sealed class MonicaCloudSyncException(message: String) : Exception(message) {
    /** The server account was recreated or the app is pointed at another account. */
    class AccountMismatch : MonicaCloudSyncException("server account changed; log in again")

    /** The server suddenly reports an empty vault while many items were synced before. */
    class SuspiciousEmptyVault(val linkedItems: Int) :
        MonicaCloudSyncException("server returned an empty vault but $linkedItems items were synced before")
}

// ---------------------------------------------------------------------------

internal fun sha256(text: String): String =
    MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

/** JSON with object keys sorted recursively, so equal content always hashes equally. */
internal fun canonical(element: JsonElement): String = when (element) {
    is JsonObject -> element.entries.sortedBy { it.key }
        .joinToString(",", "{", "}") { (k, v) -> "${JsonPrimitive(k)}:${canonical(v)}" }
    is JsonArray -> element.joinToString(",", "[", "]") { canonical(it) }
    else -> element.toString()
}
