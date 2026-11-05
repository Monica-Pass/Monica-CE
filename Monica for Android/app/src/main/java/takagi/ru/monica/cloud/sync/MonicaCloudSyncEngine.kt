package takagi.ru.monica.cloud.sync

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import takagi.ru.monica.cloud.api.ImportFolderRequest
import takagi.ru.monica.cloud.api.ImportRequest
import takagi.ru.monica.cloud.api.ItemDto
import takagi.ru.monica.cloud.api.ItemWriteRequest
import takagi.ru.monica.cloud.api.MonicaCloudApiException
import takagi.ru.monica.cloud.api.MonicaCloudClient
import takagi.ru.monica.cloud.crypto.MonicaCloudCrypto

/**
 * Two-way sync of the Monica-local vault with one Monica Cloud account (protocol §5).
 *
 * Rules:
 * - Change detection compares each record's [LocalRecord.contentHash] with the hash stored in its
 *   [CloudLink] at the last sync, and the server revisionDate with the stored revision.
 * - Both sides changed → the server copy wins locally and the local version is kept as a new
 *   "conflict copy" record, which uploads as a separate item. Nothing is lost.
 * - Deleted on one side, edited on the other → the edit wins.
 * - A full sync that suddenly returns an empty vault aborts ([MonicaCloudSyncException.SuspiciousEmptyVault]).
 *
 * Pure Kotlin: storage is behind [MonicaCloudLocalStore] / [MonicaCloudLinkStore].
 */
class MonicaCloudSyncEngine(
    private val client: MonicaCloudClient,
    private val store: MonicaCloudLocalStore,
    private val links: MonicaCloudLinkStore,
    /** Appended to the name of a conflict copy, e.g. " (冲突副本)". */
    private val conflictSuffix: String = " (conflict copy)",
) {
    private val json = Json { ignoreUnknownKeys = true }

    private class Remote(val dto: ItemDto, val payload: JsonObject)

    private class RemoteFolder(val id: String, val name: String, val revision: String)

    /**
     * Run one sync. [cursor] is the revisionDate from the previous result (null for the first
     * sync); [accountId] guards against a recreated server account.
     */
    suspend fun sync(
        userKey: ByteArray,
        accountId: String,
        cursor: String?,
        allowEmptyRemote: Boolean = false,
    ): MonicaCloudSyncResult {
        var result = MonicaCloudSyncResult(cursor = cursor.orEmpty())
        val remote = client.sync(cursor)
        if (remote.profile.id != accountId) throw MonicaCloudSyncException.AccountMismatch()

        val allLinks = links.all()
        val itemLinks = allLinks.filter { it.objectType == CloudLink.ITEM }.associateBy { it.cloudId }.toMutableMap()
        if (remote.full && remote.items.isEmpty() && itemLinks.size >= EMPTY_VAULT_THRESHOLD && !allowEmptyRemote) {
            throw MonicaCloudSyncException.SuspiciousEmptyVault(itemLinks.size)
        }

        // ---------------------------------------------------------------- folders
        val folderMap = FolderMap(allLinks.filter { it.objectType == CloudLink.FOLDER })
        val remoteFolders = remote.folders.mapNotNull { folder ->
            runCatching { RemoteFolder(folder.id, MonicaCloudCrypto.decryptString(userKey, folder.name), folder.revisionDate) }.getOrNull()
        }
        syncRemoteFolders(remoteFolders, folderMap)
        for (gone in remote.deleted.filter { it.type == "folder" }) folderMap.unlinkCloud(gone.id)

        // ---------------------------------------------------------------- pull
        val decrypted = withContext(Dispatchers.Default) {
            remote.items.mapNotNull { dto ->
                runCatching {
                    val itemKey = MonicaCloudCrypto.decryptItemKey(userKey, dto.key)
                    val payload = json.parseToJsonElement(MonicaCloudCrypto.decryptString(itemKey, dto.data)).jsonObject
                    itemKey.fill(0)
                    Remote(dto, payload)
                }.getOrNull()
            }
        }
        val localByKey = store.listRecords().associateBy { it.ref.key }.toMutableMap()
        val linkedLocalKeys = itemLinks.values.mapNotNull { it.localRef?.key }.toMutableSet()

        for (incoming in decrypted) {
            val dto = incoming.dto
            val kind = LocalKind.forType(dto.type)
            if (kind == null) {
                result = result.copy(skippedUnsupported = result.skippedUnsupported + 1)
                continue
            }
            val wanted = IncomingRecord(
                type = dto.type,
                folderLocalId = dto.folderId?.let { folderMap.localFor(it) },
                favorite = dto.favorite,
                archived = dto.archivedDate != null,
                trashed = dto.deletedDate != null,
                payload = incoming.payload,
            )
            val link = itemLinks[dto.id]
            if (link == null) {
                // Not linked yet (first sync, or after signing out): adopt an unlinked local entry with
                // the same visible content instead of duplicating it. Compare in the local representation,
                // because the stored copy carries a `monica` section the server copy may lack.
                val identity = store.previewRecord(kind, wanted)?.identityHash()
                val twin = identity?.let {
                    localByKey.values.firstOrNull { local ->
                        local.ref.key !in linkedLocalKeys && local.ref.kind == kind && local.identityHash() == it
                    }
                }
                val stored = if (twin != null) {
                    if (twin.trashed != wanted.trashed) store.updateRecord(twin.ref, wanted) ?: twin else twin
                } else {
                    store.createRecord(kind, wanted).also { result = result.copy(pulledCreated = result.pulledCreated + 1) }
                }
                remember(dto, stored, itemLinks, localByKey, linkedLocalKeys)
                continue
            }
            if (dto.revisionDate == link.revision) continue // our own write, or unchanged

            val ref = link.localRef ?: continue
            val local = localByKey[ref.key]
            val localChanged = local != null && local.contentHash() != link.contentHash
            if (local == null || !localChanged) {
                // Local untouched (or deleted locally while edited remotely: the edit wins).
                val stored = (if (local != null) store.updateRecord(ref, wanted) else null) ?: store.createRecord(kind, wanted)
                remember(dto, stored, itemLinks, localByKey, linkedLocalKeys)
                result = result.copy(pulledUpdated = result.pulledUpdated + 1)
            } else {
                // Both sides changed: keep the local version as a copy, then take the server version.
                store.createRecord(local.ref.kind, local.asConflictCopy())
                val stored = store.updateRecord(ref, wanted) ?: store.createRecord(kind, wanted)
                remember(dto, stored, itemLinks, localByKey, linkedLocalKeys)
                result = result.copy(conflicts = result.conflicts + 1)
            }
        }

        val remotelyDeleted = remote.deleted.filter { it.type == "item" }.map { it.id }.toMutableSet()
        if (remote.full) {
            val present = remote.items.map { it.id }.toSet()
            remotelyDeleted += itemLinks.keys.filter { it !in present }
        }
        for (cloudId in remotelyDeleted) {
            val link = itemLinks.remove(cloudId) ?: continue
            links.delete(cloudId)
            val ref = link.localRef ?: continue
            val local = localByKey[ref.key] ?: continue
            if (local.contentHash() == link.contentHash) {
                store.deleteRecord(ref)
                localByKey.remove(ref.key)
                result = result.copy(pulledDeleted = result.pulledDeleted + 1)
            }
            // else: edited locally after the remote delete — it stays and uploads again as new.
            linkedLocalKeys.remove(ref.key)
        }

        // ---------------------------------------------------------------- push
        val records = store.listRecords()
        pushFolders(userKey, records, folderMap)
        val byLocalKey = itemLinks.values.filter { it.localRef != null }.associateBy { it.localRef!!.key }

        val toCreate = records.filter { it.ref.key !in byLocalKey }
        result = result.copy(pushedCreated = createRemote(userKey, toCreate, folderMap))

        for (record in records) {
            val link = byLocalKey[record.ref.key] ?: continue
            var current = link
            if (record.contentHash() != link.contentHash) {
                val itemKey = link.encryptedItemKey?.let { MonicaCloudCrypto.decryptItemKey(userKey, it) }
                    ?: MonicaCloudCrypto.generateKey()
                val encrypted = MonicaCloudCrypto.encryptItem(userKey, record.payload.toString(), itemKey)
                itemKey.fill(0)
                val request = ItemWriteRequest(
                    type = record.type,
                    folderId = record.folderLocalId?.let { folderMap.cloudFor(it) },
                    favorite = record.favorite,
                    key = encrypted.key,
                    data = encrypted.data,
                    archived = record.archived,
                    lastKnownRevisionDate = link.revision,
                )
                try {
                    val saved = client.updateItem(link.cloudId, request)
                    current = link.copy(revision = saved.revisionDate, contentHash = record.contentHash(), encryptedItemKey = saved.key)
                    links.upsert(current)
                    result = result.copy(pushedUpdated = result.pushedUpdated + 1)
                } catch (e: MonicaCloudApiException) {
                    if (!e.isConflict && e.status != 404) throw e
                    // Changed (or deleted) on the server since our pull; resolved on the next sync.
                    continue
                }
            }
            if (record.trashed != current.trashed) {
                val saved = if (record.trashed) client.trashItem(link.cloudId) else client.restoreItem(link.cloudId)
                links.upsert(current.copy(trashed = record.trashed, revision = saved.revisionDate))
            }
        }

        val liveKeys = records.map { it.ref.key }.toSet()
        for (link in itemLinks.values) {
            val ref = link.localRef ?: continue
            if (ref.key in liveKeys) continue
            try {
                client.deleteItem(link.cloudId)
            } catch (e: MonicaCloudApiException) {
                if (e.status != 404) throw e
            }
            links.delete(link.cloudId)
            result = result.copy(pushedDeleted = result.pushedDeleted + 1)
        }

        result = syncAttachments(userKey, remote.items, liveKeys, result)
        return result.copy(cursor = remote.revisionDate)
    }

    // ------------------------------------------------------------------ attachments

    /**
     * Reconcile attachments after items are linked.
     * - Items in this pull: download server attachments we do not have, drop ones deleted on the server.
     * - Local attachments without a link are uploaded; linked ones that disappeared locally while their
     *   entry still exists are deleted on the server. Attachments of entries in the trash still exist
     *   locally (soft-deleted), so trashing an entry never deletes its server attachments.
     * Uploads bump the item's server revision; the item link is updated so that is not seen as a remote edit.
     */
    private suspend fun syncAttachments(
        userKey: ByteArray,
        remoteItems: List<ItemDto>,
        liveLocalKeys: Set<String>,
        start: MonicaCloudSyncResult,
    ): MonicaCloudSyncResult {
        var result = start
        val all = links.all()
        val itemByCloud = all.filter { it.objectType == CloudLink.ITEM }.associateBy { it.cloudId }.toMutableMap()
        val itemByLocal = itemByCloud.values.filter { it.localRef != null }.associateBy { it.localRef!!.key }
        val attachmentLinks = all.filter { it.objectType == CloudLink.ATTACHMENT }.associateBy { it.cloudId }.toMutableMap()
        val local = store.listAttachments()
        val localById = local.associateBy { it.id }

        suspend fun linkAttachment(cloudId: String, owner: LocalRef, localId: String, parentCloudId: String) {
            val link = CloudLink(cloudId, CloudLink.ATTACHMENT, owner.kind, localId, parentCloudId, owner.key)
            links.upsert(link)
            attachmentLinks[cloudId] = link
        }

        suspend fun bumpItem(parentCloudId: String, revision: String) {
            val link = itemByCloud[parentCloudId] ?: return
            val updated = link.copy(revision = revision)
            links.upsert(updated)
            itemByCloud[parentCloudId] = updated
        }

        // Server → device.
        for (dto in remoteItems) {
            val owner = itemByCloud[dto.id]?.localRef ?: continue
            if (owner.kind == LocalKind.PASSKEY || owner.key !in liveLocalKeys) continue
            val remoteIds = dto.attachments.map { it.id }.toSet()
            for (gone in attachmentLinks.values.filter { it.revision == dto.id && it.cloudId !in remoteIds }) {
                if (gone.localId in localById) store.deleteAttachment(gone.localId)
                links.delete(gone.cloudId)
                attachmentLinks.remove(gone.cloudId)
            }
            var itemKey: ByteArray? = null
            try {
                for (attachment in dto.attachments) {
                    val existing = attachmentLinks[attachment.id]
                    // Same owner: either present, or deleted here on purpose (pushed below). Only a link to a
                    // different (recreated) entry means the local copy is gone and must be downloaded again.
                    if (existing != null && existing.contentHash == owner.key) continue
                    if (existing != null) {
                        links.delete(existing.cloudId)
                        attachmentLinks.remove(existing.cloudId)
                    }
                    val key = itemKey ?: MonicaCloudCrypto.decryptItemKey(userKey, dto.key).also { itemKey = it }
                    val buffer = java.io.ByteArrayOutputStream()
                    val fileName = client.downloadAttachment(dto.id, key, attachment, buffer)
                    val stored = store.createAttachment(owner, fileName, buffer.toByteArray()) ?: continue
                    linkAttachment(attachment.id, owner, stored.id, dto.id)
                    result = result.copy(pulledAttachments = result.pulledAttachments + 1)
                }
            } finally {
                itemKey?.fill(0)
            }
        }

        // Re-read: the server pass may have added or removed local attachments.
        val current = store.listAttachments()
        val currentById = current.associateBy { it.id }

        // Device → server: new local attachments.
        val linkedLocalIds = attachmentLinks.values.map { it.localId }.toSet()
        for (attachment in current) {
            if (attachment.id in linkedLocalIds) continue
            val parent = itemByLocal[attachment.owner.key] ?: continue
            val parentCloudId = parent.cloudId
            val encryptedKey = itemByCloud[parentCloudId]?.encryptedItemKey ?: continue
            val itemKey = MonicaCloudCrypto.decryptItemKey(userKey, encryptedKey)
            try {
                val uploaded = client.uploadAttachment(parentCloudId, itemKey, attachment.fileName, store.readAttachment(attachment.id))
                linkAttachment(uploaded.attachmentId, attachment.owner, attachment.id, parentCloudId)
                bumpItem(parentCloudId, uploaded.item.revisionDate)
                result = result.copy(pushedAttachments = result.pushedAttachments + 1)
            } catch (e: MonicaCloudApiException) {
                if (e.status != 404) throw e // item deleted on the server meanwhile
            } finally {
                itemKey.fill(0)
            }
        }

        // Device → server: attachments removed locally.
        for (link in attachmentLinks.values.toList()) {
            if (link.localId in currentById) continue
            val parent = itemByCloud[link.revision]
            val ownerStillHere = link.contentHash in liveLocalKeys && parent?.localRef?.key == link.contentHash
            if (ownerStillHere) {
                try {
                    val item = client.deleteAttachment(link.revision, link.cloudId)
                    bumpItem(link.revision, item.revisionDate)
                    result = result.copy(pushedAttachments = result.pushedAttachments + 1)
                } catch (e: MonicaCloudApiException) {
                    if (e.status != 404) throw e
                }
            }
            // Otherwise the whole entry went away (or was recreated); the item sync handled it.
            links.delete(link.cloudId)
            attachmentLinks.remove(link.cloudId)
        }
        return result
    }

    // ------------------------------------------------------------------ items

    private suspend fun remember(
        dto: ItemDto,
        stored: LocalRecord,
        itemLinks: MutableMap<String, CloudLink>,
        localByKey: MutableMap<String, LocalRecord>,
        linkedLocalKeys: MutableSet<String>,
    ) {
        val link = CloudLink(
            cloudId = dto.id,
            objectType = CloudLink.ITEM,
            localKind = stored.ref.kind,
            localId = stored.ref.id,
            revision = dto.revisionDate,
            contentHash = stored.contentHash(),
            trashed = dto.deletedDate != null,
            encryptedItemKey = dto.key,
        )
        links.upsert(link)
        itemLinks[dto.id] = link
        localByKey[stored.ref.key] = stored
        linkedLocalKeys += stored.ref.key
    }

    private suspend fun createRemote(userKey: ByteArray, records: List<LocalRecord>, folders: FolderMap): Int {
        if (records.isEmpty()) return 0
        var created = 0
        for (batch in records.chunked(IMPORT_BATCH)) {
            val requests = withContext(Dispatchers.Default) {
                batch.map { record ->
                    val encrypted = MonicaCloudCrypto.encryptItem(userKey, record.payload.toString())
                    ItemWriteRequest(
                        type = record.type,
                        folderId = record.folderLocalId?.let { folders.cloudFor(it) },
                        favorite = record.favorite,
                        key = encrypted.key,
                        data = encrypted.data,
                        archived = record.archived,
                        ref = record.ref.key,
                    )
                }
            }
            val response = client.importItems(ImportRequest(folders = emptyList(), items = requests))
            val byRef = batch.associateBy { it.ref.key }
            for (dto in response.items) {
                val record = byRef[dto.ref] ?: continue
                var revision = dto.revisionDate
                if (record.trashed) revision = client.trashItem(dto.id).revisionDate
                links.upsert(
                    CloudLink(
                        cloudId = dto.id,
                        objectType = CloudLink.ITEM,
                        localKind = record.ref.kind,
                        localId = record.ref.id,
                        revision = revision,
                        contentHash = record.contentHash(),
                        trashed = record.trashed,
                        encryptedItemKey = dto.key,
                    ),
                )
                created++
            }
        }
        return created
    }

    private fun LocalRecord.asConflictCopy(): IncomingRecord {
        val name = (payload["name"] as? JsonPrimitive)?.content.orEmpty()
        val renamed = JsonObject(payload + ("name" to JsonPrimitive(name + conflictSuffix)))
        return IncomingRecord(type, folderLocalId, favorite, archived, trashed, renamed)
    }

    // ------------------------------------------------------------------ folders

    /** Bidirectional cloud folder id ↔ local folder (category) id map backed by folder links. */
    private inner class FolderMap(existing: List<CloudLink>) {
        val byCloud = existing.associateBy { it.cloudId }.toMutableMap()
        val byLocal = existing.associateBy { it.localId }.toMutableMap()

        fun localFor(cloudId: String): String? = byCloud[cloudId]?.localId

        fun cloudFor(localId: String): String? = byLocal[localId]?.cloudId

        suspend fun link(cloudId: String, localId: String, revision: String, name: String) {
            val link = CloudLink(cloudId, CloudLink.FOLDER, null, localId, revision, sha256(name))
            links.upsert(link)
            byCloud[cloudId] = link
            byLocal[localId] = link
        }

        suspend fun unlinkCloud(cloudId: String) {
            val link = byCloud.remove(cloudId) ?: return
            byLocal.remove(link.localId)
            links.delete(cloudId)
        }
    }

    private suspend fun syncRemoteFolders(remote: List<RemoteFolder>, folders: FolderMap) {
        if (remote.isEmpty()) return
        val locals = store.listFolders().associateBy { it.id }.toMutableMap()
        for (folder in remote) {
            val cloudId = folder.id
            val name = folder.name
            val revision = folder.revision
            val link = folders.byCloud[cloudId]
            val local = link?.let { locals[it.localId] }
            when {
                local == null -> {
                    // Reuse a local folder with the same name before creating one.
                    val target = locals.values.firstOrNull { it.name == name && folders.byLocal[it.id] == null }
                        ?: store.createFolder(name).also { locals[it.id] = it }
                    folders.link(cloudId, target.id, revision, name)
                }
                link.revision != revision && local.name != name -> {
                    store.renameFolder(local.id, name)
                    folders.link(cloudId, local.id, revision, name)
                }
            }
        }
    }

    private suspend fun pushFolders(userKey: ByteArray, records: List<LocalRecord>, folders: FolderMap) {
        val used = records.mapNotNull { it.folderLocalId }.toSet()
        if (used.isEmpty() && folders.byLocal.isEmpty()) return
        for (local in store.listFolders()) {
            val link = folders.byLocal[local.id]
            if (link == null) {
                if (local.id !in used) continue
                val created = client.createFolder(MonicaCloudCrypto.encryptString(userKey, local.name))
                folders.link(created.id, local.id, created.revisionDate, local.name)
            } else if (link.contentHash != sha256(local.name)) {
                val updated = client.updateFolder(link.cloudId, MonicaCloudCrypto.encryptString(userKey, local.name))
                folders.link(link.cloudId, local.id, updated.revisionDate, local.name)
            }
        }
    }

    companion object {
        const val EMPTY_VAULT_THRESHOLD = 5
        private const val IMPORT_BATCH = 500
    }
}
