package takagi.ru.monica.cloud.data

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import takagi.ru.monica.data.Category
import takagi.ru.monica.data.PasskeyEntry
import takagi.ru.monica.data.PasswordEntry
import takagi.ru.monica.data.SecureItem

/**
 * Sync bookkeeping for Monica Cloud: one row per server item or folder that corresponds to a
 * Monica-local entry. See [takagi.ru.monica.cloud.sync.CloudLink].
 */
@Entity(
    tableName = "monica_cloud_links",
    indices = [Index(value = ["local_kind", "local_id"], name = "index_monica_cloud_links_local")],
)
data class MonicaCloudLinkEntity(
    @PrimaryKey
    @ColumnInfo(name = "cloud_id")
    val cloudId: String,
    @ColumnInfo(name = "object_type")
    val objectType: String,
    @ColumnInfo(name = "local_kind")
    val localKind: String?,
    @ColumnInfo(name = "local_id")
    val localId: String,
    @ColumnInfo(name = "revision")
    val revision: String,
    @ColumnInfo(name = "content_hash")
    val contentHash: String,
    @ColumnInfo(name = "trashed")
    val trashed: Boolean,
    @ColumnInfo(name = "encrypted_item_key")
    val encryptedItemKey: String?,
)

/** Payload keys from other clients that Monica does not map, kept so local edits do not drop them. */
@Entity(tableName = "monica_cloud_payload_extras")
data class MonicaCloudPayloadExtraEntity(
    @PrimaryKey
    @ColumnInfo(name = "local_key")
    val localKey: String,
    @ColumnInfo(name = "extras")
    val extras: String,
)

@Dao
interface MonicaCloudDao {
    // ---------------------------------------------------------------- links

    @Query("SELECT * FROM monica_cloud_links")
    suspend fun allLinks(): List<MonicaCloudLinkEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertLink(link: MonicaCloudLinkEntity)

    @Query("DELETE FROM monica_cloud_links WHERE cloud_id = :cloudId")
    suspend fun deleteLink(cloudId: String)

    @Query("DELETE FROM monica_cloud_links")
    suspend fun clearLinks()

    @Query("SELECT COUNT(*) FROM monica_cloud_links WHERE object_type = 'item'")
    suspend fun linkedItemCount(): Int

    // ---------------------------------------------------------------- extras

    @Query("SELECT * FROM monica_cloud_payload_extras")
    suspend fun allExtras(): List<MonicaCloudPayloadExtraEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertExtra(extra: MonicaCloudPayloadExtraEntity)

    @Query("DELETE FROM monica_cloud_payload_extras WHERE local_key = :localKey")
    suspend fun deleteExtra(localKey: String)

    @Query("DELETE FROM monica_cloud_payload_extras")
    suspend fun clearExtras()

    // ---------------------------------------------------------------- Monica-local entries
    // "Monica-local" = not owned by KeePass, Bitwarden or MDBX; those sources sync themselves.

    @Query(
        "SELECT * FROM password_entries WHERE keepassDatabaseId IS NULL " +
            "AND bitwarden_vault_id IS NULL AND mdbx_database_id IS NULL",
    )
    suspend fun localPasswords(): List<PasswordEntry>

    @Query(
        "SELECT * FROM secure_items WHERE keepass_database_id IS NULL " +
            "AND bitwarden_vault_id IS NULL AND mdbx_database_id IS NULL",
    )
    suspend fun localSecureItems(): List<SecureItem>

    @Query(
        "SELECT * FROM passkeys WHERE keepass_database_id IS NULL " +
            "AND bitwarden_vault_id IS NULL AND mdbx_database_id IS NULL",
    )
    suspend fun localPasskeys(): List<PasskeyEntry>

    @Query("SELECT * FROM categories WHERE bitwarden_vault_id IS NULL AND mdbx_database_id IS NULL")
    suspend fun localCategories(): List<Category>

    @Insert
    suspend fun insertPasskey(entry: PasskeyEntry): Long

    /** Locally stored attachments (decryptable blobs), including soft-deleted ones of trashed entries. */
    @Query("SELECT * FROM attachments WHERE source = 'LOCAL' AND local_path IS NOT NULL AND wrapped_cek IS NOT NULL")
    suspend fun localAttachments(): List<takagi.ru.monica.attachments.model.Attachment>
}
