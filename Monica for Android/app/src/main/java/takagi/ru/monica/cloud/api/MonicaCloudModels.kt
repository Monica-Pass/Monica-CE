package takagi.ru.monica.cloud.api

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

// Wire types for Monica Cloud protocol v1 (Monica-Cloud/docs/protocol.zh-CN.md §4).
// Timestamps are kept as the server's strings: `revisionDate` must be echoed back verbatim.

@Serializable
data class ServerConfigDto(
    val name: String = "Monica Cloud",
    val version: String = "",
    val protocolVersion: Int = 1,
    val domain: String = "",
    val initialized: Boolean = true,
    val signupsAllowed: Boolean = false,
    val sendsAllowed: Boolean = false,
    val kdf: Int = 0,
    val kdfIterations: Int = 600_000,
    val attachmentMaxBytes: Long = 0,
    val features: List<String> = emptyList(),
)

@Serializable
data class PreloginRequest(val email: String)

@Serializable
data class PreloginResponse(val kdf: Int, val kdfIterations: Int)

@Serializable
data class RegisterRequest(
    val email: String,
    val name: String,
    val authHash: String,
    val kdf: Int,
    val kdfIterations: Int,
    val protectedUserKey: String,
)

@Serializable
data class RegisterResponse(val id: String, val email: String, val role: String)

@Serializable
data class DeviceDto(
    val identifier: String,
    val name: String,
    val type: String = "android",
    val appVersion: String = "",
)

@Serializable
data class TokenRequest(
    val grantType: String,
    val email: String? = null,
    val authHash: String? = null,
    val refreshToken: String? = null,
    val device: DeviceDto? = null,
)

@Serializable
data class AccountDto(
    val id: String,
    val email: String,
    val name: String = "",
    val role: String = "user",
)

@Serializable
data class TokenResponse(
    val accessToken: String,
    val expiresIn: Long,
    val tokenType: String = "Bearer",
    val refreshToken: String,
    val protectedUserKey: String,
    val kdf: Int,
    val kdfIterations: Int,
    val account: AccountDto,
    val deviceId: String,
)

@Serializable
data class ProfileDto(
    val id: String,
    val email: String,
    val name: String = "",
    val role: String = "user",
    val kdf: Int = 0,
    val kdfIterations: Int = 0,
    val creationDate: String = "",
    val revisionDate: String = "",
    val lastLoginDate: String? = null,
)

@Serializable
data class RevisionDateResponse(val revisionDate: String)

@Serializable
data class AttachmentDto(
    val id: String,
    val fileName: String,
    val key: String,
    val size: Long,
    val creationDate: String = "",
)

@Serializable
data class ItemDto(
    val id: String,
    val type: Int,
    val folderId: String? = null,
    val favorite: Boolean = false,
    val key: String,
    val data: String,
    val attachments: List<AttachmentDto> = emptyList(),
    val creationDate: String = "",
    val revisionDate: String,
    val deletedDate: String? = null,
    val archivedDate: String? = null,
    val ref: String? = null,
)

@Serializable
data class FolderDto(
    val id: String,
    val name: String,
    val creationDate: String = "",
    val revisionDate: String = "",
)

@Serializable
data class SendDto(
    val id: String,
    val accessId: String,
    val type: Int,
    val key: String,
    val name: String,
    val notes: String? = null,
    val text: String? = null,
    val fileName: String? = null,
    val size: Long? = null,
    val uploaded: Boolean = true,
    val passwordProtected: Boolean = false,
    val maxAccessCount: Int? = null,
    val accessCount: Int = 0,
    val disabled: Boolean = false,
    val hideEmail: Boolean = false,
    val expirationDate: String? = null,
    val deletionDate: String = "",
    val creationDate: String = "",
    val revisionDate: String = "",
)

@Serializable
data class TombstoneDto(val type: String, val id: String, val deletedAt: String)

@Serializable
data class SyncResponse(
    val full: Boolean,
    val revisionDate: String,
    val profile: ProfileDto,
    val folders: List<FolderDto> = emptyList(),
    val items: List<ItemDto> = emptyList(),
    val sends: List<SendDto> = emptyList(),
    val deleted: List<TombstoneDto> = emptyList(),
)

@Serializable
data class ItemWriteRequest(
    val type: Int,
    val folderId: String? = null,
    val favorite: Boolean = false,
    val key: String,
    val data: String,
    val archived: Boolean = false,
    /** Required for normal edits; omit only when the user chose to overwrite after a conflict. */
    val lastKnownRevisionDate: String? = null,
    /** Bulk import only: local reference echoed back. */
    val ref: String? = null,
    /** Bulk import only: folder created in the same import. */
    val folderRef: String? = null,
)

@Serializable
data class ImportFolderRequest(val ref: String, val name: String)

@Serializable
data class ImportRequest(val folders: List<ImportFolderRequest>, val items: List<ItemWriteRequest>)

@Serializable
data class ImportedFolderDto(val ref: String, val folder: FolderDto)

@Serializable
data class ImportResponse(val folders: List<ImportedFolderDto>, val items: List<ItemDto>)

@Serializable
data class BulkRequest(val action: String, val ids: List<String>, val folderId: String? = null)

@Serializable
data class BulkResponse(val affected: Int)

@Serializable
data class FolderWriteRequest(val name: String)

@Serializable
data class AttachmentRegisterRequest(val fileName: String, val key: String, val size: Long)

@Serializable
data class AttachmentRegisterResponse(val id: String, val uploadUrl: String, val attachment: AttachmentDto)

@Serializable
data class ErrorBody(val error: String = "http", val message: String = "", val current: JsonElement? = null)

@Serializable
class EmptyBody
