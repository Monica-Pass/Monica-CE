package takagi.ru.monica.cloud

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import takagi.ru.monica.cloud.api.TokenResponse
import takagi.ru.monica.security.SecurityManager
import java.util.UUID

/**
 * Persisted Monica Cloud account. Lives in SecurityManager's EncryptedSharedPreferences
 * (Android Keystore backed), like the Bitwarden module's keys, so background sync can run
 * while the app is closed. The account key is therefore protected at the same level as the
 * local vault itself.
 */
@Serializable
data class MonicaCloudAccount(
    val serverUrl: String,
    val email: String,
    val accountId: String,
    val name: String = "",
    val session: TokenResponse? = null,
    /** Account userKey, Base64. */
    val userKey: String? = null,
    val cursor: String? = null,
    val lastSyncAt: Long? = null,
    val lastError: String? = null,
    val lastPulled: Int = 0,
    val lastPushed: Int = 0,
    val lastConflicts: Int = 0,
    /** Items currently linked to the server. */
    val syncedItems: Int = 0,
    /**
     * Set after the first sync with attachment support. Accounts linked by an older build run one
     * full sync so attachments of entries that have not changed since are downloaded too.
     */
    val attachmentsSynced: Boolean = false,
)

class MonicaCloudAccountStore(private val securityManager: SecurityManager) {
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    fun load(): MonicaCloudAccount? = securityManager.getProtectedString(KEY_ACCOUNT)
        ?.let { runCatching { json.decodeFromString(MonicaCloudAccount.serializer(), it) }.getOrNull() }

    fun save(account: MonicaCloudAccount?) {
        securityManager.putProtectedString(KEY_ACCOUNT, account?.let { json.encodeToString(MonicaCloudAccount.serializer(), it) })
    }

    /** Stable per-install device id, kept across logouts so the server sees one device. */
    fun deviceIdentifier(): String = securityManager.getProtectedString(KEY_DEVICE_ID)
        ?: UUID.randomUUID().toString().also { securityManager.putProtectedString(KEY_DEVICE_ID, it) }

    private companion object {
        const val KEY_ACCOUNT = "monica_cloud_account_v1"
        const val KEY_DEVICE_ID = "monica_cloud_device_id_v1"
    }
}
