package takagi.ru.monica.cloud.api

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.Authenticator
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.Route
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import takagi.ru.monica.cloud.crypto.MonicaCloudCrypto
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

/**
 * Monica Cloud API client for one server.
 *
 * Holds the token pair, refreshes it transparently on 401 (the server rotates refresh tokens, so
 * every refresh is persisted through [onSessionChanged]) and keeps all vault crypto on the client.
 * No android.* dependencies: it runs in JVM unit tests against a real server.
 */
class MonicaCloudClient(
    serverUrl: String,
    baseHttpClient: OkHttpClient = defaultHttpClient(),
    initialSession: TokenResponse? = null,
    /** Persist the new session (or clear it when null). Called on login, every refresh and logout. */
    private val onSessionChanged: (TokenResponse?) -> Unit = {},
) {
    val serverUrl: String = normalizeServerUrl(serverUrl)

    @Volatile
    var session: TokenResponse? = initialSession
        private set

    private val refreshLock = Any()

    private val publicApi: MonicaCloudApi = retrofit(baseHttpClient)
    private val api: MonicaCloudApi = retrofit(
        baseHttpClient.newBuilder()
            .addInterceptor(BearerInterceptor())
            .authenticator(RefreshAuthenticator())
            .build(),
    )

    private fun retrofit(client: OkHttpClient): MonicaCloudApi = Retrofit.Builder()
        .baseUrl("${this.serverUrl}/api/v1/")
        .client(client)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()
        .create(MonicaCloudApi::class.java)

    // ------------------------------------------------------------------ discovery and auth

    suspend fun config(): ServerConfigDto = call { publicApi.config() }

    suspend fun prelogin(email: String): PreloginResponse = call { publicApi.prelogin(PreloginRequest(email.trim())) }

    /** Create an account. The master password never leaves the device. */
    suspend fun register(email: String, name: String, masterPassword: String, kdfIterations: Int): RegisterResponse {
        val request = withContext(Dispatchers.Default) {
            val keys = MonicaCloudCrypto.deriveMasterKeys(email, masterPassword, kdfIterations)
            val userKey = MonicaCloudCrypto.generateKey()
            try {
                RegisterRequest(
                    email = email.trim(),
                    name = name.trim(),
                    authHash = keys.authHash,
                    kdf = MonicaCloudCrypto.KDF_PBKDF2,
                    kdfIterations = kdfIterations,
                    protectedUserKey = MonicaCloudCrypto.encrypt(keys.wrapKey, userKey),
                )
            } finally {
                userKey.fill(0)
                keys.wrapKey.fill(0)
            }
        }
        return call { publicApi.register(request) }
    }

    class LoginResult(val session: TokenResponse, val userKey: ByteArray)

    /**
     * Log in and unlock. Returns the decrypted account key; keep it in memory only and wipe it
     * when the vault locks.
     */
    suspend fun login(email: String, masterPassword: String, device: DeviceDto): LoginResult {
        val iterations = prelogin(email).kdfIterations
        val keys = withContext(Dispatchers.Default) { MonicaCloudCrypto.deriveMasterKeys(email, masterPassword, iterations) }
        try {
            val newSession = call {
                publicApi.token(TokenRequest(grantType = "password", email = email.trim(), authHash = keys.authHash, device = device))
            }
            val userKey = MonicaCloudCrypto.unwrapUserKey(keys.wrapKey, newSession.protectedUserKey)
            updateSession(newSession)
            return LoginResult(newSession, userKey)
        } finally {
            keys.wrapKey.fill(0)
        }
    }

    /** Unlock a stored session offline (e.g. after app restart) with the master password. */
    suspend fun unlock(masterPassword: String): ByteArray {
        val current = session ?: throw MonicaCloudApiException(401, "unauthorized", "not logged in")
        return withContext(Dispatchers.Default) {
            val keys = MonicaCloudCrypto.deriveMasterKeys(current.account.email, masterPassword, current.kdfIterations)
            try {
                MonicaCloudCrypto.unwrapUserKey(keys.wrapKey, current.protectedUserKey)
            } finally {
                keys.wrapKey.fill(0)
            }
        }
    }

    suspend fun logout() {
        try {
            if (session != null) call { api.logout() }
        } finally {
            updateSession(null)
        }
    }

    /** Refresh now. Normally not needed: authenticated calls refresh on 401 automatically. */
    suspend fun refresh(): TokenResponse = withContext(Dispatchers.IO) { refreshBlocking(null) }
        ?: throw MonicaCloudApiException(401, "unauthorized", "session expired, log in again")

    // ------------------------------------------------------------------ vault

    suspend fun profile(): ProfileDto = call { api.profile() }

    suspend fun revisionDate(): String = call { api.revisionDate().revisionDate }

    suspend fun sync(since: String? = null): SyncResponse = call { api.sync(since?.takeIf { it.isNotBlank() }) }

    suspend fun createItem(request: ItemWriteRequest): ItemDto = call { api.createItem(request) }

    /** Throws [MonicaCloudApiException] with `status == 409` and [MonicaCloudApiException.currentItem] on conflict. */
    suspend fun updateItem(id: String, request: ItemWriteRequest): ItemDto = call { api.updateItem(id, request) }

    suspend fun importItems(request: ImportRequest): ImportResponse = call { api.importItems(request) }

    suspend fun bulk(action: String, ids: List<String>, folderId: String? = null): Int =
        call { api.bulk(BulkRequest(action, ids, folderId)).affected }

    suspend fun trashItem(id: String): ItemDto = call { api.trashItem(id) }

    suspend fun restoreItem(id: String): ItemDto = call { api.restoreItem(id) }

    suspend fun deleteItem(id: String) {
        call { api.deleteItem(id) }
    }

    suspend fun createFolder(encryptedName: String): FolderDto = call { api.createFolder(FolderWriteRequest(encryptedName)) }

    suspend fun updateFolder(id: String, encryptedName: String): FolderDto =
        call { api.updateFolder(id, FolderWriteRequest(encryptedName)) }

    suspend fun deleteFolder(id: String) {
        call { api.deleteFolder(id) }
    }

    class UploadedAttachment(val attachmentId: String, val item: ItemDto)

    /** Encrypt and upload an attachment. [itemKey] is the item's decrypted key. */
    suspend fun uploadAttachment(itemId: String, itemKey: ByteArray, fileName: String, content: ByteArray): UploadedAttachment {
        val (register, sealed) = withContext(Dispatchers.Default) {
            val attachmentKey = MonicaCloudCrypto.generateKey()
            try {
                val sealed = MonicaCloudCrypto.encryptBlob(attachmentKey, content)
                AttachmentRegisterRequest(
                    fileName = MonicaCloudCrypto.encryptString(itemKey, fileName),
                    key = MonicaCloudCrypto.encrypt(itemKey, attachmentKey),
                    size = sealed.size.toLong(),
                ) to sealed
            } finally {
                attachmentKey.fill(0)
            }
        }
        val registered = call { api.registerAttachment(itemId, register) }
        val body = sealed.toRequestBody("application/octet-stream".toMediaType())
        return UploadedAttachment(registered.id, call { api.uploadAttachment(itemId, registered.id, body) })
    }

    /** Download and decrypt an attachment into [output]. Returns the decrypted file name. */
    suspend fun downloadAttachment(itemId: String, itemKey: ByteArray, attachment: AttachmentDto, output: OutputStream): String {
        val fileName = MonicaCloudCrypto.decryptString(itemKey, attachment.fileName)
        val attachmentKey = MonicaCloudCrypto.decrypt(itemKey, attachment.key)
        try {
            val body = call { api.downloadAttachment(itemId, attachment.id) }
            withContext(Dispatchers.IO) {
                body.byteStream().use { input: InputStream -> MonicaCloudCrypto.decryptBlob(attachmentKey, input, output) }
            }
        } finally {
            attachmentKey.fill(0)
        }
        return fileName
    }

    suspend fun deleteAttachment(itemId: String, attachmentId: String): ItemDto =
        call { api.deleteAttachment(itemId, attachmentId) }

    // ------------------------------------------------------------------ plumbing

    private fun updateSession(next: TokenResponse?) {
        session = next
        onSessionChanged(next)
    }

    private suspend fun <T> call(block: suspend () -> T): T = try {
        block()
    } catch (e: HttpException) {
        throw MonicaCloudApiException.from(e)
    } catch (e: MonicaCloudApiException) {
        throw e
    } catch (e: IOException) {
        throw MonicaCloudNetworkException(e)
    }

    /**
     * Exchange the refresh token. Returns null when the session is gone (and clears it).
     * [staleAccessToken] lets concurrent 401s reuse a refresh another thread already did.
     */
    private fun refreshBlocking(staleAccessToken: String?): TokenResponse? = synchronized(refreshLock) {
        val current = session ?: return null
        if (staleAccessToken != null && current.accessToken != staleAccessToken) return current
        try {
            val refreshed = runBlocking { publicApi.token(TokenRequest(grantType = "refresh_token", refreshToken = current.refreshToken)) }
            updateSession(refreshed)
            refreshed
        } catch (e: HttpException) {
            if (e.code() == 401 || e.code() == 403) updateSession(null)
            null
        } catch (e: IOException) {
            null
        }
    }

    private inner class BearerInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val token = session?.accessToken ?: return chain.proceed(chain.request())
            return chain.proceed(chain.request().newBuilder().header("Authorization", "Bearer $token").build())
        }
    }

    private inner class RefreshAuthenticator : Authenticator {
        override fun authenticate(route: Route?, response: Response): Request? {
            if (response.priorResponse != null) return null // already retried once
            val sent = response.request.header("Authorization")?.removePrefix("Bearer ")
            val refreshed = refreshBlocking(sent) ?: return null
            return response.request.newBuilder().header("Authorization", "Bearer ${refreshed.accessToken}").build()
        }
    }

    companion object {
        val json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            encodeDefaults = true
            coerceInputValues = true
        }

        fun defaultHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(120, TimeUnit.SECONDS)
            .build()

        /**
         * `cloud.example.com/` → `https://cloud.example.com`. Plain http is kept only when typed
         * explicitly (LAN testing); the UI should warn about it.
         */
        fun normalizeServerUrl(input: String): String {
            val trimmed = input.trim().trimEnd('/')
            val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
            val parsed = withScheme.toHttpUrlOrNull()
                ?: throw IllegalArgumentException("invalid server address: $input")
            return parsed.toString().trimEnd('/')
        }
    }
}

/** A non-2xx answer from the server, in the protocol's error envelope. */
class MonicaCloudApiException(
    val status: Int,
    val code: String,
    message: String,
    /** On 409: the server's current copy of the item. */
    val current: kotlinx.serialization.json.JsonElement? = null,
) : Exception(message) {
    val isConflict: Boolean get() = status == 409
    val isUnauthorized: Boolean get() = status == 401

    fun currentItem(): ItemDto? = current?.let {
        runCatching { MonicaCloudClient.json.decodeFromJsonElement(ItemDto.serializer(), it) }.getOrNull()
    }

    companion object {
        fun from(e: HttpException): MonicaCloudApiException {
            val raw = runCatching { e.response()?.errorBody()?.string() }.getOrNull()
            val body = raw?.let { runCatching { MonicaCloudClient.json.decodeFromString(ErrorBody.serializer(), it) }.getOrNull() }
            return MonicaCloudApiException(e.code(), body?.error ?: "http", body?.message ?: e.message(), body?.current)
        }
    }
}

class MonicaCloudNetworkException(cause: IOException) : Exception(cause.message ?: "network error", cause)
