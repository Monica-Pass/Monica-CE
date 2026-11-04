package takagi.ru.monica.cloud

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.room.InvalidationTracker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import takagi.ru.monica.BuildConfig
import takagi.ru.monica.cloud.api.DeviceDto
import takagi.ru.monica.cloud.api.MonicaCloudApiException
import takagi.ru.monica.cloud.api.MonicaCloudClient
import takagi.ru.monica.cloud.api.MonicaCloudNetworkException
import takagi.ru.monica.cloud.api.ServerConfigDto
import takagi.ru.monica.cloud.crypto.MonicaCloudCrypto
import takagi.ru.monica.cloud.crypto.MonicaCloudCryptoException
import takagi.ru.monica.cloud.data.MonicaCloudRoomLinkStore
import takagi.ru.monica.cloud.data.MonicaCloudRoomStore
import takagi.ru.monica.cloud.sync.MonicaCloudSyncEngine
import takagi.ru.monica.cloud.sync.MonicaCloudSyncException
import takagi.ru.monica.cloud.sync.MonicaCloudSyncResult
import takagi.ru.monica.data.PasswordDatabase
import takagi.ru.monica.security.SecurityManager
import java.util.concurrent.TimeUnit

/** What the settings screen shows. Contains no secrets. */
data class MonicaCloudState(
    val loggedIn: Boolean = false,
    val serverUrl: String = "",
    val email: String = "",
    val name: String = "",
    val syncing: Boolean = false,
    val lastSyncAt: Long? = null,
    val lastError: MonicaCloudError? = null,
    val lastPulled: Int = 0,
    val lastPushed: Int = 0,
    val lastConflicts: Int = 0,
    val syncedItems: Int = 0,
    /** Set when the server returned an empty vault; the user must confirm before local items are removed. */
    val emptyVaultLinkedItems: Int? = null,
)

/** Error categories the UI translates; [detail] is the server or exception message. */
data class MonicaCloudError(val kind: Kind, val detail: String = "") {
    enum class Kind { NETWORK, SESSION_EXPIRED, WRONG_PASSWORD, ACCOUNT_CHANGED, SERVER, UNSUPPORTED_DATA, OTHER }
}

/**
 * Owns the Monica Cloud account: login, the API client, sync runs and their scheduling.
 * One instance per process ([get]); the sync worker and the settings screen share it.
 */
class MonicaCloudManager private constructor(private val context: Context) {
    private val securityManager = SecurityManager(context)
    private val database by lazy { PasswordDatabase.getDatabase(context) }
    private val accounts = MonicaCloudAccountStore(securityManager)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val syncLock = Mutex()

    @Volatile
    private var client: MonicaCloudClient? = null

    @Volatile
    private var quietUntil = 0L

    private val _state = MutableStateFlow(stateFrom(accounts.load()))
    val state: StateFlow<MonicaCloudState> = _state.asStateFlow()

    // ------------------------------------------------------------------ account

    suspend fun serverConfig(serverUrl: String): ServerConfigDto = MonicaCloudClient(serverUrl).config()

    /**
     * Log in (or create the account first when [register] is set), then run the first sync.
     * Throws on failure so the screen can show the message next to the form.
     */
    suspend fun login(serverUrl: String, email: String, masterPassword: String, register: Boolean = false, name: String = "") {
        val fresh = MonicaCloudClient(serverUrl, onSessionChanged = ::persistSession)
        if (register) {
            val config = fresh.config()
            fresh.register(email, name, masterPassword, config.kdfIterations)
        }
        val result = fresh.login(email, masterPassword, deviceInfo())
        // A different account than before: forget the old links so nothing is mixed up.
        val previous = accounts.load()
        if (previous != null && (previous.accountId != result.session.account.id || previous.serverUrl != fresh.serverUrl)) {
            MonicaCloudRoomLinkStore(database.monicaCloudDao()).clear()
        }
        accounts.save(
            MonicaCloudAccount(
                serverUrl = fresh.serverUrl,
                email = result.session.account.email,
                accountId = result.session.account.id,
                name = result.session.account.name,
                session = result.session,
                userKey = MonicaCloudCrypto.b64(result.userKey),
            ),
        )
        result.userKey.fill(0)
        client = fresh
        _state.value = stateFrom(accounts.load()).copy(syncing = true)
        schedulePeriodic()
        // First sync runs in the manager's scope so leaving the screen does not cancel it.
        scope.launch { syncNow() }
    }

    /** Sign out and forget sync bookkeeping. Local entries stay on the device. */
    suspend fun logout() {
        syncLock.withLock {
            runCatching { currentClient()?.logout() }
            accounts.save(null)
            client = null
            MonicaCloudRoomLinkStore(database.monicaCloudDao()).clear()
        }
        WorkManager.getInstance(context).cancelUniqueWork(PERIODIC_WORK)
        WorkManager.getInstance(context).cancelUniqueWork(ONE_TIME_WORK)
        _state.value = MonicaCloudState()
    }

    // ------------------------------------------------------------------ sync

    /** Run one sync now. Safe to call concurrently; runs are serialised. */
    suspend fun syncNow(allowEmptyRemote: Boolean = false): Result<MonicaCloudSyncResult> = syncLock.withLock {
        val account = accounts.load() ?: return@withLock Result.failure(IllegalStateException("not logged in"))
        val api = currentClient() ?: return@withLock Result.failure(IllegalStateException("not logged in"))
        val userKey = account.userKey?.let(MonicaCloudCrypto::fromB64)
            ?: return@withLock Result.failure(IllegalStateException("account key missing"))
        _state.update { it.copy(syncing = true, emptyVaultLinkedItems = null) }
        val outcome = runCatching {
            withContext(Dispatchers.IO) {
                MonicaCloudSyncEngine(
                    client = api,
                    store = MonicaCloudRoomStore(context, database, securityManager),
                    links = MonicaCloudRoomLinkStore(database.monicaCloudDao()),
                    conflictSuffix = context.getString(takagi.ru.monica.R.string.monica_cloud_conflict_suffix),
                ).sync(userKey, account.accountId, account.cursor, allowEmptyRemote)
            }
        }
        userKey.fill(0)
        quietUntil = System.currentTimeMillis() + QUIET_AFTER_SYNC_MS
        val latest = accounts.load() ?: account
        outcome.onSuccess { result ->
            accounts.save(
                latest.copy(
                    cursor = result.cursor,
                    lastSyncAt = System.currentTimeMillis(),
                    lastError = null,
                    lastPulled = result.pulledCreated + result.pulledUpdated + result.pulledDeleted,
                    lastPushed = result.pushedCreated + result.pushedUpdated + result.pushedDeleted,
                    lastConflicts = result.conflicts,
                    syncedItems = database.monicaCloudDao().linkedItemCount(),
                ),
            )
            _state.value = stateFrom(accounts.load())
        }.onFailure { error ->
            Log.w(TAG, "Monica Cloud sync failed: ${error.javaClass.simpleName}: ${error.message}")
            val mapped = mapError(error)
            accounts.load()?.let { accounts.save(it.copy(lastError = mapped.kind.name)) }
            _state.value = stateFrom(accounts.load()).copy(
                lastError = mapped,
                emptyVaultLinkedItems = (error as? MonicaCloudSyncException.SuspiciousEmptyVault)?.linkedItems,
            )
        }
        outcome
    }

    /** Ask for a sync soon (debounced). Used after local edits and on app start. */
    fun requestSync(delaySeconds: Long = 5) {
        if (accounts.load() == null) return
        val request = OneTimeWorkRequestBuilder<MonicaCloudSyncWorker>()
            .setInitialDelay(delaySeconds, TimeUnit.SECONDS)
            .setConstraints(networkConstraint())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(ONE_TIME_WORK, ExistingWorkPolicy.REPLACE, request)
    }

    /** Called from Application.onCreate: periodic sync, a sync on start and change tracking. */
    fun onAppStart() {
        if (accounts.load() == null) return
        schedulePeriodic()
        requestSync(delaySeconds = 2)
        watchLocalChanges()
    }

    private fun schedulePeriodic() {
        val request = PeriodicWorkRequestBuilder<MonicaCloudSyncWorker>(15, TimeUnit.MINUTES)
            .setConstraints(networkConstraint())
            .build()
        WorkManager.getInstance(context)
            .enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.KEEP, request)
        watchLocalChanges()
    }

    private var watching = false

    private fun watchLocalChanges() {
        if (watching) return
        watching = true
        scope.launch {
            database.invalidationTracker.addObserver(
                object : InvalidationTracker.Observer(arrayOf("password_entries", "secure_items", "passkeys", "categories", "custom_fields")) {
                    override fun onInvalidated(tables: Set<String>) {
                        // Our own sync writes also invalidate these tables; ignore them.
                        if (_state.value.syncing || System.currentTimeMillis() < quietUntil) return
                        requestSync()
                    }
                },
            )
        }
    }

    // ------------------------------------------------------------------ helpers

    private fun currentClient(): MonicaCloudClient? {
        client?.let { return it }
        val account = accounts.load() ?: return null
        return MonicaCloudClient(account.serverUrl, initialSession = account.session, onSessionChanged = ::persistSession)
            .also { client = it }
    }

    /** Every token refresh rotates the refresh token, so persist each new session immediately. */
    private fun persistSession(session: takagi.ru.monica.cloud.api.TokenResponse?) {
        val account = accounts.load() ?: return
        accounts.save(account.copy(session = session))
        if (session == null) {
            _state.update { it.copy(lastError = MonicaCloudError(MonicaCloudError.Kind.SESSION_EXPIRED)) }
        }
    }

    private fun deviceInfo() = DeviceDto(
        identifier = accounts.deviceIdentifier(),
        name = listOf(Build.MANUFACTURER.replaceFirstChar { it.uppercase() }, Build.MODEL).distinct().joinToString(" ").trim(),
        type = "android",
        appVersion = BuildConfig.VERSION_NAME,
    )

    private fun networkConstraint() = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    private fun stateFrom(account: MonicaCloudAccount?): MonicaCloudState = if (account == null) {
        MonicaCloudState()
    } else {
        MonicaCloudState(
            loggedIn = true,
            serverUrl = account.serverUrl,
            email = account.email,
            name = account.name,
            lastSyncAt = account.lastSyncAt,
            lastError = account.lastError?.let { kind ->
                runCatching { MonicaCloudError(MonicaCloudError.Kind.valueOf(kind)) }.getOrNull()
            } ?: if (account.session == null) MonicaCloudError(MonicaCloudError.Kind.SESSION_EXPIRED) else null,
            lastPulled = account.lastPulled,
            lastPushed = account.lastPushed,
            lastConflicts = account.lastConflicts,
            syncedItems = account.syncedItems,
        )
    }

    companion object {
        private const val TAG = "MonicaCloud"
        private const val PERIODIC_WORK = "monica_cloud_periodic_sync"
        private const val ONE_TIME_WORK = "monica_cloud_sync"
        private const val QUIET_AFTER_SYNC_MS = 4_000L

        @Volatile
        private var instance: MonicaCloudManager? = null

        fun get(context: Context): MonicaCloudManager = instance ?: synchronized(this) {
            instance ?: MonicaCloudManager(context.applicationContext).also { instance = it }
        }

        fun mapError(error: Throwable): MonicaCloudError = when (error) {
            is MonicaCloudNetworkException -> MonicaCloudError(MonicaCloudError.Kind.NETWORK, error.message.orEmpty())
            is MonicaCloudApiException -> when {
                error.status == 401 && error.message.orEmpty().contains("email or master password") ->
                    MonicaCloudError(MonicaCloudError.Kind.WRONG_PASSWORD)
                error.status == 401 -> MonicaCloudError(MonicaCloudError.Kind.SESSION_EXPIRED)
                else -> MonicaCloudError(MonicaCloudError.Kind.SERVER, error.message.orEmpty())
            }
            is MonicaCloudCryptoException.WrongKey -> MonicaCloudError(MonicaCloudError.Kind.WRONG_PASSWORD)
            is MonicaCloudCryptoException.UnsupportedFormat -> MonicaCloudError(MonicaCloudError.Kind.UNSUPPORTED_DATA)
            is MonicaCloudSyncException.AccountMismatch -> MonicaCloudError(MonicaCloudError.Kind.ACCOUNT_CHANGED)
            is MonicaCloudSyncException.SuspiciousEmptyVault -> MonicaCloudError(MonicaCloudError.Kind.SERVER, error.message.orEmpty())
            else -> MonicaCloudError(MonicaCloudError.Kind.OTHER, error.message ?: error.javaClass.simpleName)
        }
    }
}

/** Background sync: periodic and debounced one-time runs. */
class MonicaCloudSyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val result = MonicaCloudManager.get(applicationContext).syncNow()
        val error = result.exceptionOrNull() ?: return Result.success()
        return if (error is MonicaCloudNetworkException && runAttemptCount < 3) Result.retry() else Result.success()
    }
}
