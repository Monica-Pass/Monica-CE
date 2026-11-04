package takagi.ru.monica.cloud.mapper

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import takagi.ru.monica.data.CustomField
import takagi.ru.monica.data.ItemType
import takagi.ru.monica.data.PasskeyEntry
import takagi.ru.monica.data.PasswordEntry
import takagi.ru.monica.data.SecureItem
import takagi.ru.monica.data.model.BankCardData
import takagi.ru.monica.data.model.BillingAddressData
import takagi.ru.monica.data.model.CardWalletDataCodec
import takagi.ru.monica.data.model.DocumentData
import takagi.ru.monica.data.model.DocumentType
import takagi.ru.monica.data.model.NoteData
import takagi.ru.monica.data.model.PaymentAccountData
import takagi.ru.monica.data.model.SshKeyData
import takagi.ru.monica.data.model.SshKeyDataCodec
import takagi.ru.monica.data.model.TotpData
import takagi.ru.monica.data.model.WifiData
import takagi.ru.monica.data.model.WifiSecurity
import java.util.Date

/**
 * Maps Monica's Room entities to Monica Cloud item payloads (protocol §2) and back.
 *
 * A payload has two layers:
 * - normalized sections (`login`, `card`, `totp`, …) that the WebUI shows and edits;
 * - a `monica` section with the CE-only fields, so a round trip through the cloud is lossless.
 *
 * When applying a payload, the `monica` section restores the full entity first and the
 * normalized sections are laid on top, because another client may have edited only those.
 *
 * Inputs and outputs are plaintext: the caller decrypts `PasswordEntry.password` (and
 * Monica-ciphertext `itemData`) before mapping and re-encrypts after. Fields that change on
 * every use (`updatedAt`, passkey counters) are left out so they do not trigger uploads.
 */
object MonicaCloudEntityMapper {
    const val TYPE_LOGIN = 1
    const val TYPE_NOTE = 2
    const val TYPE_CARD = 3
    const val TYPE_DOCUMENT = 4
    const val TYPE_TOTP = 5
    const val TYPE_PASSKEY = 6
    const val TYPE_WIFI = 7
    const val TYPE_SSH_KEY = 8
    const val TYPE_ADDRESS = 9
    const val TYPE_PAYMENT = 10

    /** Top-level payload keys this client understands; anything else is preserved verbatim. */
    val KNOWN_KEYS = setOf(
        "v", "name", "notes", "uris", "fields", "login", "card", "document", "totp",
        "passkey", "wifi", "sshKey", "address", "payment", "monica",
    )

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        coerceInputValues = true
    }

    // ================================================================== passwords

    fun passwordType(entry: PasswordEntry): Int = when {
        entry.loginType.equals("WIFI", ignoreCase = true) -> TYPE_WIFI
        entry.sshKeyData.isNotBlank() -> TYPE_SSH_KEY
        else -> TYPE_LOGIN
    }

    /** [entry] must carry the decrypted password. */
    fun passwordPayload(entry: PasswordEntry, fields: List<CustomField>): JsonObject {
        val type = passwordType(entry)
        val websites = entry.website.split('\n').map { it.trim() }.filter { it.isNotEmpty() }
        return buildJsonObject {
            put("v", 1)
            put("name", entry.title)
            putIfNotBlank("notes", entry.notes)
            if (websites.isNotEmpty()) put("uris", JsonArray(websites.map(::JsonPrimitive)))
            putFields(fields.sortedBy { it.sortOrder }.map { Triple(it.title, it.value, it.isProtected) })
            when (type) {
                TYPE_WIFI -> {
                    val wifi = WifiData.fromJsonOrEmpty(entry.wifiMetadata)
                    put("wifi", buildJsonObject {
                        put("ssid", wifi.ssid)
                        put("password", entry.password)
                        put("security", wifi.security.name)
                        put("hidden", wifi.hiddenNetwork)
                    })
                }
                TYPE_SSH_KEY -> {
                    val ssh = SshKeyDataCodec.decode(entry.sshKeyData) ?: SshKeyData()
                    put("sshKey", buildJsonObject {
                        put("publicKey", ssh.publicKeyOpenSsh)
                        put("privateKey", ssh.privateKeyOpenSsh)
                        put("fingerprint", ssh.fingerprintSha256)
                    })
                }
            }
            if (type != TYPE_WIFI || entry.username.isNotBlank()) {
                put("login", buildJsonObject {
                    putIfNotBlank("username", entry.username)
                    if (type != TYPE_WIFI) putIfNotBlank("password", entry.password)
                    putIfNotBlank("totp", entry.authenticatorKey)
                    put("loginType", entry.loginType.ifBlank { "PASSWORD" })
                    putIfNotBlank("ssoProvider", entry.ssoProvider)
                })
            }
            put("monica", buildJsonObject {
                put("kind", "password")
                put("createdAt", entry.createdAt.time)
                put("sortOrder", entry.sortOrder)
                put("isGroupCover", entry.isGroupCover)
                putIfNotBlank("appPackageName", entry.appPackageName)
                putIfNotBlank("appName", entry.appName)
                putIfNotBlank("email", entry.email)
                putIfNotBlank("phone", entry.phone)
                putIfNotBlank("addressLine", entry.addressLine)
                putIfNotBlank("city", entry.city)
                putIfNotBlank("state", entry.state)
                putIfNotBlank("zipCode", entry.zipCode)
                putIfNotBlank("country", entry.country)
                putIfNotBlank("creditCardNumber", entry.creditCardNumber)
                putIfNotBlank("creditCardHolder", entry.creditCardHolder)
                putIfNotBlank("creditCardExpiry", entry.creditCardExpiry)
                putIfNotBlank("creditCardCVV", entry.creditCardCVV)
                putIfNotBlank("passkeyBindings", entry.passkeyBindings)
                putIfNotBlank("wifiMetadata", entry.wifiMetadata)
                putIfNotBlank("sshKeyData", entry.sshKeyData)
                if (entry.customIconType != "NONE") {
                    put("customIconType", entry.customIconType)
                    put("customIconValue", entry.customIconValue)
                    put("customIconUpdatedAt", entry.customIconUpdatedAt)
                }
            })
        }
    }

    /**
     * Build the local entity for a remote payload. [base] is the existing local entry (plaintext)
     * or null for a new one. Returns the entry (plaintext password) and its custom fields
     * (with `entryId = 0`; the store assigns it).
     */
    fun applyPassword(
        base: PasswordEntry?,
        type: Int,
        payload: JsonObject,
        favorite: Boolean,
        archived: Boolean,
        trashed: Boolean,
        categoryId: Long?,
    ): Pair<PasswordEntry, List<CustomField>> {
        val m = payload.obj("monica")?.takeIf { it.str("kind") == "password" }
        val login = payload.obj("login")
        val wifi = payload.obj("wifi")
        val ssh = payload.obj("sshKey")
        val now = Date()
        val start = base ?: PasswordEntry(title = "", website = "", username = "", password = "")

        val loginType = when (type) {
            TYPE_WIFI -> "WIFI"
            else -> login?.str("loginType")?.takeIf { it.isNotBlank() && it != "WIFI" } ?: "PASSWORD"
        }
        val storedWifi = m?.str("wifiMetadata") ?: start.wifiMetadata
        val storedSsh = m?.str("sshKeyData") ?: start.sshKeyData
        val wifiMetadata = if (type == TYPE_WIFI) {
            val stored = WifiData.fromJsonOrEmpty(storedWifi)
            val sameAsStored = wifi?.str("ssid") == stored.ssid && wifi.bool("hidden") == stored.hiddenNetwork &&
                wifi.str("security") == stored.security.name && storedWifi.isNotBlank()
            if (sameAsStored) storedWifi else stored.copy(
                ssid = wifi?.str("ssid") ?: stored.ssid,
                hiddenNetwork = wifi?.bool("hidden") ?: stored.hiddenNetwork,
                security = wifi?.str("security")?.let { s -> WifiSecurity.entries.firstOrNull { it.name == s } } ?: stored.security,
            ).toJson()
        } else {
            m?.str("wifiMetadata") ?: ""
        }
        val sshKeyData = if (type == TYPE_SSH_KEY) {
            val stored = SshKeyDataCodec.decode(storedSsh) ?: SshKeyData()
            val sameAsStored = ssh?.str("publicKey") == stored.publicKeyOpenSsh &&
                ssh.str("privateKey") == stored.privateKeyOpenSsh && ssh.str("fingerprint") == stored.fingerprintSha256 &&
                storedSsh.isNotBlank()
            if (sameAsStored) storedSsh else SshKeyDataCodec.encode(
                stored.copy(
                    publicKeyOpenSsh = ssh?.str("publicKey") ?: stored.publicKeyOpenSsh,
                    privateKeyOpenSsh = ssh?.str("privateKey") ?: stored.privateKeyOpenSsh,
                    fingerprintSha256 = ssh?.str("fingerprint") ?: stored.fingerprintSha256,
                ),
            )
        } else {
            m?.str("sshKeyData") ?: ""
        }
        val password = when (type) {
            TYPE_WIFI -> wifi?.str("password") ?: login?.str("password").orEmpty()
            else -> login?.str("password").orEmpty()
        }

        val entry = start.copy(
            title = payload.str("name").orEmpty(),
            website = payload.array("uris").mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.joinToString("\n"),
            username = login?.str("username").orEmpty(),
            password = password,
            notes = payload.str("notes").orEmpty(),
            createdAt = m?.long("createdAt")?.let(::Date) ?: base?.createdAt ?: now,
            updatedAt = now,
            isFavorite = favorite,
            sortOrder = m?.int("sortOrder") ?: start.sortOrder,
            isGroupCover = m?.bool("isGroupCover") ?: false,
            appPackageName = m?.str("appPackageName").orEmpty(),
            appName = m?.str("appName").orEmpty(),
            email = m?.str("email").orEmpty(),
            phone = m?.str("phone").orEmpty(),
            addressLine = m?.str("addressLine").orEmpty(),
            city = m?.str("city").orEmpty(),
            state = m?.str("state").orEmpty(),
            zipCode = m?.str("zipCode").orEmpty(),
            country = m?.str("country").orEmpty(),
            creditCardNumber = m?.str("creditCardNumber").orEmpty(),
            creditCardHolder = m?.str("creditCardHolder").orEmpty(),
            creditCardExpiry = m?.str("creditCardExpiry").orEmpty(),
            creditCardCVV = m?.str("creditCardCVV").orEmpty(),
            categoryId = categoryId,
            authenticatorKey = login?.str("totp").orEmpty(),
            passkeyBindings = m?.str("passkeyBindings") ?: start.passkeyBindings,
            sshKeyData = sshKeyData,
            loginType = loginType,
            ssoProvider = login?.str("ssoProvider").orEmpty(),
            wifiMetadata = wifiMetadata,
            customIconType = m?.str("customIconType") ?: "NONE",
            customIconValue = m?.str("customIconValue"),
            customIconUpdatedAt = m?.long("customIconUpdatedAt") ?: 0L,
            isDeleted = trashed,
            deletedAt = if (trashed) start.deletedAt ?: now else null,
            isArchived = archived,
            archivedAt = if (archived) start.archivedAt ?: now else null,
        )
        val fields = payload.array("fields").mapIndexedNotNull { index, element ->
            val field = element as? JsonObject ?: return@mapIndexedNotNull null
            CustomField(
                entryId = start.id,
                title = field.str("name").orEmpty(),
                value = field.str("value").orEmpty(),
                isProtected = field.bool("hidden") ?: false,
                sortOrder = index,
            )
        }
        return entry to fields
    }

    // ================================================================== secure items

    fun secureType(itemType: ItemType): Int? = when (itemType) {
        ItemType.NOTE -> TYPE_NOTE
        ItemType.BANK_CARD -> TYPE_CARD
        ItemType.DOCUMENT -> TYPE_DOCUMENT
        ItemType.TOTP -> TYPE_TOTP
        ItemType.BILLING_ADDRESS -> TYPE_ADDRESS
        ItemType.PAYMENT_ACCOUNT -> TYPE_PAYMENT
        ItemType.PASSWORD -> null // legacy secure-item passwords stay local
    }

    fun itemTypeFor(type: Int): ItemType? = when (type) {
        TYPE_NOTE -> ItemType.NOTE
        TYPE_CARD -> ItemType.BANK_CARD
        TYPE_DOCUMENT -> ItemType.DOCUMENT
        TYPE_TOTP -> ItemType.TOTP
        TYPE_ADDRESS -> ItemType.BILLING_ADDRESS
        TYPE_PAYMENT -> ItemType.PAYMENT_ACCOUNT
        else -> null
    }

    /** [item] must carry decrypted `itemData`. */
    fun securePayload(item: SecureItem): JsonObject = buildJsonObject {
        put("v", 1)
        put("name", item.title)
        if (item.itemType == ItemType.NOTE) {
            putIfNotBlank("notes", decodeNote(item.itemData, item.notes).content)
        } else {
            putIfNotBlank("notes", item.notes)
        }
        secureSection(item.itemType, item.itemData)?.let { (key, section) -> put(key, section) }
        put("monica", buildJsonObject {
            put("kind", "secure")
            put("itemType", item.itemType.name)
            put("createdAt", item.createdAt.time)
            put("sortOrder", item.sortOrder)
            put("itemData", item.itemData)
            if (item.itemType == ItemType.NOTE) putIfNotBlank("noteFieldNotes", item.notes)
        })
    }

    /** The normalized payload section (key and content) a secure item's data maps to. */
    private fun secureSection(itemType: ItemType, itemData: String): Pair<String, JsonObject>? = when (itemType) {
        ItemType.TOTP -> decodeTotp(itemData)?.let { totp ->
            "totp" to buildJsonObject {
                put("secret", totp.secret)
                putIfNotBlank("issuer", totp.issuer)
                putIfNotBlank("account", totp.accountName)
                put("digits", totp.digits)
                put("period", totp.period)
                put("algorithm", totp.algorithm)
                put("otpType", totp.otpType.name)
            }
        }
        ItemType.BANK_CARD -> CardWalletDataCodec.parseBankCardData(itemData)?.let { card ->
            "card" to buildJsonObject {
                putIfNotBlank("holder", card.cardholderName)
                putIfNotBlank("number", card.cardNumber)
                putIfNotBlank("expiry", formatExpiry(card.expiryMonth, card.expiryYear))
                putIfNotBlank("cvv", card.cvv)
                putIfNotBlank("brand", card.brand)
            }
        }
        ItemType.DOCUMENT -> CardWalletDataCodec.parseDocumentData(itemData)?.let { doc ->
            "document" to buildJsonObject {
                put("kind", doc.documentType.name)
                putIfNotBlank("number", doc.documentNumber)
                putIfNotBlank("holder", doc.fullName)
                putIfNotBlank("issuedBy", doc.issuedBy)
                putIfNotBlank("expiry", doc.expiryDate)
            }
        }
        ItemType.BILLING_ADDRESS -> CardWalletDataCodec.parseBillingAddressData(itemData)?.let { a ->
            "address" to buildJsonObject {
                putIfNotBlank("fullName", a.fullName)
                putIfNotBlank("line1", a.streetAddress)
                putIfNotBlank("line2", a.apartment)
                putIfNotBlank("city", a.city)
                putIfNotBlank("state", a.stateProvince)
                putIfNotBlank("zip", a.postalCode)
                putIfNotBlank("country", a.country)
                putIfNotBlank("phone", a.phone)
                putIfNotBlank("email", a.email)
            }
        }
        ItemType.PAYMENT_ACCOUNT -> CardWalletDataCodec.parsePaymentAccountData(itemData)?.let { p ->
            "payment" to buildJsonObject {
                putIfNotBlank("provider", p.provider)
                putIfNotBlank("account", p.accountName.ifBlank { p.accountId })
                putIfNotBlank("holder", p.accountHolderName)
            }
        }
        else -> null
    }

    /** Build the local secure item for a remote payload. Returns null for types this client cannot store. */
    fun applySecure(
        base: SecureItem?,
        type: Int,
        payload: JsonObject,
        favorite: Boolean,
        trashed: Boolean,
        categoryId: Long?,
    ): SecureItem? {
        val itemType = itemTypeFor(type) ?: return null
        val m = payload.obj("monica")?.takeIf { it.str("kind") == "secure" && it.str("itemType") == itemType.name }
        val storedData = m?.str("itemData") ?: base?.itemData?.takeIf { base.itemType == itemType } ?: ""
        val now = Date()
        val notes = payload.str("notes").orEmpty()

        val unchanged = when (itemType) {
            ItemType.NOTE -> decodeNote(storedData, "").content == notes
            else -> secureSection(itemType, storedData)?.let { (key, section) -> payload[key] == section } ?: false
        }
        val itemData = if (unchanged) storedData else when (itemType) {
            ItemType.NOTE -> {
                val note = decodeNote(storedData, "")
                json.encodeToString(NoteData.serializer(), note.copy(content = notes))
            }
            ItemType.TOTP -> {
                val t = payload.obj("totp")
                val stored = decodeTotp(storedData) ?: TotpData(secret = "")
                json.encodeToString(
                    TotpData.serializer(),
                    stored.copy(
                        secret = t?.str("secret") ?: stored.secret,
                        issuer = t?.str("issuer") ?: stored.issuer,
                        accountName = t?.str("account") ?: stored.accountName,
                        digits = t?.int("digits") ?: stored.digits,
                        period = t?.int("period") ?: stored.period,
                        algorithm = t?.str("algorithm") ?: stored.algorithm,
                    ),
                )
            }
            ItemType.BANK_CARD -> {
                val c = payload.obj("card")
                val stored = CardWalletDataCodec.parseBankCardData(storedData) ?: BankCardData(cardNumber = "", cardholderName = "", expiryMonth = "", expiryYear = "")
                val (month, year) = parseExpiry(c?.str("expiry")) ?: (stored.expiryMonth to stored.expiryYear)
                CardWalletDataCodec.encodeBankCardData(
                    stored.copy(
                        cardNumber = c?.str("number") ?: stored.cardNumber,
                        cardholderName = c?.str("holder") ?: stored.cardholderName,
                        expiryMonth = month,
                        expiryYear = year,
                        cvv = c?.str("cvv") ?: stored.cvv,
                        brand = c?.str("brand").orEmpty(),
                    ),
                )
            }
            ItemType.DOCUMENT -> {
                val d = payload.obj("document")
                val stored = CardWalletDataCodec.parseDocumentData(storedData) ?: DocumentData(documentType = DocumentType.OTHER, documentNumber = "", fullName = "")
                CardWalletDataCodec.encodeDocumentData(
                    stored.copy(
                        documentType = d?.str("kind")?.let { k -> DocumentType.entries.firstOrNull { it.name == k } } ?: stored.documentType,
                        documentNumber = d?.str("number") ?: stored.documentNumber,
                        fullName = d?.str("holder") ?: stored.fullName,
                        issuedBy = d?.str("issuedBy") ?: stored.issuedBy,
                        expiryDate = d?.str("expiry") ?: stored.expiryDate,
                    ),
                )
            }
            ItemType.BILLING_ADDRESS -> {
                val a = payload.obj("address")
                val stored = CardWalletDataCodec.parseBillingAddressData(storedData) ?: BillingAddressData()
                CardWalletDataCodec.encodeBillingAddressData(
                    stored.copy(
                        fullName = a?.str("fullName") ?: stored.fullName,
                        streetAddress = a?.str("line1") ?: stored.streetAddress,
                        apartment = a?.str("line2") ?: stored.apartment,
                        city = a?.str("city") ?: stored.city,
                        stateProvince = a?.str("state") ?: stored.stateProvince,
                        postalCode = a?.str("zip") ?: stored.postalCode,
                        country = a?.str("country") ?: stored.country,
                        phone = a?.str("phone") ?: stored.phone,
                        email = a?.str("email") ?: stored.email,
                    ),
                )
            }
            ItemType.PAYMENT_ACCOUNT -> {
                val p = payload.obj("payment")
                val stored = CardWalletDataCodec.parsePaymentAccountData(storedData) ?: PaymentAccountData()
                CardWalletDataCodec.encodePaymentAccountData(
                    stored.copy(
                        provider = p?.str("provider") ?: stored.provider,
                        accountName = p?.str("account")?.takeIf { it != stored.accountId } ?: stored.accountName,
                        accountHolderName = p?.str("holder") ?: stored.accountHolderName,
                    ),
                )
            }
            ItemType.PASSWORD -> return null
        }

        val start = base?.takeIf { it.itemType == itemType } ?: SecureItem(itemType = itemType, title = "", itemData = "")
        return start.copy(
            id = base?.id ?: 0,
            itemType = itemType,
            title = payload.str("name").orEmpty(),
            notes = if (itemType == ItemType.NOTE) m?.str("noteFieldNotes").orEmpty() else notes,
            isFavorite = favorite,
            sortOrder = m?.int("sortOrder") ?: start.sortOrder,
            createdAt = m?.long("createdAt")?.let(::Date) ?: base?.createdAt ?: now,
            updatedAt = now,
            itemData = itemData,
            categoryId = categoryId,
            isDeleted = trashed,
            deletedAt = if (trashed) start.deletedAt ?: now else null,
        )
    }

    // ================================================================== passkeys

    /**
     * [privateKeyPkcs8] is the exportable PKCS#8 key (Base64), or null for a device-bound
     * credential whose key lives only in Android Keystore (protocol §2.1).
     */
    fun passkeyPayload(entry: PasskeyEntry, privateKeyPkcs8: String?): JsonObject = buildJsonObject {
        put("v", 1)
        put("name", entry.rpName.ifBlank { entry.rpId })
        putIfNotBlank("notes", entry.notes)
        if (entry.rpId.isNotBlank()) put("uris", JsonArray(listOf(JsonPrimitive("https://${entry.rpId}"))))
        put("passkey", buildJsonObject {
            put("credentialId", entry.credentialId)
            put("keyType", "public-key")
            put("keyAlgorithm", if (entry.publicKeyAlgorithm == PasskeyEntry.ALGORITHM_RS256) "RSA" else "ECDSA")
            put("keyCurve", "P-256")
            put("keyValue", privateKeyPkcs8.orEmpty())
            put("rpId", entry.rpId)
            putIfNotBlank("rpName", entry.rpName)
            put("userHandle", entry.userId)
            putIfNotBlank("userName", entry.userName)
            putIfNotBlank("userDisplayName", entry.userDisplayName)
            put("counter", 0)
            put("discoverable", entry.isDiscoverable)
            put("creationDate", java.time.Instant.ofEpochMilli(entry.createdAt).toString())
        })
        put("monica", buildJsonObject {
            put("kind", "passkey")
            put("publicKey", entry.publicKey)
            put("publicKeyAlgorithm", entry.publicKeyAlgorithm)
            put("transports", entry.transports)
            putIfNotBlank("aaguid", entry.aaguid)
            put("userVerificationRequired", entry.isUserVerificationRequired)
            put("passkeyMode", entry.passkeyMode)
            putIfNotBlank("iconUrl", entry.iconUrl.orEmpty())
            if (privateKeyPkcs8.isNullOrBlank()) put("passkeyDeviceBound", true)
        })
    }

    /**
     * Build the local passkey for a remote payload. Returns the entry plus the PKCS#8 key to
     * protect and store, or null to keep [base]'s key (never erase a key that only lives here).
     * Returns null when the payload has no credential.
     */
    fun applyPasskey(base: PasskeyEntry?, payload: JsonObject, categoryId: Long?): Pair<PasskeyEntry, String?>? {
        val p = payload.obj("passkey") ?: return null
        val credentialId = p.str("credentialId")?.takeIf { it.isNotBlank() } ?: return null
        val m = payload.obj("monica")?.takeIf { it.str("kind") == "passkey" }
        val keyValue = p.str("keyValue")?.takeIf { it.isNotBlank() }
        val createdAt = p.str("creationDate")?.let { runCatching { java.time.Instant.parse(it).toEpochMilli() }.getOrNull() }
        val start = base ?: PasskeyEntry(
            credentialId = credentialId,
            rpId = "",
            rpName = "",
            userId = "",
            userName = "",
            userDisplayName = "",
            publicKey = "",
            privateKeyAlias = "",
        )
        val entry = start.copy(
            credentialId = credentialId,
            rpId = p.str("rpId").orEmpty(),
            rpName = p.str("rpName") ?: payload.str("name").orEmpty(),
            userId = p.str("userHandle").orEmpty(),
            userName = p.str("userName").orEmpty(),
            userDisplayName = p.str("userDisplayName").orEmpty(),
            publicKeyAlgorithm = m?.int("publicKeyAlgorithm")
                ?: if (p.str("keyAlgorithm") == "RSA") PasskeyEntry.ALGORITHM_RS256 else PasskeyEntry.ALGORITHM_ES256,
            publicKey = m?.str("publicKey") ?: start.publicKey,
            createdAt = createdAt ?: start.createdAt,
            iconUrl = m?.str("iconUrl") ?: start.iconUrl,
            isDiscoverable = p.bool("discoverable") ?: true,
            isUserVerificationRequired = m?.bool("userVerificationRequired") ?: start.isUserVerificationRequired,
            transports = m?.str("transports") ?: start.transports,
            aaguid = m?.str("aaguid") ?: start.aaguid,
            isBackedUp = true,
            notes = payload.str("notes").orEmpty(),
            categoryId = categoryId,
            passkeyMode = m?.str("passkeyMode") ?: start.passkeyMode,
        )
        return entry to keyValue
    }

    // ================================================================== extras

    /** Payload keys written by other clients that this client does not map; kept so edits do not drop them. */
    fun foreignKeys(payload: JsonObject): JsonObject = JsonObject(payload.filterKeys { it !in KNOWN_KEYS })

    fun withForeignKeys(payload: JsonObject, extras: JsonObject?): JsonObject =
        if (extras.isNullOrEmpty()) payload else JsonObject(extras + payload)

    // ================================================================== helpers

    private fun decodeTotp(raw: String): TotpData? =
        runCatching { json.decodeFromString(TotpData.serializer(), raw) }.getOrNull()

    private fun decodeNote(raw: String, fallback: String): NoteData =
        runCatching { json.decodeFromString(NoteData.serializer(), raw) }.getOrNull()
            ?: NoteData(content = raw.ifBlank { fallback })

    private fun formatExpiry(month: String, year: String): String {
        if (month.isBlank() && year.isBlank()) return ""
        return "${month.padStart(2, '0')}/${year.takeLast(2)}"
    }

    private fun parseExpiry(raw: String?): Pair<String, String>? {
        val match = Regex("""^\s*(\d{1,2})\s*/\s*(\d{2}|\d{4})\s*$""").find(raw ?: return null) ?: return null
        val (month, year) = match.destructured
        return month.padStart(2, '0') to (if (year.length == 2) "20$year" else year)
    }

    private fun JsonObjectBuilder.putIfNotBlank(key: String, value: String?) {
        if (!value.isNullOrBlank()) put(key, value)
    }

    private fun JsonObjectBuilder.putFields(fields: List<Triple<String, String, Boolean>>) {
        if (fields.isEmpty()) return
        put("fields", buildJsonArray {
            for ((name, value, hidden) in fields) {
                add(buildJsonObject {
                    put("name", name)
                    put("value", value)
                    put("hidden", hidden)
                })
            }
        })
    }

    private fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject

    private fun JsonObject.array(key: String): List<JsonElement> = (this[key] as? JsonArray).orEmpty()

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull

    private fun JsonObject.bool(key: String): Boolean? = (this[key] as? JsonPrimitive)?.booleanOrNull

    private fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull

    private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull
}
