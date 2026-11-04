package takagi.ru.monica.cloud

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import takagi.ru.monica.cloud.mapper.MonicaCloudEntityMapper as M
import takagi.ru.monica.data.CustomField
import takagi.ru.monica.data.ItemType
import takagi.ru.monica.data.PasskeyEntry
import takagi.ru.monica.data.PasswordEntry
import takagi.ru.monica.data.SecureItem
import takagi.ru.monica.data.model.BankCardData
import takagi.ru.monica.data.model.CardWalletDataCodec
import takagi.ru.monica.data.model.TotpData
import takagi.ru.monica.data.model.WifiData
import takagi.ru.monica.data.model.WifiSecurity
import java.util.Date

class MonicaCloudEntityMapperTest {
    private val json = Json { ignoreUnknownKeys = true }
    private fun parse(text: String) = json.parseToJsonElement(text).jsonObject

    private val login = PasswordEntry(
        id = 7,
        title = "GitHub",
        website = "https://github.com",
        username = "octocat",
        password = "hunter2",
        notes = "recovery in attachment",
        createdAt = Date(1_700_000_000_000),
        isFavorite = true,
        sortOrder = 3,
        appPackageName = "com.github.android",
        email = "octo@example.com",
        categoryId = 5,
        authenticatorKey = "JBSWY3DPEHPK3PXP",
        isArchived = false,
    )
    private val fields = listOf(
        CustomField(id = 1, entryId = 7, title = "API token", value = "ghp_x", isProtected = true, sortOrder = 0),
        CustomField(id = 2, entryId = 7, title = "Recovery email", value = "r@example.com", isProtected = false, sortOrder = 1),
    )

    @Test
    fun passwordRoundTripIsLosslessAndStable() {
        val payload = M.passwordPayload(login, fields)
        assertEquals(M.TYPE_LOGIN, M.passwordType(login))
        assertEquals("hunter2", payload["login"]!!.jsonObject["password"]!!.jsonPrimitive.content)

        val (restored, restoredFields) = M.applyPassword(null, M.TYPE_LOGIN, payload, true, false, false, 5)
        assertEquals(login.title, restored.title)
        assertEquals(login.website, restored.website)
        assertEquals(login.username, restored.username)
        assertEquals(login.password, restored.password)
        assertEquals(login.notes, restored.notes)
        assertEquals(login.createdAt, restored.createdAt)
        assertEquals(login.appPackageName, restored.appPackageName)
        assertEquals(login.email, restored.email)
        assertEquals(login.authenticatorKey, restored.authenticatorKey)
        assertEquals(3, restored.sortOrder)
        assertEquals(5L, restored.categoryId)
        assertTrue(restored.isFavorite)
        assertEquals(fields.map { Triple(it.title, it.value, it.isProtected) }, restoredFields.map { Triple(it.title, it.value, it.isProtected) })

        // Mapping what we stored must give the same payload, or every sync would re-upload.
        assertEquals(payload, M.passwordPayload(restored, restoredFields))
    }

    @Test
    fun webUiEditOverridesNormalizedFieldsButKeepsMonicaOnes() {
        val payload = M.passwordPayload(login, fields)
        // The WebUI only touches normalized sections.
        val edited = JsonObject(
            payload + mapOf(
                "name" to kotlinx.serialization.json.JsonPrimitive("GitHub (work)"),
                "login" to parse("""{"username":"octo-work","password":"new-pass","loginType":"PASSWORD"}"""),
            ),
        )
        val (restored, _) = M.applyPassword(login, M.TYPE_LOGIN, edited, true, false, false, 5)
        assertEquals("GitHub (work)", restored.title)
        assertEquals("octo-work", restored.username)
        assertEquals("new-pass", restored.password)
        assertEquals("", restored.authenticatorKey) // removed in the WebUI
        assertEquals("com.github.android", restored.appPackageName) // CE-only, preserved
        assertEquals(7L, restored.id)
    }

    @Test
    fun itemCreatedInWebUiMapsToEntry() {
        val payload = parse(
            """{"v":1,"name":"Cloudflare","notes":"ops","uris":["dash.cloudflare.com","https://x.example"],
               "login":{"username":"ops@example.com","password":"cf"},
               "fields":[{"name":"PIN","value":"1234","hidden":true}]}""",
        )
        val (entry, entryFields) = M.applyPassword(null, M.TYPE_LOGIN, payload, false, true, false, null)
        assertEquals("Cloudflare", entry.title)
        assertEquals("dash.cloudflare.com\nhttps://x.example", entry.website)
        assertEquals("PASSWORD", entry.loginType)
        assertTrue(entry.isArchived)
        assertEquals(listOf("PIN"), entryFields.map { it.title })
        assertTrue(entryFields.single().isProtected)
        val again = M.passwordPayload(entry, entryFields)
        assertEquals(again, M.passwordPayload(M.applyPassword(null, M.TYPE_LOGIN, again, false, true, false, null).first, entryFields))
    }

    @Test
    fun wifiAndSshEntries() {
        val wifi = PasswordEntry(
            title = "Home", website = "", username = "", password = "wifi-pass", loginType = "WIFI",
            wifiMetadata = WifiData(ssid = "Lin-5G", hiddenNetwork = true, security = WifiSecurity.WPA3).toJson(),
        )
        val payload = M.passwordPayload(wifi, emptyList())
        assertEquals(M.TYPE_WIFI, M.passwordType(wifi))
        assertEquals("Lin-5G", payload["wifi"]!!.jsonObject["ssid"]!!.jsonPrimitive.content)
        val (restored, _) = M.applyPassword(null, M.TYPE_WIFI, payload, false, false, false, null)
        assertEquals("wifi-pass", restored.password)
        assertEquals("WIFI", restored.loginType)
        assertEquals(WifiSecurity.WPA3, WifiData.fromJsonOrEmpty(restored.wifiMetadata).security)
        assertEquals(payload, M.passwordPayload(restored, emptyList()))

        val ssh = parse("""{"v":1,"name":"Deploy","sshKey":{"publicKey":"ssh-ed25519 AAA","privateKey":"-----BEGIN","fingerprint":"SHA256:x"}}""")
        val (sshEntry, _) = M.applyPassword(null, M.TYPE_SSH_KEY, ssh, false, false, false, null)
        assertEquals(M.TYPE_SSH_KEY, M.passwordType(sshEntry))
        val sshPayload = M.passwordPayload(sshEntry, emptyList())
        assertEquals("SHA256:x", sshPayload["sshKey"]!!.jsonObject["fingerprint"]!!.jsonPrimitive.content)
    }

    @Test
    fun bankCardRoundTripAndWebUiEdit() {
        val card = SecureItem(
            id = 3, itemType = ItemType.BANK_CARD, title = "招商银行", isFavorite = true, createdAt = Date(1_700_000_000_000),
            itemData = CardWalletDataCodec.encodeBankCardData(
                BankCardData(cardNumber = "6225880123456789", cardholderName = "LIN", expiryMonth = "8", expiryYear = "2029", cvv = "123", bankName = "CMB", iban = "X1"),
            ),
        )
        val payload = M.securePayload(card)
        assertEquals("08/29", payload["card"]!!.jsonObject["expiry"]!!.jsonPrimitive.content)
        val restored = M.applySecure(card, M.TYPE_CARD, payload, true, false, null)!!
        assertEquals(payload, M.securePayload(restored))

        val edited = JsonObject(payload + ("card" to parse("""{"holder":"LIN","number":"6225880000000000","expiry":"11/31","cvv":"999"}""")))
        val after = CardWalletDataCodec.parseBankCardData(M.applySecure(card, M.TYPE_CARD, edited, true, false, null)!!.itemData)!!
        assertEquals("6225880000000000", after.cardNumber)
        assertEquals("11", after.expiryMonth)
        assertEquals("2031", after.expiryYear)
        assertEquals("X1", after.iban) // CE-only field survives
    }

    @Test
    fun totpNoteAndOtherSecureTypes() {
        val totp = SecureItem(itemType = ItemType.TOTP, title = "AWS", itemData = json.encodeToString(TotpData.serializer(), TotpData(secret = "ABC", issuer = "AWS", accountName = "root", steamDeviceId = "keep")))
        val tp = M.securePayload(totp)
        assertEquals("ABC", tp["totp"]!!.jsonObject["secret"]!!.jsonPrimitive.content)
        val restoredTotp = M.applySecure(null, M.TYPE_TOTP, tp, false, false, null)!!
        assertEquals("keep", json.decodeFromString(TotpData.serializer(), restoredTotp.itemData).steamDeviceId)
        assertEquals(tp, M.securePayload(restoredTotp))

        val note = M.applySecure(null, M.TYPE_NOTE, parse("""{"v":1,"name":"清单","notes":"1. 更新\n2. 备份"}"""), false, true, null)!!
        assertEquals(ItemType.NOTE, note.itemType)
        assertTrue(note.isDeleted)
        assertEquals("1. 更新\n2. 备份", M.securePayload(note)["notes"]!!.jsonPrimitive.content)

        for ((type, section) in listOf(M.TYPE_DOCUMENT to "document", M.TYPE_ADDRESS to "address", M.TYPE_PAYMENT to "payment")) {
            val webPayload = when (section) {
                "document" -> parse("""{"v":1,"name":"护照","document":{"kind":"PASSPORT","number":"E123","holder":"LIN"}}""")
                "address" -> parse("""{"v":1,"name":"家","address":{"fullName":"LIN","city":"上海","country":"CN"}}""")
                else -> parse("""{"v":1,"name":"支付宝","payment":{"provider":"Alipay","account":"lin@example.com"}}""")
            }
            val item = M.applySecure(null, type, webPayload, false, false, null)!!
            val out = M.securePayload(item)
            assertEquals(webPayload[section], out[section])
            assertEquals(out, M.securePayload(M.applySecure(item, type, out, false, false, null)!!))
        }
        assertNull(M.secureType(ItemType.PASSWORD))
    }

    @Test
    fun passkeyKeepsDeviceBoundKey() {
        val passkey = PasskeyEntry(
            id = 9, credentialId = "cred", rpId = "github.com", rpName = "GitHub", userId = "u1", userName = "octocat",
            userDisplayName = "Octo", publicKey = "pub", privateKeyAlias = "keystore-alias", createdAt = 1_700_000_000_000,
        )
        val bound = M.passkeyPayload(passkey, privateKeyPkcs8 = null)
        assertEquals("", bound["passkey"]!!.jsonObject["keyValue"]!!.jsonPrimitive.content)
        assertTrue(bound["monica"]!!.jsonObject.containsKey("passkeyDeviceBound"))
        val (applied, key) = M.applyPasskey(passkey, bound, null)!!
        assertNull(key) // caller keeps the existing Keystore alias
        assertEquals(passkey.copy(isBackedUp = true), applied.copy(privateKeyAlias = passkey.privateKeyAlias))

        val synced = M.passkeyPayload(passkey, privateKeyPkcs8 = "MIGHAgEA")
        assertEquals("MIGHAgEA", M.applyPasskey(null, synced, null)!!.second)
        assertEquals(0, synced["passkey"]!!.jsonObject["counter"]!!.jsonPrimitive.content.toInt())
    }

    @Test
    fun foreignKeysArePreserved() {
        val payload = parse("""{"v":1,"name":"x","login":{"username":"u"},"passwordHistory":[{"password":"old"}],"futureField":42}""")
        val foreign = M.foreignKeys(payload)
        assertEquals(setOf("passwordHistory", "futureField"), foreign.keys)
        val (entry, _) = M.applyPassword(null, M.TYPE_LOGIN, payload, false, false, false, null)
        val merged = M.withForeignKeys(M.passwordPayload(entry, emptyList()), foreign)
        assertEquals(payload["futureField"], merged["futureField"])
        assertFalse(M.withForeignKeys(merged, foreign).keys.count { it == "futureField" } > 1)
    }
}
