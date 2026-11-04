package takagi.ru.monica.cloud.ui

import android.text.format.DateUtils
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.CloudSync
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Mail
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import takagi.ru.monica.R
import takagi.ru.monica.cloud.MonicaCloudError
import takagi.ru.monica.cloud.MonicaCloudManager
import takagi.ru.monica.cloud.MonicaCloudState

/**
 * Settings → Sync & backup → Monica Cloud. Log in with a custom server address; once signed
 * in, shows sync status and lets the user sync now or sign out.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MonicaCloudScreen(onNavigateBack: () -> Unit) {
    val context = LocalContext.current
    val manager = remember { MonicaCloudManager.get(context) }
    val state by manager.state.collectAsState()
    val scope = rememberCoroutineScope()
    var relogin by rememberSaveable { mutableStateOf(false) }
    var confirmLogout by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.monica_cloud_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.go_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (!state.loggedIn || relogin) {
                LoginForm(
                    initialServer = state.serverUrl,
                    initialEmail = state.email,
                    allowRegister = !relogin,
                    onSubmit = { server, email, password, register, name ->
                        manager.login(server, email, password, register, name)
                        relogin = false
                    },
                )
            } else {
                AccountCard(state)
                StatusCard(
                    state = state,
                    onSync = { scope.launch { manager.syncNow() } },
                    onRelogin = { relogin = true },
                )
                ScopeCard()
                OutlinedButton(onClick = { confirmLogout = true }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.AutoMirrored.Filled.Logout, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.monica_cloud_logout))
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (confirmLogout) {
        AlertDialog(
            onDismissRequest = { confirmLogout = false },
            title = { Text(stringResource(R.string.monica_cloud_logout_title)) },
            text = { Text(stringResource(R.string.monica_cloud_logout_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmLogout = false
                    scope.launch { manager.logout() }
                }) { Text(stringResource(R.string.monica_cloud_logout)) }
            },
            dismissButton = { TextButton(onClick = { confirmLogout = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }

    state.emptyVaultLinkedItems?.let { count ->
        AlertDialog(
            onDismissRequest = {},
            icon = { Icon(Icons.Outlined.Warning, contentDescription = null) },
            title = { Text(stringResource(R.string.monica_cloud_empty_title)) },
            text = { Text(stringResource(R.string.monica_cloud_empty_body, count)) },
            confirmButton = {
                TextButton(onClick = { scope.launch { manager.syncNow(allowEmptyRemote = true) } }) {
                    Text(stringResource(R.string.monica_cloud_empty_accept))
                }
            },
            dismissButton = {
                TextButton(onClick = { scope.launch { manager.logout() } }) {
                    Text(stringResource(R.string.monica_cloud_empty_disconnect))
                }
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LoginForm(
    initialServer: String,
    initialEmail: String,
    allowRegister: Boolean,
    onSubmit: suspend (server: String, email: String, password: String, register: Boolean, name: String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    var server by rememberSaveable { mutableStateOf(initialServer) }
    var email by rememberSaveable { mutableStateOf(initialEmail) }
    var name by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var register by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val errorText = errorStrings()
    val shortError = stringResource(R.string.monica_cloud_error_password_short)
    val mismatchError = stringResource(R.string.monica_cloud_error_password_mismatch)
    val requiredError = stringResource(R.string.monica_cloud_error_required)

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(Icons.Outlined.CloudSync, contentDescription = null, modifier = Modifier.size(32.dp), tint = MaterialTheme.colorScheme.primary)
            Column {
                Text(stringResource(R.string.monica_cloud_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(
                    stringResource(R.string.monica_cloud_intro),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
                )
            }
        }
    }

    if (allowRegister) {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            SegmentedButton(selected = !register, onClick = { register = false }, shape = SegmentedButtonDefaults.itemShape(0, 2)) {
                Text(stringResource(R.string.monica_cloud_login))
            }
            SegmentedButton(selected = register, onClick = { register = true }, shape = SegmentedButtonDefaults.itemShape(1, 2)) {
                Text(stringResource(R.string.monica_cloud_register))
            }
        }
    }

    OutlinedTextField(
        value = server,
        onValueChange = { server = it.trim() },
        label = { Text(stringResource(R.string.monica_cloud_server)) },
        placeholder = { Text("https://cloud.example.com") },
        leadingIcon = { Icon(Icons.Outlined.Cloud, contentDescription = null) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Next),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
        supportingText = if (server.startsWith("http://", ignoreCase = true)) {
            { Text(stringResource(R.string.monica_cloud_http_warning), color = MaterialTheme.colorScheme.error) }
        } else {
            null
        },
    )
    OutlinedTextField(
        value = email,
        onValueChange = { email = it.trim() },
        label = { Text(stringResource(R.string.monica_cloud_email)) },
        leadingIcon = { Icon(Icons.Outlined.Mail, contentDescription = null) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    AnimatedVisibility(visible = register) {
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.monica_cloud_name)) },
            leadingIcon = { Icon(Icons.Outlined.Person, contentDescription = null) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
    }
    OutlinedTextField(
        value = password,
        onValueChange = { password = it },
        label = { Text(stringResource(R.string.monica_cloud_master_password)) },
        leadingIcon = { Icon(Icons.Outlined.Lock, contentDescription = null) },
        trailingIcon = {
            IconButton(onClick = { showPassword = !showPassword }) {
                Icon(if (showPassword) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, contentDescription = null)
            }
        },
        visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = if (register) ImeAction.Next else ImeAction.Done),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    AnimatedVisibility(visible = register) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text(stringResource(R.string.monica_cloud_confirm_password)) },
                leadingIcon = { Icon(Icons.Outlined.Lock, contentDescription = null) },
                visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Notice(stringResource(R.string.monica_cloud_no_recovery))
        }
    }

    error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }

    Button(
        onClick = {
            error = when {
                server.isBlank() || email.isBlank() || password.isEmpty() -> requiredError
                register && password.length < 12 -> shortError
                register && password != confirm -> mismatchError
                else -> null
            }
            if (error != null) return@Button
            busy = true
            scope.launch {
                try {
                    onSubmit(server, email, password, register, name)
                    password = ""
                    confirm = ""
                } catch (e: Exception) {
                    error = errorText(MonicaCloudManager.mapError(e))
                } finally {
                    busy = false
                }
            }
        },
        enabled = !busy,
        modifier = Modifier.fillMaxWidth().height(52.dp),
    ) {
        if (busy) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(12.dp))
            Text(stringResource(R.string.monica_cloud_deriving))
        } else {
            Text(stringResource(if (register) R.string.monica_cloud_register_action else R.string.monica_cloud_login_action))
        }
    }
    Notice(stringResource(R.string.monica_cloud_zero_knowledge))
}

@Composable
private fun AccountCard(state: MonicaCloudState) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(MaterialTheme.colorScheme.primary, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    (state.name.ifBlank { state.email }).take(1).uppercase(),
                    color = MaterialTheme.colorScheme.onPrimary,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            Column {
                Text(state.name.ifBlank { state.email }, style = MaterialTheme.typography.titleMedium)
                if (state.name.isNotBlank()) Text(state.email, style = MaterialTheme.typography.bodyMedium)
                Text(state.serverUrl, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun StatusCard(state: MonicaCloudState, onSync: () -> Unit, onRelogin: () -> Unit) {
    val errorText = errorStrings()
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                if (state.syncing) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                } else {
                    Icon(
                        if (state.lastError != null) Icons.Outlined.ErrorOutline else Icons.Outlined.Sync,
                        contentDescription = null,
                        tint = if (state.lastError != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                    )
                }
                Column(Modifier.weight(1f)) {
                    Text(
                        when {
                            state.syncing -> stringResource(R.string.monica_cloud_syncing)
                            state.lastSyncAt != null -> stringResource(
                                R.string.monica_cloud_last_sync,
                                DateUtils.getRelativeTimeSpanString(state.lastSyncAt, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS),
                            )
                            else -> stringResource(R.string.monica_cloud_never_synced)
                        },
                        style = MaterialTheme.typography.titleSmall,
                    )
                    if (state.lastSyncAt != null && state.lastError == null) {
                        val changes = if (state.lastPulled + state.lastPushed > 0) {
                            " · " + stringResource(R.string.monica_cloud_last_result, state.lastPulled, state.lastPushed)
                        } else {
                            ""
                        }
                        Text(
                            stringResource(R.string.monica_cloud_synced_items, state.syncedItems) + changes,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            if (state.lastConflicts > 0 && state.lastError == null) {
                Notice(stringResource(R.string.monica_cloud_conflicts, state.lastConflicts))
            }
            state.lastError?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
            if (state.lastError?.kind == MonicaCloudError.Kind.SESSION_EXPIRED) {
                Button(onClick = onRelogin, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.monica_cloud_relogin)) }
            } else {
                Button(onClick = onSync, enabled = !state.syncing, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.Sync, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.monica_cloud_sync_now))
                }
            }
        }
    }
}

@Composable
private fun ScopeCard() {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(stringResource(R.string.monica_cloud_scope), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun Notice(text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
        Icon(Icons.Outlined.Info, contentDescription = null, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Localised message for a [MonicaCloudError]; server details are appended when useful. */
@Composable
private fun errorStrings(): (MonicaCloudError) -> String {
    val network = stringResource(R.string.monica_cloud_error_network)
    val expired = stringResource(R.string.monica_cloud_error_session)
    val wrong = stringResource(R.string.monica_cloud_error_wrong_password)
    val changed = stringResource(R.string.monica_cloud_error_account_changed)
    val unsupported = stringResource(R.string.monica_cloud_error_unsupported)
    val generic = stringResource(R.string.monica_cloud_error_generic)
    return { error ->
        when (error.kind) {
            MonicaCloudError.Kind.NETWORK -> network
            MonicaCloudError.Kind.SESSION_EXPIRED -> expired
            MonicaCloudError.Kind.WRONG_PASSWORD -> wrong
            MonicaCloudError.Kind.ACCOUNT_CHANGED -> changed
            MonicaCloudError.Kind.UNSUPPORTED_DATA -> unsupported
            MonicaCloudError.Kind.SERVER, MonicaCloudError.Kind.OTHER ->
                if (error.detail.isBlank()) generic else "$generic: ${error.detail}"
        }
    }
}
