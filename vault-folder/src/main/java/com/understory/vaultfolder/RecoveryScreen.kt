package com.understory.vaultfolder

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.RecoveryCopy
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The re-bind recovery screen. Reached when the unlock path classifies the
 * device-auth key as [com.understory.security.VaultRecovery.VaultKeyState
 * .PERMANENTLY_INVALIDATED] — a fingerprint was re-enrolled or the lock screen
 * changed, so Android destroyed the shared device-auth key and the vault's
 * `header.bin` is now un-unwrappable.
 *
 * SELF-SEALING FILE MODEL (operator directive 2026-07-03 — "the screen is the
 * enemy"). The user never types or sees a recovery key. Two honest paths:
 *
 *  1. SILENT re-bind from the in-vault sealed kit. Tried FIRST, automatically,
 *     with nothing on screen: the non-auth [com.understory.backup.RecoveryWrapKey]
 *     survived the re-enrollment, so [VaultFolder.rebindFromSealedKit] can read
 *     the vault KEK straight back and re-wrap it under a fresh device-auth key
 *     (one biometric prompt). If it succeeds the vault is usable again and the
 *     user is returned to unlock without ever seeing this screen's body.
 *  2. If the sealed kit is gone (app data cleared, migrated device), fall back
 *     to "Restore from your recovery file" — a SAF `OpenDocument` import of the
 *     opaque recovery file the user exported earlier. Still no typing.
 *  3. RESET — neither path available → route to the shared reset screen.
 */
@Composable
fun RecoveryScreen(
    activity: FragmentActivity,
    onRebound: () -> Unit,
    onReset: () -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val hasKit = remember { VaultFolder.hasSealedKit(ctx) }

    // null = not yet attempted; true/false = silent re-bind result.
    var silentTried by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    // Import launcher for the fallback "restore from your recovery file" path.
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        VaultFolderManager.endTransientFlight()
        if (uri == null) return@rememberLauncherForActivityResult
        working = true; error = null; status = null
        rebindFromFile(
            activity = activity,
            scope = scope,
            uri = uri,
            onStatus = { status = it },
            onError = { msg -> error = msg; working = false },
            onDone = { working = false; onRebound() },
        )
    }

    // Attempt the SILENT sealed-kit re-bind exactly once, before showing any
    // fallback UI. Nothing is rendered for this path beyond the spinner + the
    // single device-auth prompt the framework raises.
    LaunchedEffect(Unit) {
        if (!hasKit) { silentTried = true; return@LaunchedEffect }
        working = true
        silentRebind(
            activity = activity,
            scope = scope,
            onError = { msg ->
                // Silent path failed (kit undecryptable, or auth declined): fall
                // through to the file-import fallback rather than dead-ending.
                Diagnostics.log("vault-folder.Recovery", "silent re-bind unavailable: $msg")
                silentTried = true; working = false
            },
            onDone = { working = false; onRebound() },
        )
    }

    SuiteScaffold(
        title = stringResource(R.string.recovery_title),
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                RecoveryCopy.INVALIDATED_BODY,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            status?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = UnderstoryTheme.semantic.success)
            }
            error?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
            }
            if (working) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                CircularProgressIndicator()
            }

            // Until the silent attempt resolves, show only the spinner — no
            // fallback buttons that would flash and vanish on a silent success.
            if (!silentTried) return@Column

            Text(
                stringResource(R.string.recovery_import_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SecureButton(
                onClick = {
                    if (working) return@SecureButton
                    VaultFolderManager.beginTransientFlight()
                    runCatching { importLauncher.launch(arrayOf("application/octet-stream", "*/*")) }
                        .onFailure {
                            VaultFolderManager.endTransientFlight()
                            error = ctx.getString(R.string.recovery_import_open_failed, it.message)
                        }
                },
                enabled = !working,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.recovery_import_action)) }

            SecureOutlinedButton(onClick = onReset, enabled = !working, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.recovery_reset_action))
            }
            SecureOutlinedButton(onClick = onClose, enabled = !working, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_close))
            }
        }
    }
}

/**
 * Silent same-device re-bind from the in-vault sealed kit. Mints a fresh
 * device-auth cipher, drives ONE BiometricPrompt, and on auth re-wraps the
 * recovered KEK off the main thread — nothing rendered, no key entered. On any
 * failure (kit gone / undecryptable / auth declined) calls [onError] so the
 * screen can offer the file-import fallback.
 */
private fun silentRebind(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    onError: (String) -> Unit,
    onDone: () -> Unit,
) {
    // The invalidated key may still hold its alias on some OEMs; delete it so
    // deviceAuthCipherForEncrypt mints a fresh one.
    runCatching { Crypto.deleteDeviceAuthKey() }
    val cipher = runCatching { Crypto.deviceAuthCipherForEncrypt() }.getOrElse {
        onError("Could not create a new device key: ${it.message}"); return
    }
    promptDeviceAuth(
        activity = activity,
        title = activity.getString(R.string.auth_bind_title),
        subtitle = activity.getString(R.string.app_name),
        cipher = cipher,
        onSuccess = { authed ->
            scope.launch {
                val outcome = runCatching {
                    withContext(Bg.io) {
                        VaultFolder.rebindFromSealedKit(activity.applicationContext, authed)
                    }
                }
                outcome.fold(
                    onSuccess = { ok ->
                        if (!ok) { onError("sealed kit absent or undecryptable"); return@fold }
                        Diagnostics.log("vault-folder.Recovery", "silent re-bind from sealed kit ok")
                        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) onDone()
                        else onError("Interrupted — re-open the app to finish recovery.")
                    },
                    onFailure = { onError(it.message ?: "silent re-bind failed") },
                )
            }
        },
        onError = { msg -> onError("Authentication failed: $msg") },
        onCancel = { onError("Authentication cancelled.") },
    )
}

/**
 * Fallback re-bind from an exported recovery file the user picked via SAF.
 * Mints a fresh device-auth cipher, drives ONE BiometricPrompt, then imports
 * the opaque file and re-wraps the recovered KEK off the main thread. No key is
 * typed — the recovery secret travels inside the file.
 */
private fun rebindFromFile(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    uri: Uri,
    onStatus: (String) -> Unit,
    onError: (String) -> Unit,
    onDone: () -> Unit,
) {
    runCatching { Crypto.deleteDeviceAuthKey() }
    val cipher = runCatching { Crypto.deviceAuthCipherForEncrypt() }.getOrElse {
        onError("Could not create a new device key: ${it.message}"); return
    }
    onStatus(activity.getString(R.string.recovery_import_working))
    promptDeviceAuth(
        activity = activity,
        title = activity.getString(R.string.auth_bind_title),
        subtitle = activity.getString(R.string.app_name),
        cipher = cipher,
        onSuccess = { authed ->
            scope.launch {
                val outcome = runCatching {
                    withContext(Bg.io) {
                        activity.contentResolver.openInputStream(uri)?.use { input ->
                            VaultFolder.rebindFromRecoveryFile(activity.applicationContext, input, authed)
                        } ?: error("Could not open the chosen file.")
                    }
                }
                outcome.fold(
                    onSuccess = {
                        Diagnostics.log("vault-folder.Recovery", "re-bind from recovery file ok")
                        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) onDone()
                        else onError("Interrupted — re-open the app to finish recovery.")
                    },
                    onFailure = { onError(activity.getString(R.string.recovery_import_bad_file)) },
                )
            }
        },
        onError = { msg -> onError("Authentication failed: $msg") },
        onCancel = { onError("Authentication cancelled.") },
    )
}
