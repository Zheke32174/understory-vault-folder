package com.understory.vaultfolder

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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.RecoveryCopy
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.VaultRecovery
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The re-bind recovery screen (§4.2). Reached when the unlock path classifies
 * the device-auth key as [VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED]
 * — a fingerprint was re-enrolled or the lock screen changed, so Android
 * destroyed the shared device-auth key and every folder's `header.bin` is now
 * un-unwrappable.
 *
 * Two honest paths forward:
 *  1. RE-BIND — if the user saved a recovery key at setup, they enter it here.
 *     Each folder with a `recovery.bin` is recovered and re-wrapped under a
 *     freshly minted device-auth key (one biometric prompt per folder, because
 *     the device-auth key requires per-operation auth). No plaintext file ever
 *     touches disk. On success the vault is usable again.
 *  2. RESET — no recovery key → route to the shared [com.understory.security
 *     .VaultRecoveryScreen], which double-confirms and wipes.
 *
 * This is a NEW screen, authored token-native (shared components +
 * UnderstoryTheme) per the wave-2 rule.
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
    val recoverable = remember { VaultFolder.recoverableFolders(ctx) }
    var keyField by remember { mutableStateOf(TextFieldValue("")) }
    var status by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

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

            if (recoverable.isEmpty()) {
                // Nothing was escrowed — the only honest path is reset.
                Text(
                    stringResource(R.string.recovery_no_key),
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.warning,
                )
                SecureButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.recovery_reset_action))
                }
                SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.action_close))
                }
                return@Column
            }

            Text(
                stringResource(R.string.recovery_enter_key, recoverable.size),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = keyField,
                onValueChange = { keyField = it },
                singleLine = true,
                enabled = !working,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
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

            SecureButton(
                onClick = {
                    if (working || keyField.text.isBlank()) return@SecureButton
                    working = true
                    error = null
                    status = null
                    val entered = VaultRecovery.recoveryKeyFrom(keyField.text.toCharArray())
                    rebindAll(
                        activity = activity,
                        scope = scope,
                        recoverable = recoverable,
                        recoveryKey = entered,
                        onProgress = { done, total -> status = "Re-bound $done of $total folder(s)…" },
                        onError = { msg -> error = msg; working = false; entered.wipe() },
                        onDone = { entered.wipe(); working = false; onRebound() },
                    )
                },
                enabled = !working && keyField.text.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.recovery_rebind_action)) }

            SecureOutlinedButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.recovery_reset_action))
            }
            SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_close))
            }
        }
    }
}

/**
 * Re-bind every recoverable folder sequentially. Deletes the stale (invalidated)
 * device-auth key ONCE, then walks the folders: for each, mint a fresh
 * device-auth encrypt cipher, drive one BiometricPrompt, and on auth re-wrap
 * that folder's recovered KEK under the fresh key off the main thread.
 *
 * The recovery-key argon2 decrypt inside [VaultFolder.rebindFolder] is the
 * expensive part and runs on Bg.io; the biometric auth is inherently UI-thread
 * driven by the framework.
 */
private fun rebindAll(
    activity: FragmentActivity,
    scope: kotlinx.coroutines.CoroutineScope,
    recoverable: List<VaultFolders.FolderInfo>,
    recoveryKey: VaultRecovery.RecoveryKey,
    onProgress: (done: Int, total: Int) -> Unit,
    onError: (String) -> Unit,
    onDone: () -> Unit,
) {
    val total = recoverable.size
    // The invalidated key may still hold its alias on some OEMs; delete it so
    // deviceAuthCipherForEncrypt mints a fresh one.
    runCatching { Crypto.deleteDeviceAuthKey() }

    fun step(index: Int) {
        if (index >= total) { onDone(); return }
        val info = recoverable[index]
        val cipher = runCatching { Crypto.deviceAuthCipherForEncrypt() }.getOrElse {
            onError("Could not create a new device key: ${it.message}"); return
        }
        promptDeviceAuth(
            activity = activity,
            title = "Re-bind ${info.name}",
            subtitle = "Authenticate to restore access to this folder.",
            cipher = cipher,
            onSuccess = { authed ->
                scope.launch {
                    val outcome = runCatching {
                        withContext(Bg.io) {
                            VaultFolder.rebindFolder(
                                activity.applicationContext, info.id, recoveryKey.chars, authed,
                            )
                        }
                    }
                    outcome.fold(
                        onSuccess = {
                            Diagnostics.log("vault-folder.Recovery", "rebound ${info.id}")
                            onProgress(index + 1, total)
                            if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                step(index + 1)
                            } else {
                                onError("Interrupted — re-open the app to finish recovery.")
                            }
                        },
                        onFailure = { onError("Recovery failed: ${it.message ?: "wrong key or corrupt slot"}") },
                    )
                }
            },
            onError = { msg -> onError("Authentication failed: $msg") },
            onCancel = { onError("Authentication cancelled.") },
        )
    }
    step(0)
}
