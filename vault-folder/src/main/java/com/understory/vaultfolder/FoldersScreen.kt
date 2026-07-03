package com.understory.vaultfolder

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics

/**
 * Multi-folder hub. Lists every folder (default + secondaries),
 * exposes "Open" per folder and a "Create folder" entry. Each open
 * runs through device-auth biometric for the target folder's KEK,
 * and the parent swaps the unlocked store on success.
 *
 * The screen is navigation-only — it doesn't display the current
 * folder's file list; that's the existing [com.understory.vaultfolder]
 * .ListScreen, reached after a successful per-folder unlock.
 *
 * Why a separate screen rather than baking folder switching into
 * ListScreen: keeps the per-folder file UX uncluttered, mirrors the
 * Files / Photos pattern users expect from "secure folder" apps, and
 * the navigation stack stays linear (Folders → ListScreen → Add).
 */
@Composable
fun FoldersScreen(
    activity: FragmentActivity,
    currentFolderId: String?,
    onOpenFolder: (VaultFolderStore) -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    var refreshKey by remember { mutableStateOf(0) }
    val folders = remember(refreshKey) { VaultFolders.list(ctx) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    var showCreateDialog by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<VaultFolders.FolderInfo?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("folders", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Each folder has its own master key, biometric-released. " +
                "Switching folders prompts for biometric again. The " +
                "Default folder is the one created at first setup.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            items(folders, key = { it.id }) { folder ->
                FolderRow(
                    folder = folder,
                    isCurrent = folder.id == currentFolderId,
                    working = working,
                    onOpen = {
                        if (working) return@FolderRow
                        if (folder.id == currentFolderId) {
                            // Already unlocked; just navigate to its list.
                            // Caller passes through the existing store.
                            onBack()
                            return@FolderRow
                        }
                        Diagnostics.log("vault-folder.Folders", "open: ${folder.id}")
                        working = true
                        error = null
                        runCatching {
                            val iv = VaultFolder.ivForUnlock(ctx, folder.id)
                            val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                            promptAuthLocal(activity, "Unlock ${folder.name}", cipher,
                                onSuccess = { authed ->
                                    runCatching {
                                        val store = VaultFolder.unlock(ctx, authed, folder.id)
                                        if (activity.lifecycle.currentState
                                                .isAtLeast(Lifecycle.State.STARTED)
                                        ) {
                                            onOpenFolder(store)
                                        } else {
                                            store.lock()
                                        }
                                        working = false
                                    }.onFailure {
                                        error = "Decrypt failed: ${it.message}"
                                        working = false
                                    }
                                },
                                onError = { msg ->
                                    error = "Auth failed: $msg"; working = false
                                },
                                onCancel = {
                                    error = "Auth cancelled."; working = false
                                },
                            )
                        }.onFailure {
                            error = "Crypto init failed: ${it.message}"; working = false
                        }
                    },
                    onDelete = if (folder.isDefault) null else {
                        { pendingDelete = folder }
                    },
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { showCreateDialog = true },
            modifier = Modifier.fillMaxWidth(),
            enabled = !working,
        ) { Text("Create folder") }
        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Back") }
    }

    if (showCreateDialog) {
        CreateFolderDialog(
            activity = activity,
            onDismiss = { showCreateDialog = false },
            onCreated = { store ->
                showCreateDialog = false
                refreshKey++
                onOpenFolder(store)
            },
            onError = { msg ->
                showCreateDialog = false
                error = msg
            },
        )
    }

    pendingDelete?.let { folder ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Delete folder?") },
            text = {
                Text(
                    "Delete \"${folder.name}\"? This permanently shreds " +
                        "every file in it. This cannot be undone.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val ok = VaultFolders.delete(ctx, folder.id)
                    error = if (ok) "Deleted ${folder.name}." else "Delete failed."
                    pendingDelete = null
                    refreshKey++
                }) { Text("Delete", color = Color(0xFFEF5350)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun FolderRow(
    folder: VaultFolders.FolderInfo,
    isCurrent: Boolean,
    working: Boolean,
    onOpen: () -> Unit,
    onDelete: (() -> Unit)?,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (isCurrent) Color(0xFF1A2A1A) else Color(0xFF1C1C1C),
                RoundedCornerShape(6.dp),
            )
            .padding(12.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    folder.name,
                    color = Color(0xFFE0E0E0), fontSize = 14.sp,
                    modifier = Modifier.fillMaxWidth(0.7f),
                )
                if (isCurrent) {
                    Text("· unlocked", color = Color(0xFF66BB6A), fontSize = 11.sp)
                }
            }
            Text(
                if (folder.isDefault) "Default folder · created at setup"
                else "Created ${java.text.SimpleDateFormat(
                    "yyyy-MM-dd",
                    java.util.Locale.getDefault(),
                ).format(java.util.Date(folder.createdAtMs))}",
                color = Color(0xFF9E9E9E), fontSize = 11.sp,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onOpen,
                    enabled = !working,
                    modifier = if (onDelete != null) Modifier.fillMaxWidth(0.6f) else Modifier.fillMaxWidth(),
                ) { Text(if (isCurrent) "Open" else "Unlock") }
                if (onDelete != null) {
                    OutlinedButton(
                        onClick = onDelete,
                        enabled = !working,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Delete") }
                }
            }
        }
    }
}

@Composable
private fun CreateFolderDialog(
    activity: FragmentActivity,
    onDismiss: () -> Unit,
    onCreated: (VaultFolderStore) -> Unit,
    onError: (String) -> Unit,
) {
    val ctx = LocalContext.current
    var name by remember { mutableStateOf("") }
    var step by remember { mutableStateOf(0) } // 0 = name input, 1 = biometric

    AlertDialog(
        onDismissRequest = { if (step == 0) onDismiss() },
        title = { Text(if (step == 0) "Create folder" else "Authenticate") },
        text = {
            when (step) {
                0 -> Column {
                    Text(
                        "Pick a name. Each folder is independently encrypted; " +
                            "you'll authenticate again after picking a name to " +
                            "seed the new folder's master key.",
                        color = Color(0xFF9E9E9E), fontSize = 12.sp,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text("Folder name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                1 -> Text(
                    "Authenticate to seed the new folder's master key.",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (step != 0) return@TextButton
                    if (name.isBlank()) return@TextButton
                    step = 1
                },
                enabled = step == 0 && name.isNotBlank(),
            ) { Text("Next") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )

    if (step == 1) {
        LaunchedEffect(name) {
            runCatching {
                val info = VaultFolders.reserveNew(ctx, name)
                val cipher = Crypto.deviceAuthCipherForEncrypt()
                promptAuthLocal(activity, "Create ${info.name}", cipher,
                    onSuccess = { authed ->
                        runCatching {
                            val store = VaultFolder.create(ctx, authed, info.id)
                            if (activity.lifecycle.currentState
                                    .isAtLeast(Lifecycle.State.STARTED)
                            ) {
                                onCreated(store)
                            } else {
                                store.lock()
                            }
                        }.onFailure {
                            // Roll back the index reservation if the
                            // create itself failed mid-way (no header
                            // to anchor the entry).
                            VaultFolders.delete(ctx, info.id)
                            onError("Create failed: ${it.message}")
                        }
                    },
                    onError = { msg ->
                        VaultFolders.delete(ctx, info.id)
                        onError("Auth failed: $msg")
                    },
                    onCancel = {
                        VaultFolders.delete(ctx, info.id)
                        onError("Auth cancelled.")
                    },
                )
            }.onFailure {
                onError("Crypto init failed: ${it.message}")
            }
        }
    }
}

// Local promptAuth shim. The MainActivity-private one is identical;
// re-declared here to avoid leaking the function across files.
private fun promptAuthLocal(
    activity: FragmentActivity,
    title: String,
    cipher: javax.crypto.Cipher,
    onSuccess: (javax.crypto.Cipher) -> Unit,
    onError: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val prompt = androidx.biometric.BiometricPrompt(
        activity,
        java.util.concurrent.Executors.newSingleThreadExecutor(),
        object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(
                result: androidx.biometric.BiometricPrompt.AuthenticationResult,
            ) {
                val c = result.cryptoObject?.cipher
                if (c != null) onSuccess(c)
                else onError("Cipher missing in BiometricPrompt result.")
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode == androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) onCancel()
                else onError(errString.toString())
            }
        },
    )
    val info = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle("Required to seed or release this folder's master key.")
        .setAllowedAuthenticators(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info, androidx.biometric.BiometricPrompt.CryptoObject(cipher))
}
