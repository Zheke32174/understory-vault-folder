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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.Icon
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
    showMessage: (String) -> Unit,
    onOpenFolder: (VaultFolderStore) -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var refreshKey by remember { mutableStateOf(0) }
    val folders = remember(refreshKey) { VaultFolders.list(ctx) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    var showCreateDialog by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<VaultFolders.FolderInfo?>(null) }
    var pendingRename by remember { mutableStateOf<VaultFolders.FolderInfo?>(null) }

    // §6.3 (A11.4 / D12): clean orphan index rows left by a cancelled/failed
    // create, off the main thread, instead of relying on read-time filtering.
    LaunchedEffect(Unit) {
        withContext(Bg.io) { runCatching { VaultFolders.pruneOrphans(ctx) } }
    }

    SuiteScaffold(
        title = stringResource(R.string.title_folders),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(
                stringResource(R.string.folders_intro),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            error?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                // §6.2 (A11.3 / D9): weight(1f) so a long folder list can't push
                // Create/Back off-screen; those stay as fixed rows below.
                modifier = Modifier.fillMaxWidth().weight(1f),
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
                                promptDeviceAuth(
                                    activity,
                                    ctx.getString(R.string.auth_unlock_folder_title, folder.name),
                                    ctx.getString(R.string.auth_folder_subtitle), cipher,
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
                                            error = ctx.getString(R.string.err_decrypt_failed, it.message)
                                            working = false
                                        }
                                    },
                                    onError = { msg ->
                                        error = ctx.getString(R.string.err_auth_failed, msg); working = false
                                    },
                                    onCancel = {
                                        error = ctx.getString(R.string.err_auth_cancelled); working = false
                                    },
                                )
                            }.onFailure {
                                error = ctx.getString(R.string.err_crypto_init, it.message); working = false
                            }
                        },
                        onDelete = if (folder.isDefault) null else {
                            { pendingDelete = folder }
                        },
                        // §6.5 (A13 / D12): rename is only offered on non-default
                        // folders (the default's display name is hardcoded).
                        onRename = if (folder.isDefault) null else {
                            { pendingRename = folder }
                        },
                    )
                }
            }

            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Button(
                onClick = { showCreateDialog = true },
                modifier = Modifier.fillMaxWidth(),
                enabled = !working,
            ) { Text(stringResource(R.string.folders_create)) }
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.action_back)) }
        }
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
            title = { Text(stringResource(R.string.folder_delete_title)) },
            text = {
                // §6.4 (A12 / D5): folder-delete is the most destructive action
                // in the app — bring its guard to parity with file delete:
                // filterTouchesWhenObscured on the dialog view + a hasWindowFocus
                // gate on confirm (see below), and blast-radius copy.
                val dialogView = LocalView.current
                DisposableEffect(dialogView) {
                    dialogView.filterTouchesWhenObscured = true
                    onDispose { }
                }
                Text(stringResource(R.string.folder_delete_body, folder.name))
            },
            confirmButton = {
                val dialogView = LocalView.current
                TextButton(onClick = {
                    if (!dialogView.hasWindowFocus()) return@TextButton
                    val target = folder
                    pendingDelete = null
                    error = null
                    scope.launch {
                        val ok = withContext(Bg.io) {
                            runCatching { VaultFolders.delete(ctx, target.id) }.getOrDefault(false)
                        }
                        // §6.4: folder-delete success is a NEUTRAL snackbar line,
                        // not the red error slot.
                        if (ok) showMessage(ctx.getString(R.string.folder_delete_done, target.name))
                        else error = ctx.getString(R.string.folder_delete_failed)
                        refreshKey++
                    }
                }) {
                    Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    // §6.5: rename dialog. Reuses the same sanitize/disabled-empty handling as
    // the create dialog's name entry. rename() itself refuses the default
    // folder and sanitizes the name.
    pendingRename?.let { folder ->
        var newName by remember(folder.id) { mutableStateOf(folder.name) }
        AlertDialog(
            onDismissRequest = { pendingRename = null },
            title = { Text(stringResource(R.string.folder_rename_title)) },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    label = { Text(stringResource(R.string.folder_name_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val target = folder
                        val name = newName
                        pendingRename = null
                        error = null
                        scope.launch {
                            val ok = withContext(Bg.io) {
                                runCatching { VaultFolders.rename(ctx, target.id, name) }.isSuccess
                            }
                            if (ok) showMessage(ctx.getString(R.string.folder_rename_done, name.trim()))
                            else error = ctx.getString(R.string.folder_rename_failed)
                            refreshKey++
                        }
                    },
                    enabled = newName.isNotBlank(),
                ) { Text(stringResource(R.string.action_rename)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingRename = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
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
    onRename: (() -> Unit)?,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (isCurrent) UnderstoryTheme.semantic.successContainer
                else MaterialTheme.colorScheme.surfaceVariant,
                MaterialTheme.shapes.small,
            )
            .padding(UnderstoryTheme.spacing.md),
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    folder.name,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                if (isCurrent) {
                    Text(
                        stringResource(R.string.folder_unlocked_tag),
                        style = MaterialTheme.typography.bodySmall,
                        color = UnderstoryTheme.semantic.success,
                    )
                }
                if (onRename != null) {
                    IconButton(onClick = onRename, enabled = !working) {
                        Icon(
                            Icons.Filled.Edit,
                            contentDescription = stringResource(R.string.cd_rename, folder.name),
                        )
                    }
                }
            }
            Text(
                if (folder.isDefault) stringResource(R.string.folder_default_desc)
                else stringResource(
                    R.string.folder_created_desc,
                    java.text.SimpleDateFormat(
                        "yyyy-MM-dd",
                        java.util.Locale.getDefault(),
                    ).format(java.util.Date(folder.createdAtMs)),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                Button(
                    onClick = onOpen,
                    enabled = !working,
                    modifier = if (onDelete != null) Modifier.fillMaxWidth(0.6f) else Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (isCurrent) stringResource(R.string.action_open)
                        else stringResource(R.string.action_unlock)
                    )
                }
                if (onDelete != null) {
                    // §6.4: row Delete is tap-jack-hardened (SecureOutlinedButton),
                    // matching the file-delete action's guard.
                    SecureOutlinedButton(
                        onClick = onDelete,
                        enabled = !working,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.action_delete)) }
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
        title = {
            Text(
                if (step == 0) stringResource(R.string.folders_create)
                else stringResource(R.string.folder_create_auth_title)
            )
        },
        text = {
            when (step) {
                0 -> Column {
                    Text(
                        stringResource(R.string.folder_create_intro),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text(stringResource(R.string.folder_name_label)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                1 -> Text(
                    stringResource(R.string.folder_create_auth_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
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
            ) { Text(stringResource(R.string.action_next)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )

    if (step == 1) {
        LaunchedEffect(name) {
            runCatching {
                val info = VaultFolders.reserveNew(ctx, name)
                val cipher = Crypto.deviceAuthCipherForEncrypt()
                promptDeviceAuth(
                    activity,
                    ctx.getString(R.string.auth_create_folder_title, info.name),
                    ctx.getString(R.string.auth_create_folder_subtitle), cipher,
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
                            onError(ctx.getString(R.string.err_create_failed, it.message))
                        }
                    },
                    onError = { msg ->
                        VaultFolders.delete(ctx, info.id)
                        onError(ctx.getString(R.string.err_auth_failed, msg))
                    },
                    onCancel = {
                        VaultFolders.delete(ctx, info.id)
                        onError(ctx.getString(R.string.err_auth_cancelled))
                    },
                )
            }.onFailure {
                onError(ctx.getString(R.string.err_create_failed, it.message))
            }
        }
    }
}
