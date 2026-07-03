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
import androidx.compose.material3.IconButton
import androidx.compose.material3.Icon
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
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
    onOpenFolder: (VaultFolderStore) -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var refreshKey by remember { mutableStateOf(0) }
    val folders = remember(refreshKey) { VaultFolders.list(ctx) }
    var error by remember { mutableStateOf<String?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    var showCreateDialog by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<VaultFolders.FolderInfo?>(null) }
    var pendingRename by remember { mutableStateOf<VaultFolders.FolderInfo?>(null) }

    // §6.3 (A11.4 / D12): clean orphan index rows left by a cancelled/failed
    // create, off the main thread, instead of relying on read-time filtering.
    LaunchedEffect(Unit) {
        withContext(Bg.io) { runCatching { VaultFolders.pruneOrphans(ctx) } }
    }

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
        // §6.4: folder-delete / rename success is a NEUTRAL line, not the red
        // error slot.
        notice?.let { Text(it, color = Color(0xFF81C784), fontSize = 12.sp) }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(6.dp),
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
                        notice = null
                        runCatching {
                            val iv = VaultFolder.ivForUnlock(ctx, folder.id)
                            val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                            promptDeviceAuth(activity, "Unlock ${folder.name}",
                                "Required to release this folder's master key.", cipher,
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
                    // §6.5 (A13 / D12): rename is only offered on non-default
                    // folders (the default's display name is hardcoded).
                    onRename = if (folder.isDefault) null else {
                        { pendingRename = folder }
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
                // §6.4 (A12 / D5): folder-delete is the most destructive action
                // in the app — bring its guard to parity with file delete:
                // filterTouchesWhenObscured on the dialog view + a hasWindowFocus
                // gate on confirm (see below), and blast-radius copy.
                val dialogView = LocalView.current
                DisposableEffect(dialogView) {
                    dialogView.filterTouchesWhenObscured = true
                    onDispose { }
                }
                Text(
                    "Deletes the folder \"${folder.name}\" and ALL files in it. " +
                        "No recycle bin, no recovery.",
                )
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
                        if (ok) notice = "Deleted ${target.name}." else error = "Delete failed."
                        refreshKey++
                    }
                }) { Text("Delete", color = Color(0xFFEF5350)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text("Cancel") }
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
            title = { Text("Rename folder") },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    label = { Text("Folder name") },
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
                            if (ok) notice = "Renamed to ${name.trim()}." else error = "Rename failed."
                            refreshKey++
                        }
                    },
                    enabled = newName.isNotBlank(),
                ) { Text("Rename") }
            },
            dismissButton = {
                TextButton(onClick = { pendingRename = null }) { Text("Cancel") }
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
                    modifier = Modifier.weight(1f),
                )
                if (isCurrent) {
                    Text("· unlocked", color = Color(0xFF66BB6A), fontSize = 11.sp)
                }
                if (onRename != null) {
                    IconButton(onClick = onRename, enabled = !working) {
                        Icon(Icons.Filled.Edit, contentDescription = "Rename ${folder.name}")
                    }
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
                    // §6.4: row Delete is tap-jack-hardened (SecureOutlinedButton),
                    // matching the file-delete action's guard.
                    SecureOutlinedButton(
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
                promptDeviceAuth(activity, "Create ${info.name}",
                    "Required to seed this folder's master key.", cipher,
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
