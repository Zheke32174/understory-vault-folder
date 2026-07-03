package com.understory.vaultfolder

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.provider.OpenableColumns
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.TransientFlight
import com.understory.security.SecureOutlinedButton
import com.understory.security.SuiteStatusFooter
import com.understory.security.Tamper
import com.understory.security.TestingMode
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {

    private var unlocked: VaultFolderStore?
        get() = VaultFolderManager.current
        set(value) {
            if (value == null) VaultFolderManager.clear()
            else VaultFolderManager.setUnlocked(value)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("vault-folder.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("vault-folder.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("vault-folder crash", color = Color(0xFFEF5350), fontSize = 18.sp)
                        Text(t.toString(), color = Color(0xFFE0E0E0), fontSize = 11.sp)
                    }
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        Diagnostics.log("vault-folder.MainActivity", "onPause (inFlight=${VaultFolderManager.isInTransientFlight})")
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            com.understory.security.SuiteAttestation.verify(applicationContext).hardFail
        ) {
            finishAndRemoveTask(); return
        }

        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                window.setHideOverlayWindows(true)
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        // ACTION_VIEW with a content URI: the user (or a peer suite app
        // explicitly invoking us) is depositing a file into the vault.
        // We pull the URI here so it survives onCreate's reach and gets
        // handed to the Add screen post-unlock — same pattern as
        // passgen/aegis import landings.
        val depositUri: android.net.Uri? =
            if (intent?.action == android.content.Intent.ACTION_VIEW) intent?.data else null

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                    VaultFolderRoot(
                        activity = this,
                        unlockedRef = ::unlocked,
                        setUnlocked = { unlocked = it },
                        onClose = { finishAndRemoveTask() },
                        depositUri = depositUri,
                    )
                }
            }
        }

        // Note: we deliberately do NOT set
        // `window.decorView.filterTouchesWhenObscured = true` here. Samsung
        // One UI's Edge Panel and various system gesture overlays trigger
        // FLAG_WINDOW_IS_OBSCURED on touches that pass through them, and
        // a global decor-view filter silently drops every tap underneath
        // — including the "Pick a file" SAF launcher tap, which is what
        // surfaced this bug. Tap-jacking defense for *destructive* paths
        // (Lock, Delete, encrypt/decrypt action) is enforced per-control
        // via SecureButton / SecureOutlinedButton; the SAF picker is its
        // own activity with its own anti-overlay protections, so opening
        // it doesn't need this layer.
        // FLAG_SECURE on the window still prevents screenshots / overlay
        // capture of vault contents.
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        val inFlight = VaultFolderManager.isInTransientFlight
        Diagnostics.log("vault-folder.MainActivity",
            "onUserLeaveHint (inFlight=$inFlight, keepAlive=${TestingMode.KEEP_ALIVE_ON_LEAVE})")
        // Skip during a deliberate transient round-trip (SAF picker,
        // biometric prompt). Same reasoning as aegis/backups.
        if (inFlight) return
        // Skip during the testing phase so the app stays alive across
        // switching apps. RELEASE-BLOCKER to flip
        // TestingMode.KEEP_ALIVE_ON_LEAVE = false before publish.
        if (TestingMode.KEEP_ALIVE_ON_LEAVE) return
        unlocked?.lock()
        unlocked = null
        finishAndRemoveTask()
    }

    /**
     * Lock on onStop, NOT onPause — same lesson the aegis lifecycle
     * audit taught us: onPause fires during transient occlusions
     * (system permission dialogs, biometric prompts on some OEMs, the
     * SAF picker we use for file import/export). Locking on onPause
     * would wipe the KEK during such a round-trip and the active
     * Compose state would call vault.save() against zero bytes.
     */
    override fun onStop() {
        super.onStop()
        val inFlight = VaultFolderManager.isInTransientFlight
        val isCfg = isChangingConfigurations
        val keepAlive = TestingMode.KEEP_ALIVE_ON_LEAVE
        Diagnostics.log("vault-folder.MainActivity",
            "onStop (inFlight=$inFlight, changingConfigs=$isCfg, keepAlive=$keepAlive, willLock=${!isCfg && !inFlight && !keepAlive})")
        DiagnosticsDump.snapshotState(this, "onStop")
        // Preserve the unlocked store across:
        //   - deliberate transient round-trips (SAF picker, biometric prompt)
        //   - the testing phase (TestingMode.KEEP_ALIVE_ON_LEAVE — RELEASE-
        //     BLOCKER to flip false before publish)
        if (!isCfg && !inFlight && !keepAlive) {
            unlocked?.lock()
            unlocked = null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Diagnostics.log("vault-folder.MainActivity", "onDestroy")
        unlocked?.lock()
        unlocked = null
    }

    override fun onResume() {
        super.onResume()
        val vaultFlight = VaultFolderManager.isInTransientFlight
        val commonFlight = TransientFlight.isActive()
        Diagnostics.log("vault-folder.MainActivity",
            "onResume (vaultFlight=$vaultFlight commonFlight=$commonFlight)")
        // Skip the hardFail re-check during a SAF picker round-trip.
        // Same defense as antivirus + backups — the onCreate check is the
        // authoritative gate, and the resume-time recheck self-inflicts a
        // denial-of-service when a probe flaps during the foreground
        // transition.
        if (vaultFlight || commonFlight) return
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("vault-folder.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }
}

private enum class Stage { Setup, Unlock, List, Add, Folders, Diagnostics }

@Composable
private fun VaultFolderRoot(
    activity: FragmentActivity,
    unlockedRef: () -> VaultFolderStore?,
    setUnlocked: (VaultFolderStore?) -> Unit,
    onClose: () -> Unit,
    depositUri: android.net.Uri? = null,
) {
    val ctx = LocalContext.current
    // String-encoded saveable state — rememberSaveable<Enum> via the
    // AutoSaver was not reliably restoring on Samsung in earlier tests
    // (the shipped APK contained the "cannot be saved" Compose error
    // string). Round-tripping via String.name is bulletproof.
    var stageName by rememberSaveable {
        mutableStateOf(if (VaultFolder.exists(ctx)) Stage.Unlock.name else Stage.Setup.name)
    }
    val stage = remember(stageName) { Stage.valueOf(stageName) }
    val setStage: (Stage) -> Unit = {
        Diagnostics.log("vault-folder.Root", "stage transition: $stageName → ${it.name}")
        stageName = it.name
    }
    // Single-shot incoming deposit URI — consumed once on first entry
    // to Stage.Add. Kept as plain `remember` because configChanges in
    // the manifest skip recreation; if that ever changes the worst
    // case is the user re-triggers via the file manager.
    var pendingDeposit by remember { mutableStateOf(depositUri) }
    val backToList: () -> Unit = {
        pendingDeposit = null
        setStage(Stage.List)
    }
    when (stage) {
        Stage.Setup -> {
            KeepAliveBackHandler("vault-folder.Root.Setup")
            SetupScreen(activity = activity, onCreated = {
                setUnlocked(it)
                setStage(if (pendingDeposit != null) Stage.Add else Stage.List)
            }, onClose = onClose)
        }
        Stage.Unlock -> {
            KeepAliveBackHandler("vault-folder.Root.Unlock")
            UnlockScreen(activity = activity, onUnlocked = {
                setUnlocked(it)
                setStage(if (pendingDeposit != null) Stage.Add else Stage.List)
            }, onClose = onClose)
        }
        Stage.List -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            KeepAliveBackHandler("vault-folder.Root.List")
            ListScreen(
                store = v,
                onAdd = { setStage(Stage.Add) },
                onFolders = { setStage(Stage.Folders) },
                onLock = { v.lock(); setUnlocked(null); onClose() },
                onDiagnostics = { setStage(Stage.Diagnostics) },
            )
        }
        Stage.Folders -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToList() }
            FoldersScreen(
                activity = activity,
                currentFolderId = v.folderId,
                onOpenFolder = { newStore ->
                    // If user opened the same folder, we already have its
                    // store; the FoldersScreen short-circuits via onBack.
                    // Otherwise we lock the previous store and adopt the
                    // newly-unlocked one.
                    if (newStore.folderId != v.folderId) {
                        v.lock()
                    }
                    setUnlocked(newStore)
                    setStage(Stage.List)
                },
                onBack = backToList,
            )
        }
        Stage.Add -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToList() }
            // Consume the deposit URI once: capture into a local and
            // null the holder so a recomposition doesn't replay the
            // auto-add. The Add screen runs its existing flow on the
            // pre-supplied URI without bouncing through the picker.
            val incoming = pendingDeposit
            if (incoming != null) {
                pendingDeposit = null
            }
            AddScreen(
                store = v,
                onSaved = backToList,
                onCancel = backToList,
                incomingUri = incoming,
            )
        }
        Stage.Diagnostics -> {
            BackHandler { backToList() }
            DiagnosticsScreen(onBack = backToList)
        }
    }
}

private fun deviceUnsupportedReason(ctx: Context): String? {
    val km = ctx.getSystemService(android.app.KeyguardManager::class.java)
    if (km == null || !km.isDeviceSecure) {
        return "Device screen lock required.\n\nVault-folder binds the master key " +
            "to your device's PIN / pattern / biometric. Set up a screen lock in " +
            "system Settings, then come back."
    }
    val bm = BiometricManager.from(ctx)
    val canAuth = bm.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
    )
    if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
        return "BiometricPrompt unavailable (status $canAuth). Configure a strong " +
            "biometric or device credential in system Settings."
    }
    return null
}

@Composable
private fun SetupScreen(
    activity: FragmentActivity,
    onCreated: (VaultFolderStore) -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var step by remember { mutableIntStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    val deviceIssue = remember { deviceUnsupportedReason(ctx) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("vault folder — first-time setup", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        if (deviceIssue != null) {
            Box(modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                .padding(12.dp)) {
                Text(deviceIssue, color = Color(0xFFFFB74D), fontSize = 12.sp)
            }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
            return@Column
        }
        when (step) {
            0 -> {
                Text(
                    "Vault-folder generates its own 256-bit master key, self-encrypts " +
                        "it under a hardware-backed Keystore key, and self-binds it to this " +
                        "device's screen lock. Files you add are individually AES-256-GCM " +
                        "encrypted under that master.",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp,
                )
                Box(modifier = Modifier.fillMaxWidth()
                    .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                    .padding(12.dp)) {
                    Text(
                        "Per-file size cap: 20 MiB. Vault-folder is for documents, keys, " +
                            "recovery codes, photos — not video archives.\n\n" +
                            "Lost device = lost vault. The Keystore-wrapped master cannot " +
                            "leave this device. Use backups (#7 in the suite) for off-device " +
                            "recoverable copies.",
                        color = Color(0xFFFFB74D), fontSize = 11.sp,
                    )
                }
                Button(onClick = { step = 1 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Self-generate vault")
                }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            1 -> {
                Text("Authenticate with your device to bind the vault master key.",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp)
                error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }
                LaunchedEffect(Unit) {
                    runCatching {
                        val cipher = Crypto.deviceAuthCipherForEncrypt()
                        promptAuth(activity, "Bind vault-folder to this device", cipher,
                            onSuccess = { authed ->
                                runCatching {
                                    val v = VaultFolder.create(ctx, authed)
                                    if (activity.lifecycle.currentState
                                            .isAtLeast(Lifecycle.State.STARTED)
                                    ) onCreated(v) else v.lock()
                                }.onFailure { error = "Setup failed: ${it.message}" }
                            },
                            onError = { msg -> error = "Authentication failed: $msg" },
                            onCancel = { error = "Authentication cancelled."; step = 0 },
                        )
                    }.onFailure { error = "Crypto init failed: ${it.message}" }
                }
            }
        }
    }
}

@Composable
private fun UnlockScreen(
    activity: FragmentActivity,
    onUnlocked: (VaultFolderStore) -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("vault folder — unlock", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text("Authenticate with your device biometric or PIN.",
            color = Color(0xFF9E9E9E), fontSize = 13.sp)
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }

        Button(
            onClick = {
                if (working) return@Button
                working = true; error = null
                runCatching {
                    val iv = VaultFolder.ivForUnlock(ctx)
                    val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                    promptAuth(activity, "Unlock vault-folder", cipher,
                        onSuccess = { authed ->
                            runCatching {
                                val v = VaultFolder.unlock(ctx, authed)
                                if (activity.lifecycle.currentState
                                        .isAtLeast(Lifecycle.State.STARTED)
                                ) onUnlocked(v) else { v.lock(); working = false }
                            }.onFailure {
                                error = "Vault decryption failed."; working = false
                            }
                        },
                        onError = { msg -> error = "Authentication failed: $msg"; working = false },
                        onCancel = { error = "Authentication cancelled."; working = false },
                    )
                }.onFailure {
                    error = "Crypto init failed: ${it.message}"; working = false
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Authenticating…" else "Unlock with device auth")
        }
        OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
    }
}

private fun promptAuth(
    activity: FragmentActivity,
    title: String,
    cipher: Cipher,
    onSuccess: (Cipher) -> Unit,
    onError: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            val c = result.cryptoObject?.cipher
            if (c == null) onError("no cipher") else onSuccess(c)
        }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            if (errorCode in setOf(
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED,
                )) onCancel() else onError(errString.toString())
        }
    }
    val prompt = BiometricPrompt(activity, executor, callback)
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle("vault-folder")
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

@Composable
private fun ListScreen(
    store: VaultFolderStore,
    onAdd: () -> Unit,
    onFolders: () -> Unit,
    onLock: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    val ctx = LocalContext.current
    var revision by remember { mutableIntStateOf(0) }
    var deleteCandidate by remember { mutableStateOf<VaultFolderEntry?>(null) }

    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { /* handled via state below — we set this up lazily */ }

    // We need per-export state since CreateDocument is per-launch.
    // pendingExport is rememberSaveable so it survives activity recreation
    // during the SAF round-trip on Samsung — without this, the export
    // target reference is gone when the picker returns and the export
    // silently no-ops.
    var pendingExport by rememberSaveable { mutableStateOf<VaultFolderEntry?>(null) }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri: Uri? ->
        Diagnostics.log("vault-folder.List",
            "exportLauncher result: uri=${if (uri != null) "non-null" else "null"}")
        VaultFolderManager.endTransientFlight()
        val target = pendingExport
        pendingExport = null
        if (uri != null && target != null) {
            runCatching { store.exportFile(target, uri) }
                .onSuccess {
                    Diagnostics.log("vault-folder.List", "exported ${target.name} ok")
                    Toast.makeText(ctx, "Exported ${target.name}", Toast.LENGTH_SHORT).show()
                }
                .onFailure {
                    Diagnostics.error("vault-folder.List",
                        "export failed: ${it.javaClass.simpleName}: ${it.message}")
                    Toast.makeText(ctx, "Export failed: ${it.message}", Toast.LENGTH_LONG).show()
                }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.weight(1f)) {
                Text("vault folder", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    "${store.contents.entries.size} file(s)",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp,
                )
            }
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            // Per SAMSUNG_QUIRKS.md: navigation is plain Button. Lock is
            // also plain — locking is a non-destructive operation (worst
            // case the user has to re-authenticate).
            Button(onClick = onAdd, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Add file") }
            OutlinedButton(onClick = onLock, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Lock") }
        }
        // Multi-folder hub. Surfaces the current folder name and routes
        // to the FoldersScreen for switching / creating / deleting. The
        // default-folder install sees this row too — it's the entry
        // point to creating a second folder for users who want one.
        OutlinedButton(onClick = onFolders, modifier = Modifier.fillMaxWidth()) {
            val label = if (store.folderId == VaultFolder.DEFAULT_FOLDER_ID)
                "Folder: Default · switch / create"
            else "Folder: ${store.folderId.take(8)}… · switch / create"
            Text(label)
        }

        @Suppress("UNUSED_EXPRESSION") revision

        if (store.contents.entries.isEmpty()) {
            Spacer(Modifier.height(20.dp))
            Text("No files yet. Tap Add file to import one.",
                color = Color(0xFF9E9E9E), fontSize = 13.sp)
            Spacer(Modifier.weight(1f))
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth().weight(1f),
            ) {
                items(store.contents.entries, key = { it.id }) { entry ->
                    EntryRow(
                        entry = entry,
                        onExport = {
                            Diagnostics.log("vault-folder.List", "export tap: ${entry.name}")
                            pendingExport = entry
                            VaultFolderManager.beginTransientFlight()
                            runCatching { exportLauncher.launch(entry.name) }
                                .onFailure {
                                    Diagnostics.error("vault-folder.List",
                                        "exportLauncher.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                                    VaultFolderManager.endTransientFlight()
                                }
                        },
                        onDelete = { deleteCandidate = entry },
                    )
                }
            }
        }
        OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text("Diagnostics")
        }
        SuiteStatusFooter()
    }

    deleteCandidate?.let { entry ->
        AlertDialog(
            onDismissRequest = { deleteCandidate = null },
            title = { Text("Delete this file?") },
            text = {
                val dialogView = LocalView.current
                DisposableEffect(dialogView) {
                    dialogView.filterTouchesWhenObscured = true
                    onDispose { }
                }
                Column {
                    Text(entry.name, color = Color(0xFFE0E0E0), fontSize = 14.sp)
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "Deleting permanently removes the encrypted blob from this " +
                            "vault. There is no recycle bin and no recovery path. " +
                            "Export first if you might want it back.",
                        color = Color(0xFFFFB74D), fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                val dialogView = LocalView.current
                TextButton(onClick = {
                    if (!dialogView.hasWindowFocus()) return@TextButton
                    val target = entry
                    deleteCandidate = null
                    runCatching { store.deleteFile(target); revision++ }
                        .onSuccess { Toast.makeText(ctx, "Deleted ${target.name}", Toast.LENGTH_SHORT).show() }
                        .onFailure { Toast.makeText(ctx, "Delete failed: ${it.message}", Toast.LENGTH_LONG).show() }
                }) { Text("Delete", color = Color(0xFFEF5350)) }
            },
            dismissButton = {
                TextButton(onClick = { deleteCandidate = null }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun EntryRow(
    entry: VaultFolderEntry,
    onExport: () -> Unit,
    onDelete: () -> Unit,
) {
    Box(
        modifier = Modifier.fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(8.dp))
            .padding(12.dp),
    ) {
        Column {
            Text(entry.name, color = Color(0xFFE0E0E0), fontSize = 14.sp)
            Text(
                "${entry.mimeType} · ${humanSize(entry.sizeBytes)}",
                color = Color(0xFF9E9E9E), fontSize = 11.sp,
            )
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                // Export: plain OutlinedButton (launches SAF picker only;
                // export bytes flow only after the user explicitly chooses
                // a destination in the system picker).
                OutlinedButton(onClick = onExport, modifier = Modifier.weight(1f).fillMaxWidth()) {
                    Text("Export")
                }
                // Delete stays SecureOutlinedButton — taps a confirmation
                // dialog whose "Delete" action irreversibly destroys the
                // encrypted blob. Tap-jacking that path matters.
                SecureOutlinedButton(onClick = onDelete, modifier = Modifier.weight(1f).fillMaxWidth()) {
                    Text("Delete")
                }
            }
        }
    }
}

@Composable
private fun AddScreen(
    store: VaultFolderStore,
    onSaved: () -> Unit,
    onCancel: () -> Unit,
    incomingUri: Uri? = null,
) {
    val ctx = LocalContext.current
    var status by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    // The toggle is stateful to the screen; default off so the
    // common case (read-only ingest) is the path-of-no-surprise.
    var shredSource by rememberSaveable { mutableStateOf(false) }
    // Pending uri awaiting confirmation before running the shred path.
    // Plain remember (not Saveable) — Uri is process-bound and the
    // confirm dialog is a momentary modal.
    var pendingShredConfirm by remember { mutableStateOf<Uri?>(null) }

    // Shared add-file body: factored out so both the SAF picker callback
    // and the LaunchedEffect for an incoming "Open with…" deposit URI
    // run the exact same path. Honors [shredSource]; the caller has
    // already gone through the confirm dialog when shred is requested.
    fun runAdd(uri: Uri) {
        working = true
        val opts = if (shredSource) IngestOptions.SHRED_SOURCE else IngestOptions.READ_ONLY
        runCatching {
            val (name, mime) = queryDisplayMetadata(ctx, uri)
            store.addFile(uri, name, mime, opts)
        }.onSuccess { result ->
            Diagnostics.log("vault-folder.Add",
                "addFile ok: ${result.entry.name} (${result.entry.sizeBytes} B) " +
                    "shred=${result.javaClass.simpleName}")
            status = when (result) {
                is AddResult.Added ->
                    "Added ${result.entry.name} (${humanSize(result.entry.sizeBytes)})"
                is AddResult.AddedSourceShredded ->
                    "Added ${result.entry.name} · source shredded"
                is AddResult.AddedSourceShredFailed ->
                    "Added ${result.entry.name} · shred failed: ${result.reason} " +
                        "(your encrypted copy is safe; delete the source manually)"
            }
            Toast.makeText(ctx, status, Toast.LENGTH_LONG).show()
            // Only navigate back on full success (Added or
            // AddedSourceShredded). On shred-failed, stay on the
            // screen so the user reads the message.
            if (result !is AddResult.AddedSourceShredFailed) onSaved()
        }.onFailure {
            Diagnostics.error("vault-folder.Add",
                "addFile failed: ${it.javaClass.simpleName}: ${it.message}")
            status = "Add failed: ${it.message ?: it.javaClass.simpleName}"
        }
        working = false
    }

    /** Entry point that respects the confirm dialog when shred is on. */
    fun beginAdd(uri: Uri) {
        if (shredSource) {
            pendingShredConfirm = uri
        } else {
            runAdd(uri)
        }
    }

    val pickInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        Diagnostics.log("vault-folder.Add",
            "pickInput result: uri=${if (uri != null) "non-null" else "null"}")
        VaultFolderManager.endTransientFlight()
        if (uri == null) return@rememberLauncherForActivityResult
        beginAdd(uri)
    }

    // Auto-add path for cross-app deposits: when the activity was
    // launched via ACTION_VIEW and the user-unlocked-the-vault step has
    // landed us on Stage.Add, run the same encrypt-into-vault flow on
    // the supplied URI. The parent already nulls pendingDeposit after
    // first entry, so a recomposition won't replay this.
    LaunchedEffect(incomingUri) {
        if (incomingUri != null) {
            Diagnostics.log("vault-folder.Add", "auto-add from incoming URI")
            beginAdd(incomingUri)
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("add file", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Pick a file via the system file picker. It's encrypted in-place under " +
                "this vault's master key. Per-file cap: 20 MiB.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )
        // Plain Button, NOT SecureButton — the tap-jacking guard's
        // partial-obscure check rejected taps under Samsung Edge Panel
        // and the SAF picker silently never opened. Tap-jacking the
        // "Pick a file" button is non-destructive (it just launches the
        // system SAF picker which has its own anti-overlay defenses).
        Button(
            onClick = {
                Diagnostics.log("vault-folder.Add", "Pick a file: tap")
                VaultFolderManager.beginTransientFlight()
                runCatching { pickInput.launch(arrayOf("*/*")) }
                    .onFailure {
                        Diagnostics.error("vault-folder.Add",
                            "pickInput.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                        VaultFolderManager.endTransientFlight()
                    }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Encrypting…" else "Pick a file")
        }

        // Shred toggle. Off by default — the common case is to keep
        // the source. When on, the picker callback routes through a
        // confirm dialog before the encrypt+delete runs. Whether the
        // delete actually succeeds depends on the URI grant — see
        // VaultFolderStore.addFile docs and AddResult.
        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    androidx.compose.ui.graphics.Color(0xFF1C1C1C),
                    androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
                )
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.fillMaxWidth(0.85f)) {
                Text(
                    "Delete source after import",
                    color = Color(0xFFE0E0E0), fontSize = 13.sp,
                )
                Text(
                    if (shredSource)
                        "On — you'll confirm before each shred. Only works on URIs " +
                            "with WRITE permission (system file picker, not bare " +
                            "Open-with deposits)."
                    else
                        "Off — the source file stays where it is.",
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
            }
            androidx.compose.material3.Switch(
                checked = shredSource,
                onCheckedChange = {
                    shredSource = it
                    Diagnostics.log("vault-folder.Add",
                        "shred toggle: ${if (it) "ON" else "OFF"}")
                },
            )
        }

        status?.let { Text(it, color = Color(0xFFFFB74D), fontSize = 12.sp) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("Back") }
    }

    pendingShredConfirm?.let { uri ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { pendingShredConfirm = null },
            title = { Text("Shred source after import?") },
            text = {
                Text(
                    "After encrypting this file into the vault, attempt to " +
                        "permanently delete the source file from where you " +
                        "picked it. This cannot be undone if it succeeds. " +
                        "If the source URI doesn't grant write access, the " +
                        "delete will fail and the source will remain — your " +
                        "encrypted copy is safe either way.",
                )
            },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = {
                    val u = pendingShredConfirm
                    pendingShredConfirm = null
                    if (u != null) runAdd(u)
                }) { Text("Encrypt + shred", color = Color(0xFFEF5350)) }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = {
                    pendingShredConfirm = null
                }) { Text("Cancel") }
            },
        )
    }
}

private fun queryDisplayMetadata(ctx: Context, uri: Uri): Pair<String, String?> {
    var name = "imported"
    val mime = ctx.contentResolver.getType(uri)
    runCatching {
        ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (c.moveToFirst() && nameIdx >= 0) {
                val raw = c.getString(nameIdx)
                if (!raw.isNullOrBlank()) name = raw
            }
        }
    }
    return name to mime
}

private fun humanSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> "${bytes / (1024 * 1024)} MB"
}
