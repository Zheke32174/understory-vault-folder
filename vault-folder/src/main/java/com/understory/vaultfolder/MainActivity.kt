package com.understory.vaultfolder

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.provider.OpenableColumns
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.RecoveryCopy
import com.understory.security.SecureOutlinedButton
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.TransientFlight
import com.understory.security.VaultExportScreen
import com.understory.security.VaultImportScreen
import com.understory.security.VaultRecovery
import com.understory.security.VaultRecoveryScreen
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
                // Deliberately raw (no UnderstoryTheme / M3 tokens): this is the
                // last-resort surface shown when initialize() itself threw, so it
                // must render even if the theme is what failed. Only the title is
                // a resource; the body is the raw exception text.
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text(stringResource(R.string.crash_title), color = Color(0xFFEF5350), fontSize = 18.sp)
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
            // §9.5 / CD-4c: show a brief honest screen instead of a bare exit so
            // a user hitting an integrity failure understands why the app closed.
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.VAULTFOLDER) {
                    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        Column(
                            modifier = Modifier.fillMaxSize().padding(24.dp),
                            verticalArrangement = Arrangement.Center,
                        ) {
                            Text(
                                stringResource(R.string.integrity_failed_title),
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.error,
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                stringResource(R.string.integrity_failed_body),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
            return
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
        // explicitly invoking us) is depositing a file into the vault. We pull
        // the URI here so it survives onCreate's reach and gets handed to the
        // deposit-confirm dialog post-unlock. A warm-task deposit is handled by
        // onNewIntent below.
        val depositUri: Uri? =
            if (intent?.action == Intent.ACTION_VIEW) intent?.data else null

        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.VAULTFOLDER) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    // §9.2: one suite-wide SnackbarHost hosted above the stage
                    // switch so an operation result (e.g. "Added file") survives
                    // the screen navigating back to the list after it completes.
                    val snackbarHostState = remember { SnackbarHostState() }
                    val snackScope = rememberCoroutineScope()
                    Box(modifier = Modifier.fillMaxSize()) {
                        VaultFolderRoot(
                            activity = this@MainActivity,
                            unlockedRef = ::unlocked,
                            setUnlocked = { unlocked = it },
                            onClose = { finishAndRemoveTask() },
                            depositUri = depositUri,
                            showMessage = { msg ->
                                snackScope.launch { snackbarHostState.showSnackbar(msg) }
                            },
                        )
                        SnackbarHost(
                            hostState = snackbarHostState,
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .navigationBarsPadding(),
                        )
                    }
                }
            }
        }
    }

    /**
     * §3.4 (A7): a deposit arriving while this singleTask instance is already
     * alive only reaches onNewIntent, not onCreate. Re-extract the URI into the
     * observable holder the root composable reads, so a warm-task deposit is
     * routed to the confirm dialog (after unlock, if currently locked) rather
     * than silently dropped.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.action == Intent.ACTION_VIEW) {
            VaultFolderManager.pendingDepositUri = intent.data
            Diagnostics.log("vault-folder.MainActivity", "onNewIntent deposit uri present=${intent.data != null}")
        }
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        val inFlight = VaultFolderManager.isInTransientFlight
        Diagnostics.log("vault-folder.MainActivity",
            "onUserLeaveHint (inFlight=$inFlight, keepAlive=${TestingMode.KEEP_ALIVE_ON_LEAVE})")
        if (inFlight) return
        if (TestingMode.KEEP_ALIVE_ON_LEAVE) return
        unlocked?.lock()
        unlocked = null
        finishAndRemoveTask()
    }

    /**
     * Lock on onStop, NOT onPause — same lesson the aegis lifecycle audit
     * taught us: onPause fires during transient occlusions (system permission
     * dialogs, biometric prompts on some OEMs, the SAF picker we use for file
     * import/export). Locking on onPause would wipe the KEK during such a
     * round-trip and the active Compose state would call vault.save() against
     * zero bytes.
     */
    override fun onStop() {
        super.onStop()
        val inFlight = VaultFolderManager.isInTransientFlight
        val isCfg = isChangingConfigurations
        val keepAlive = TestingMode.KEEP_ALIVE_ON_LEAVE
        Diagnostics.log("vault-folder.MainActivity",
            "onStop (inFlight=$inFlight, changingConfigs=$isCfg, keepAlive=$keepAlive, willLock=${!isCfg && !inFlight && !keepAlive})")
        DiagnosticsDump.snapshotState(this, "onStop")
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
        if (vaultFlight || commonFlight) return
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("vault-folder.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }
}

private enum class Stage { Setup, Unlock, List, Add, Folders, Diagnostics, Recovery, Reset, Export, ExportDo, Import, Viewer }

@Composable
private fun VaultFolderRoot(
    activity: FragmentActivity,
    unlockedRef: () -> VaultFolderStore?,
    setUnlocked: (VaultFolderStore?) -> Unit,
    onClose: () -> Unit,
    showMessage: (String) -> Unit,
    depositUri: Uri? = null,
) {
    val ctx = LocalContext.current
    // §4 detection: if the device-auth key was invalidated (fingerprint
    // re-enrolled / lock-screen changed) the vault can't be unlocked. Skip the
    // doomed BiometricPrompt and land on Recovery straight away.
    val initialStage = remember {
        when {
            !VaultFolder.exists(ctx) -> Stage.Setup
            VaultRecovery.keyStateAtStartup(ctx, headerExists = true) ==
                VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED -> Stage.Recovery
            else -> Stage.Unlock
        }.name
    }
    // String-encoded saveable state — rememberSaveable<Enum> via the AutoSaver
    // was not reliably restoring on Samsung. Round-tripping via String.name is
    // bulletproof.
    var stageName by rememberSaveable { mutableStateOf(initialStage) }
    val stage = remember(stageName) { Stage.valueOf(stageName) }
    val setStage: (Stage) -> Unit = {
        Diagnostics.log("vault-folder.Root", "stage transition: $stageName → ${it.name}")
        stageName = it.name
    }

    // The deposit URI: cold-launch value or a warm-task onNewIntent value. Merge
    // both into one holder; the confirm dialog consumes it.
    val warmDeposit = VaultFolderManager.pendingDepositUri
    var pendingDeposit by remember { mutableStateOf(depositUri) }
    LaunchedEffect(warmDeposit) {
        if (warmDeposit != null) {
            pendingDeposit = warmDeposit
            VaultFolderManager.pendingDepositUri = null
            // Route an unlocked session to Add; a locked one lands there after
            // the next unlock (Stage.Unlock's onUnlocked checks pendingDeposit).
            if (unlockedRef() != null && stage != Stage.Add) setStage(Stage.Add)
        }
    }

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
            UnlockScreen(
                activity = activity,
                onUnlocked = {
                    setUnlocked(it)
                    setStage(if (pendingDeposit != null) Stage.Add else Stage.List)
                },
                onInvalidated = { setStage(Stage.Recovery) },
                onClose = onClose,
            )
        }
        Stage.Recovery -> {
            KeepAliveBackHandler("vault-folder.Root.Recovery")
            RecoveryScreen(
                activity = activity,
                onRebound = { setStage(Stage.Unlock) },
                onReset = { setStage(Stage.Reset) },
                onClose = onClose,
            )
        }
        Stage.Reset -> {
            KeepAliveBackHandler("vault-folder.Root.Reset")
            // Reset is reached from Recovery (device-auth key invalidated), so
            // the vault can't be unlocked and export-first is impossible — the
            // shared screen skips it and goes EXPLAIN → CONFIRM_WIPE. A user who
            // still has a working vault should use the list's Backup action
            // BEFORE resetting; the EXPLAIN copy says so.
            VaultRecoveryScreen(
                keyUsable = false,
                appName = stringResource(R.string.app_name),
                hooks = remember { VaultFolderResetHooks(onSetup = { setStage(Stage.Setup) }) },
                onExportFirst = null,
            )
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
                onExportBackup = { setStage(Stage.Export) },
                onImportBackup = { setStage(Stage.Import) },
                onView = { entry -> viewerEntryId = entry.id; setStage(Stage.Viewer) },
                showMessage = showMessage,
            )
        }
        Stage.Viewer -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            val entry = v.contents.entries.firstOrNull { it.id == viewerEntryId }
            if (entry == null) { backToList(); return }
            BackHandler { backToList() }
            ViewerScreen(store = v, entry = entry, onBack = backToList)
        }
        Stage.Export -> {
            unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { setStage(Stage.List) }
            // A recovery export is encrypted under the user's recovery key. We
            // do NOT retain that key in memory, so the user re-enters it here
            // (they saved it at setup) — the key gate makes the export both
            // real and honest. It's verified against the stored verifier so a
            // typo can't produce an unrecoverable file.
            ExportKeyGate(
                onKey = { key ->
                    // hand off to the shared export screen with the entered key
                    exportKeyChars = key
                    setStage(Stage.ExportDo)
                },
                onBack = { setStage(Stage.List) },
            )
        }
        Stage.ExportDo -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            val key = exportKeyChars ?: return run { setStage(Stage.Export) }
            BackHandler { setStage(Stage.List) }
            VaultExportScreen(
                port = remember { VaultFolderExportPort() },
                unlocked = v,
                recoveryKey = key,
                onDone = {
                    key.fill(' '); exportKeyChars = null
                    setStage(Stage.List)
                },
            )
        }
        Stage.Import -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { setStage(Stage.List) }
            val port = remember { VaultFolderExportPort().also { it.importTarget = v } }
            VaultImportScreen(port = port, onDone = { setStage(Stage.List) })
        }
        Stage.Folders -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToList() }
            FoldersScreen(
                activity = activity,
                currentFolderId = v.folderId,
                showMessage = showMessage,
                onOpenFolder = { newStore ->
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
            // Consume the deposit URI once: capture into a local and null the
            // holder so a recomposition doesn't replay the auto-add.
            val incoming = pendingDeposit
            if (incoming != null) {
                pendingDeposit = null
            }
            AddScreen(
                store = v,
                onSaved = backToList,
                onCancel = backToList,
                incomingUri = incoming,
                showMessage = showMessage,
            )
        }
        Stage.Diagnostics -> {
            BackHandler { backToList() }
            DiagnosticsScreen(onBack = backToList)
        }
    }
}

// Process-scoped scratch for cross-stage hand-offs. Not persisted; recreated on
// process death (which locks the vault anyway).
private var viewerEntryId: String? = null
private var exportKeyChars: CharArray? = null

/**
 * Gate before a recovery export: the user re-enters their recovery key (they
 * saved it at setup). The key is verified against the stored verifier so a typo
 * can't produce an unrecoverable file. Shown only when a recovery key was
 * enrolled — otherwise there is no recovery-encrypted export to make, and the
 * screen says so honestly.
 */
@Composable
private fun ExportKeyGate(onKey: (CharArray) -> Unit, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val enrolled = remember { RecoveryStateStore.exists(ctx) }
    var field by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.export_gate_title), style = MaterialTheme.typography.titleLarge)
        if (!enrolled) {
            Text(
                stringResource(R.string.export_gate_no_key),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_back))
            }
            return@Column
        }
        Text(
            stringResource(R.string.export_gate_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = field,
            onValueChange = { field = it },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
        Button(
            onClick = {
                val state = RecoveryStateStore.load(ctx)
                if (state == null) { error = ctx.getString(R.string.export_gate_state_unavailable); return@Button }
                val entered = VaultRecovery.recoveryKeyFrom(field.toCharArray())
                val ok = VaultRecovery.verifyRecoveryKey(entered, state.verifier, state.verifierSalt)
                if (!ok) {
                    entered.wipe()
                    error = RecoveryCopy.IMPORT_WRONG_KEY
                } else {
                    onKey(entered.chars)
                }
            },
            enabled = field.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.action_continue)) }
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_back))
        }
    }
}

private fun deviceUnsupportedReason(ctx: Context): String? {
    val km = ctx.getSystemService(android.app.KeyguardManager::class.java)
    if (km == null || !km.isDeviceSecure) {
        return ctx.getString(R.string.setup_need_screenlock)
    }
    val bm = BiometricManager.from(ctx)
    val canAuth = bm.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
    )
    if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
        return ctx.getString(R.string.setup_need_biometric, canAuth)
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
    val scope = rememberCoroutineScope()
    var step by remember { mutableIntStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    val deviceIssue = remember { deviceUnsupportedReason(ctx) }

    // §4.3 recovery escrow: the recovery key minted for this setup (shown to the
    // user in step 1), and whether the user chose to enroll it. Held in plain
    // remember — process-bound, wiped on leave.
    val recoveryKey = remember { VaultRecovery.newRecoveryKey() }
    var enrollRecovery by remember { mutableStateOf(true) }
    var savedConfirmed by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { recoveryKey.wipe() } }

    SuiteScaffold(
        title = stringResource(R.string.title_setup),
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            if (deviceIssue != null) {
                Surface(
                    color = UnderstoryTheme.semantic.warningContainer,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        deviceIssue,
                        style = MaterialTheme.typography.bodySmall,
                        color = UnderstoryTheme.semantic.warning,
                        modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                    )
                }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.action_close))
                }
                return@Column
            }
            when (step) {
                0 -> {
                    Text(
                        stringResource(R.string.setup_intro),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Surface(
                        color = UnderstoryTheme.semantic.warningContainer,
                        shape = MaterialTheme.shapes.small,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            stringResource(R.string.setup_size_cap) + "\n\n" +
                                stringResource(R.string.setup_recovery_prompt),
                            style = MaterialTheme.typography.bodySmall,
                            color = UnderstoryTheme.semantic.warning,
                            modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                        )
                    }
                    // §4.4 backup honesty — no false "#7 backups" claim.
                    Text(
                        stringResource(R.string.backup_offdevice),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(onClick = { step = 1 }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.setup_generate))
                    }
                    OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.action_cancel))
                    }
                }
                1 -> {
                    // §4.3: recovery-key enrollment choice BEFORE binding.
                    Text(
                        RecoveryCopy.RECOVERY_KEY_TITLE,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        RecoveryCopy.RECOVERY_KEY_BODY,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    // §3 a11y: shared SwitchRow → merged Role.Switch TalkBack
                    // semantics instead of a bare Switch beside a label.
                    SwitchRow(
                        label = stringResource(R.string.setup_recovery_save),
                        checked = enrollRecovery,
                        onCheckedChange = { enrollRecovery = it },
                    )
                    if (enrollRecovery) {
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(
                                com.understory.security.RecoveryKeyCodec.grouped(recoveryKey.chars),
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                            )
                        }
                        Text(
                            stringResource(R.string.setup_recovery_key_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = savedConfirmed, onCheckedChange = { savedConfirmed = it })
                            Text(
                                stringResource(R.string.setup_recovery_saved_confirm),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    }
                    error?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    Button(
                        onClick = { step = 2 },
                        enabled = !enrollRecovery || savedConfirmed,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            if (enrollRecovery) stringResource(R.string.action_continue)
                            else stringResource(R.string.setup_continue_no_key)
                        )
                    }
                    OutlinedButton(onClick = { step = 0 }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.action_back))
                    }
                }
                2 -> {
                    Text(
                        stringResource(R.string.setup_authenticate),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    error?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    LaunchedEffect(Unit) {
                        runCatching {
                            val cipher = Crypto.deviceAuthCipherForEncrypt()
                            promptDeviceAuth(
                                activity,
                                ctx.getString(R.string.auth_bind_title),
                                ctx.getString(R.string.app_name),
                                cipher,
                                onSuccess = { authed ->
                                    scope.launch {
                                        val outcome = runCatching {
                                            withContext(Bg.io) {
                                                val keyChars = if (enrollRecovery) recoveryKey.chars else null
                                                val v = VaultFolder.create(ctx, authed, recoveryKeyChars = keyChars)
                                                if (enrollRecovery) {
                                                    // Persist the recovery verifier so a later
                                                    // recovery / import can check the key.
                                                    RecoveryStateStore.save(
                                                        ctx,
                                                        VaultRecovery.enroll(recoveryKey, itemCount = 0),
                                                    )
                                                }
                                                v
                                            }
                                        }
                                        outcome.fold(
                                            onSuccess = { v ->
                                                if (activity.lifecycle.currentState
                                                        .isAtLeast(Lifecycle.State.STARTED)
                                                ) onCreated(v) else v.lock()
                                            },
                                            onFailure = { error = ctx.getString(R.string.err_setup_failed, it.message) },
                                        )
                                    }
                                },
                                onError = { msg -> error = ctx.getString(R.string.err_auth_failed, msg) },
                                onCancel = { error = ctx.getString(R.string.err_auth_cancelled); step = 1 },
                            )
                        }.onFailure { error = ctx.getString(R.string.err_crypto_init, it.message) }
                    }
                }
            }
        }
    }
}

@Composable
private fun UnlockScreen(
    activity: FragmentActivity,
    onUnlocked: (VaultFolderStore) -> Unit,
    onInvalidated: () -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    SuiteScaffold(
        title = stringResource(R.string.title_unlock),
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                stringResource(R.string.unlock_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            error?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }

            Button(
                onClick = {
                    if (working) return@Button
                    working = true; error = null
                    runCatching {
                        val iv = VaultFolder.ivForUnlock(ctx)
                        val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                        promptDeviceAuth(activity, ctx.getString(R.string.auth_unlock_title),
                            ctx.getString(R.string.app_name), cipher,
                            onSuccess = { authed ->
                                runCatching {
                                    val v = VaultFolder.unlock(ctx, authed)
                                    if (activity.lifecycle.currentState
                                            .isAtLeast(Lifecycle.State.STARTED)
                                    ) onUnlocked(v) else { v.lock(); working = false }
                                }.onFailure {
                                    working = false
                                    // §4: distinguish a permanent key invalidation
                                    // (route to recovery) from a transient failure.
                                    if (VaultRecovery.classifyUnlockFailure(it) ==
                                        VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED
                                    ) onInvalidated()
                                    else error = ctx.getString(R.string.err_vault_decrypt)
                                }
                            },
                            onError = { msg -> error = ctx.getString(R.string.err_auth_failed, msg); working = false },
                            onCancel = { error = ctx.getString(R.string.err_auth_cancelled); working = false },
                        )
                    }.onFailure {
                        working = false
                        if (VaultRecovery.classifyUnlockFailure(it) ==
                            VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED
                        ) onInvalidated()
                        else error = ctx.getString(R.string.err_crypto_init, it.message)
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (working) stringResource(R.string.unlock_working)
                    else stringResource(R.string.unlock_action)
                )
            }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_close))
            }
        }
    }
}

/** UI-facing operation state for a threaded crypto/IO action (§2.2). */
private sealed interface OpState {
    data object Idle : OpState
    data object Working : OpState
    data class Done(val msg: String) : OpState
    data class Failed(val msg: String) : OpState
}

@Composable
private fun ListScreen(
    store: VaultFolderStore,
    onAdd: () -> Unit,
    onFolders: () -> Unit,
    onLock: () -> Unit,
    onDiagnostics: () -> Unit,
    onExportBackup: () -> Unit,
    onImportBackup: () -> Unit,
    onView: (VaultFolderEntry) -> Unit,
    showMessage: (String) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var revision by remember { mutableIntStateOf(0) }
    var deleteCandidate by remember { mutableStateOf<VaultFolderEntry?>(null) }
    var exportState by remember { mutableStateOf<OpState>(OpState.Idle) }

    // §1.2 crash fix: hold the entry ID STRING (natively saveable), never the
    // non-Parcelable VaultFolderEntry, across the SAF round-trip. On return we
    // re-resolve the id against live metadata, which also fixes the stale-object
    // hazard (exporting a snapshot that no longer matches disk).
    var pendingExportId by rememberSaveable { mutableStateOf<String?>(null) }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri: Uri? ->
        Diagnostics.log("vault-folder.List",
            "exportLauncher result: uri=${if (uri != null) "non-null" else "null"}")
        VaultFolderManager.endTransientFlight()
        val target = pendingExportId?.let { id -> store.contents.entries.firstOrNull { it.id == id } }
        pendingExportId = null
        if (uri == null) return@rememberLauncherForActivityResult
        if (target == null) {
            showMessage(ctx.getString(R.string.list_export_unavailable))
            return@rememberLauncherForActivityResult
        }
        // §2: run decrypt+write off the main thread; surface a real state.
        exportState = OpState.Working
        scope.launch {
            val outcome = withContext(Bg.io) { runCatching { store.exportFile(target, uri) } }
            exportState = outcome.fold(
                onSuccess = {
                    Diagnostics.log("vault-folder.List", "exported ${target.name} ok")
                    OpState.Done(ctx.getString(R.string.list_export_done, target.name))
                },
                onFailure = {
                    Diagnostics.error("vault-folder.List",
                        "export failed: ${it.javaClass.simpleName}: ${it.message}")
                    OpState.Failed(ctx.getString(R.string.list_export_failed, it.message))
                },
            )
        }
    }

    SuiteScaffold(title = stringResource(R.string.title_list)) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(
                stringResource(R.string.list_file_count, store.contents.entries.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            ) {
                Button(onClick = onAdd, modifier = Modifier.weight(1f).fillMaxWidth()) {
                    Text(stringResource(R.string.action_add_file))
                }
                OutlinedButton(onClick = onLock, modifier = Modifier.weight(1f).fillMaxWidth()) {
                    Text(stringResource(R.string.action_lock))
                }
            }
            OutlinedButton(onClick = onFolders, modifier = Modifier.fillMaxWidth()) {
                val label = if (store.folderId == VaultFolder.DEFAULT_FOLDER_ID)
                    stringResource(R.string.list_folder_default)
                else stringResource(R.string.list_folder_named, store.folderId.take(8))
                Text(label)
            }

            @Suppress("UNUSED_EXPRESSION") revision

            when (val s = exportState) {
                is OpState.Working -> {
                    Text(
                        stringResource(R.string.list_exporting),
                        style = MaterialTheme.typography.bodySmall,
                        color = UnderstoryTheme.semantic.warning,
                    )
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
                is OpState.Done -> LaunchedEffect(s) { showMessage(s.msg); exportState = OpState.Idle }
                is OpState.Failed -> LaunchedEffect(s) { showMessage(s.msg); exportState = OpState.Idle }
                OpState.Idle -> {}
            }

            if (store.contents.entries.isEmpty()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
                Text(
                    stringResource(R.string.list_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.weight(1f))
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    modifier = Modifier.fillMaxWidth().weight(1f),
                ) {
                    items(store.contents.entries, key = { it.id }) { entry ->
                        EntryRow(
                            entry = entry,
                            canView = ViewerSupport.isSupported(entry.mimeType),
                            busy = exportState is OpState.Working,
                            onView = { onView(entry) },
                            onExport = {
                                Diagnostics.log("vault-folder.List", "export tap: ${entry.name}")
                                pendingExportId = entry.id
                                VaultFolderManager.beginTransientFlight()
                                runCatching { exportLauncher.launch(entry.name) }
                                    .onFailure {
                                        Diagnostics.error("vault-folder.List",
                                            "exportLauncher.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                                        VaultFolderManager.endTransientFlight()
                                        pendingExportId = null
                                    }
                            },
                            onDelete = { deleteCandidate = entry },
                        )
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            ) {
                OutlinedButton(onClick = onExportBackup, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_backup))
                }
                OutlinedButton(onClick = onImportBackup, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_restore))
                }
            }
            OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_diagnostics))
            }
        }
    }

    deleteCandidate?.let { entry ->
        AlertDialog(
            onDismissRequest = { deleteCandidate = null },
            title = { Text(stringResource(R.string.delete_file_title)) },
            text = {
                val dialogView = LocalView.current
                DisposableEffect(dialogView) {
                    dialogView.filterTouchesWhenObscured = true
                    onDispose { }
                }
                Column {
                    Text(
                        entry.name,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    Text(
                        stringResource(R.string.delete_file_body),
                        style = MaterialTheme.typography.bodySmall,
                        color = UnderstoryTheme.semantic.warning,
                    )
                }
            },
            confirmButton = {
                val dialogView = LocalView.current
                TextButton(onClick = {
                    if (!dialogView.hasWindowFocus()) return@TextButton
                    val target = entry
                    deleteCandidate = null
                    scope.launch {
                        val outcome = withContext(Bg.io) { runCatching { store.deleteFile(target) } }
                        outcome.fold(
                            onSuccess = {
                                revision++
                                showMessage(ctx.getString(R.string.delete_file_done, target.name))
                            },
                            onFailure = {
                                showMessage(ctx.getString(R.string.delete_file_failed, it.message))
                            },
                        )
                    }
                }) {
                    Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteCandidate = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun EntryRow(
    entry: VaultFolderEntry,
    canView: Boolean,
    busy: Boolean,
    onView: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(UnderstoryTheme.spacing.md)) {
            Text(
                entry.name,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                stringResource(R.string.entry_meta, entry.mimeType, humanSize(entry.sizeBytes)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Row(horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                if (canView) {
                    OutlinedButton(onClick = onView, enabled = !busy, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.viewer_action))
                    }
                }
                OutlinedButton(onClick = onExport, enabled = !busy, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_export))
                }
                SecureOutlinedButton(onClick = onDelete, enabled = !busy, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_delete))
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
    showMessage: (String) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var opState by remember { mutableStateOf<OpState>(OpState.Idle) }
    val working = opState is OpState.Working
    var shredSource by rememberSaveable { mutableStateOf(false) }
    var pendingShredConfirm by remember { mutableStateOf<Uri?>(null) }
    // §3.2: a deposit (ACTION_VIEW incoming URI) MUST be confirmed before it is
    // encrypted into the vault, independent of the shred toggle.
    var pendingDepositConfirm by remember { mutableStateOf<Uri?>(null) }

    fun runAdd(uri: Uri) {
        opState = OpState.Working
        val opts = if (shredSource) IngestOptions.SHRED_SOURCE else IngestOptions.READ_ONLY
        scope.launch {
            val outcome = withContext(Bg.io) {
                runCatching {
                    val (name, mime) = queryDisplayMetadata(ctx, uri)
                    store.addFile(uri, name, mime, opts)
                }
            }
            outcome.fold(
                onSuccess = { result ->
                    Diagnostics.log("vault-folder.Add",
                        "addFile ok: ${result.entry.name} (${result.entry.sizeBytes} B) " +
                            "shred=${result.javaClass.simpleName}")
                    val msg = when (result) {
                        is AddResult.Added ->
                            ctx.getString(R.string.add_done, result.entry.name, humanSize(result.entry.sizeBytes))
                        is AddResult.AddedSourceShredded ->
                            ctx.getString(R.string.add_done_shredded, result.entry.name)
                        is AddResult.AddedSourceShredFailed ->
                            ctx.getString(R.string.add_done_shred_failed, result.entry.name, result.reason)
                    }
                    opState = OpState.Idle
                    showMessage(msg)
                    if (result !is AddResult.AddedSourceShredFailed) onSaved()
                },
                onFailure = {
                    Diagnostics.error("vault-folder.Add",
                        "addFile failed: ${it.javaClass.simpleName}: ${it.message}")
                    opState = OpState.Idle
                    showMessage(ctx.getString(R.string.add_failed, it.message ?: it.javaClass.simpleName))
                },
            )
        }
    }

    /** Entry point that respects the shred confirm dialog when shred is on. */
    fun beginAdd(uri: Uri) {
        if (shredSource) pendingShredConfirm = uri else runAdd(uri)
    }

    val pickInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        Diagnostics.log("vault-folder.Add",
            "pickInput result: uri=${if (uri != null) "non-null" else "null"}")
        VaultFolderManager.endTransientFlight()
        if (uri == null) return@rememberLauncherForActivityResult
        // Picker-originated add: the user already chose the file in the system
        // picker, so no second deposit-confirm here (§3.2).
        beginAdd(uri)
    }

    // §3.2: an incoming deposit URI populates the confirm dialog instead of
    // silently encrypting — fixes the false "we confirm before encrypting" claim.
    LaunchedEffect(incomingUri) {
        if (incomingUri != null) {
            Diagnostics.log("vault-folder.Add", "deposit received → confirm interstitial")
            pendingDepositConfirm = incomingUri
        }
    }

    SuiteScaffold(
        title = stringResource(R.string.title_add),
        onBack = onCancel,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(
                stringResource(R.string.add_intro),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = {
                    if (working) return@Button
                    Diagnostics.log("vault-folder.Add", "Pick a file: tap")
                    VaultFolderManager.beginTransientFlight()
                    runCatching { pickInput.launch(arrayOf("*/*")) }
                        .onFailure {
                            Diagnostics.error("vault-folder.Add",
                                "pickInput.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                            VaultFolderManager.endTransientFlight()
                        }
                },
                enabled = !working,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (working) stringResource(R.string.add_working)
                    else stringResource(R.string.add_pick)
                )
            }
            if (working) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

            // §3 GUI a11y: the shared SwitchRow bakes in the merged Role.Switch
            // TalkBack semantics (reads "<label>, switch, on") that a bare Switch
            // in a Row lacks. The supporting line changes with the toggle state.
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth(),
            ) {
                SwitchRow(
                    label = stringResource(R.string.add_shred_label),
                    checked = shredSource,
                    enabled = !working,
                    supporting = if (shredSource) stringResource(R.string.add_shred_on)
                    else stringResource(R.string.add_shred_off),
                    onCheckedChange = {
                        shredSource = it
                        Diagnostics.log("vault-folder.Add", "shred toggle: ${if (it) "ON" else "OFF"}")
                    },
                )
            }

            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            OutlinedButton(onClick = onCancel, enabled = !working, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_back))
            }
        }
    }

    // §3.2 deposit-confirm interstitial. Renders metadata ONLY (no content
    // render) so a hostile deposit can't paint UI. On confirm it routes through
    // beginAdd (which still shows the shred confirm if the user has shred on).
    pendingDepositConfirm?.let { uri ->
        val meta = remember(uri) { queryDisplayMetadata(ctx, uri) }
        val displayName = remember(meta) { clampName(meta.first) }
        val sizeText = remember(uri) { humanSize(queryDisplaySize(ctx, uri)) }
        val folderLabel = if (store.folderId == VaultFolder.DEFAULT_FOLDER_ID)
            stringResource(R.string.folder_default_name)
        else store.folderId.take(8) + "…"
        AlertDialog(
            onDismissRequest = {
                pendingDepositConfirm = null
                showMessage(ctx.getString(R.string.deposit_cancelled))
            },
            title = { Text(stringResource(R.string.deposit_confirm_title)) },
            text = {
                Text(
                    stringResource(
                        R.string.deposit_confirm_body,
                        displayName,
                        meta.second ?: "application/octet-stream",
                        sizeText,
                        folderLabel,
                    ),
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingDepositConfirm = null
                    beginAdd(uri)
                }) { Text(stringResource(R.string.deposit_confirm_add)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    pendingDepositConfirm = null
                    showMessage(ctx.getString(R.string.deposit_cancelled))
                }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    pendingShredConfirm?.let { uri ->
        AlertDialog(
            onDismissRequest = { pendingShredConfirm = null },
            title = { Text(stringResource(R.string.shred_title)) },
            text = {
                Text(stringResource(R.string.shred_body))
            },
            confirmButton = {
                TextButton(onClick = {
                    val u = pendingShredConfirm
                    pendingShredConfirm = null
                    if (u != null) runAdd(u)
                }) {
                    Text(stringResource(R.string.shred_confirm), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingShredConfirm = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
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

private fun queryDisplaySize(ctx: Context, uri: Uri): Long {
    var size = 0L
    runCatching {
        ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
            if (c.moveToFirst() && sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx)
        }
    }
    return size
}

/**
 * §3.3: deposit filenames are attacker-influenced. Clamp the DISPLAYED name to a
 * sane length so the confirm dialog stays readable and un-spoofable. Display
 * only — the stored name is the full sanitized value.
 */
private fun clampName(name: String): String =
    if (name.length <= 120) name else name.take(117) + "…"

private fun humanSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> "${bytes / (1024 * 1024)} MB"
}
