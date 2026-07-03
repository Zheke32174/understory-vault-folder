package com.understory.vaultfolder

import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue

/**
 * Process-singleton holding the currently-unlocked vault folder, if
 * any. Mirrors the AegisVaultManager pattern: MainActivity unlocks via
 * BiometricPrompt and places the [VaultFolderStore] here so subsequent
 * Compose screens can read from it without re-prompting.
 *
 * Lifecycle:
 *   - MainActivity unlocks → [setUnlocked].
 *   - Activity lifecycle hooks (onStop, onDestroy, onUserLeaveHint)
 *     call [clear], which locks the store and wipes the KEK.
 *   - Process death also clears it implicitly.
 *
 * Also tracks "transient flight" — deliberate SAF picker / biometric
 * round-trips. While in-flight, the activity's onStop preserves the
 * unlocked store rather than wiping it, so the user comes back from
 * the picker still holding their session. Without this, Samsung One
 * UI's aggressive memory management nulls the store during the brief
 * stop and the user is bounced back to the Unlock screen with no SAF
 * result delivered.
 */
object VaultFolderManager {
    // The held VaultFolderStore contains a Context field which lint
    // structurally flags as StaticFieldLeak (singleton -> Context = leaked
    // Activity). The constructor coerces that Context to applicationContext
    // (see VaultFolderStore.kt), so the actual leak risk is mitigated.
    // Lint's analyzer doesn't trace that coercion; suppressing here. If a
    // future change drops the .applicationContext coercion, this
    // suppression also has to come off.
    @android.annotation.SuppressLint("StaticFieldLeak")
    @Volatile private var unlocked: VaultFolderStore? = null

    val current: VaultFolderStore? get() = unlocked
    val isUnlocked: Boolean get() = unlocked != null

    fun setUnlocked(store: VaultFolderStore) {
        unlocked = store
    }

    fun clear() {
        runCatching { unlocked?.lock() }
        unlocked = null
    }

    /**
     * A deposit URI (ACTION_VIEW) that arrived via onNewIntent while a
     * MainActivity instance was already alive (§3.4 / A7 warm-task edge). Held
     * as observable Compose state so the root recomposes and routes it into the
     * deposit-confirm dialog; process-bound (cleared on lock/close). Without
     * this a warm-task deposit is silently dropped — only onCreate reads
     * intent.data.
     */
    var pendingDepositUri: android.net.Uri? by androidx.compose.runtime.mutableStateOf(null)

    @Volatile private var transientFlightCount = 0
    private val flightLock = Any()

    fun beginTransientFlight() {
        synchronized(flightLock) { transientFlightCount++ }
    }

    fun endTransientFlight() {
        synchronized(flightLock) { if (transientFlightCount > 0) transientFlightCount-- }
    }

    val isInTransientFlight: Boolean
        get() = synchronized(flightLock) { transientFlightCount > 0 }
}
