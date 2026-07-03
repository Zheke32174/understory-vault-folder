package com.understory.vaultfolder

import android.content.Context
import com.understory.security.VaultResetHooks

/**
 * App glue for the shared [com.understory.security.VaultRecoveryScreen] reset
 * flow (§4.2). All vault-folder-specific knowledge lives behind these four
 * calls so the shared screen stays app-agnostic.
 *
 * @param onSetup routes the app back to its Setup stage after a wipe.
 */
class VaultFolderResetHooks(private val onSetup: () -> Unit) : VaultResetHooks {

    override fun exists(ctx: Context): Boolean = VaultFolder.exists(ctx)

    override fun exportPayload(unlocked: Any): ByteArray? {
        val store = unlocked as? VaultFolderStore ?: return null
        return VaultFolderBackupAdapter(store).export()
    }

    /**
     * Wipe every folder dir (default + secondaries) AND the shared device-auth
     * Keystore key, plus the recovery-state bookkeeping. One device-auth key
     * backs all folders, so this correctly clears them together (re-enrollment
     * already bricked them together).
     */
    override fun wipe(ctx: Context) {
        VaultFolder.deleteAll(ctx)
        RecoveryStateStore.clear(ctx)
    }

    override fun goToSetup() = onSetup()
}
