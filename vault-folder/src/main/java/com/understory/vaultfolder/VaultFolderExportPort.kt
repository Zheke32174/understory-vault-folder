package com.understory.vaultfolder

import com.understory.backup.VaultRecoveryEnvelope
import com.understory.security.Crypto
import com.understory.security.VaultExportPort
import java.io.InputStream
import java.io.OutputStream

/**
 * vault-folder's bridge from the shared export/import composables
 * ([com.understory.security.VaultExportScreen] / `VaultImportScreen`) to the
 * `common-backup` [VaultRecoveryEnvelope] + [VaultFolderBackupAdapter].
 *
 * Lives in the app module because that is the only place that vendors BOTH
 * common-security (the port interface) and common-backup (the envelope) — the
 * module graph is common-backup -> common-security, so a common-security
 * composable cannot reference the envelope directly (see [VaultExportPort]).
 *
 * The [unlocked] handle the shared screens pass back is the app's
 * [VaultFolderStore]; the adapter is constructed from it on demand.
 */
class VaultFolderExportPort : VaultExportPort {

    override val appId: String = "com.understory.vaultfolder"
    override val schemaVersion: Int = 2
    override val appLabel: String = "File Vault"

    override fun buildPayload(unlocked: Any?): ByteArray? {
        val store = unlocked as? VaultFolderStore ?: return null
        return VaultFolderBackupAdapter(store).export()
    }

    override fun writeEncrypted(out: OutputStream, payload: ByteArray, key: CharArray, label: String) {
        VaultRecoveryEnvelope.writeEncrypted(out, appId, schemaVersion, payload, key, label)
    }

    override fun peekAppId(input: InputStream): String =
        VaultRecoveryEnvelope.open(input).appId

    override fun decryptAndImport(input: InputStream, key: CharArray): String {
        // Import needs the unlocked store to write restored blobs. The shared
        // import screen does not carry a vault handle, so this port is only
        // wired for import when the caller has set [importTarget] to the live
        // store immediately before navigating to the import screen.
        val store = importTarget ?: error("No unlocked vault to restore into.")
        val opened = VaultRecoveryEnvelope.open(input)
        val payload = VaultRecoveryEnvelope.decrypt(opened, key)
        try {
            return VaultFolderBackupAdapter(store).import(payload, opened.schemaVersion)
        } finally {
            Crypto.wipe(payload)
        }
    }

    /** Live store the import screen restores into; set before navigating to import. */
    var importTarget: VaultFolderStore? = null
}
