package com.understory.vaultfolder

import com.understory.backup.BackupAdapter
import com.understory.security.Crypto
import org.json.JSONArray
import org.json.JSONObject
import android.util.Base64

/**
 * vault-folder's [BackupAdapter]. Exports the currently-unlocked folder's
 * files — name/mime/size/timestamp metadata AND the decrypted file bytes —
 * as a self-contained cleartext payload, so a recovery export (encrypted
 * under the vault recovery key by [com.understory.backup.VaultRecoveryEnvelope])
 * reconstructs the actual FILES onto a fresh vault, not a stale hardware KEK.
 *
 * A CLASS (not an object): the unlocked [VaultFolderStore] is held in the
 * activity's process-singleton and injected at the point export/import runs,
 * mirroring [com.understory.passgen.PassgenBackupAdapter].
 *
 * schemaVersion = 2: uses the split-key convention
 * ([com.understory.backup.VaultRecoveryEnvelope.SchemaVersions.SPLIT_KEY_MIN]) —
 * the payload is adapter cleartext and the passphrase is the distinct recovery
 * key, never the raw KEK.
 *
 * Import semantics: merge, add every incoming file as a NEW blob (files have no
 * natural user-facing identity key the way a credential does; a re-import
 * duplicates rather than silently dropping, which is the safe choice for
 * opaque bytes). Returns a human summary.
 */
class VaultFolderBackupAdapter(private val store: VaultFolderStore) : BackupAdapter {

    override val appId: String = "com.understory.vaultfolder"

    override val schemaVersion: Int = 2

    override fun export(): ByteArray {
        val files = JSONArray()
        for (entry in store.contents.entries) {
            val bytes = store.readBlobBytes(entry)
            try {
                files.put(
                    JSONObject().apply {
                        put("name", entry.name)
                        put("mime", entry.mimeType)
                        put("created", entry.createdAtMs)
                        put("bytes", Base64.encodeToString(bytes, Base64.NO_WRAP))
                    },
                )
            } finally {
                Crypto.wipe(bytes)
            }
        }
        val root = JSONObject().apply {
            put("schema", schemaVersion)
            put("files", files)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    override fun import(payload: ByteArray, schemaVersion: Int): String {
        require(schemaVersion <= this.schemaVersion) {
            "backup schemaVersion=$schemaVersion is newer than this build supports " +
                "(${this.schemaVersion}); upgrade vault-folder before importing"
        }
        val root = JSONObject(payload.toString(Charsets.UTF_8))
        val files = root.optJSONArray("files") ?: JSONArray()
        var added = 0
        for (i in 0 until files.length()) {
            val o = files.getJSONObject(i)
            val name = o.optString("name", "(unnamed)")
            val mime = o.optString("mime", "application/octet-stream")
            val b64 = o.optString("bytes", "")
            if (b64.isEmpty()) continue
            val bytes = Base64.decode(b64, Base64.NO_WRAP)
            try {
                store.addRestoredFile(name, mime, bytes)
                added++
            } finally {
                Crypto.wipe(bytes)
            }
        }
        return "Restored $added file" + (if (added == 1) "" else "s") +
            ". ${store.contents.entries.size} total."
    }
}
