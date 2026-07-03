package com.understory.vaultfolder

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Index over the multi-folder layout. The legacy single-folder vault
 * at `filesDir/vault-folder/` becomes the synthetic "default" entry;
 * additional user-created folders live under
 * `filesDir/vault-folder-secondary/<id>/` and are tracked in
 * `filesDir/vault-folder-secondary/folders.json`.
 *
 * Index format (cleartext — folder names + timestamps are non-secret;
 * the *contents* of each folder are encrypted at rest by [VaultFolder]):
 *
 *   {
 *     "version": 1,
 *     "folders": [
 *       {"id": "<uuid>", "name": "Receipts", "createdAtMs": 1700000000000}
 *     ]
 *   }
 *
 * The default folder is NEVER stored in folders.json — it's synthesized
 * on every read. This keeps the legacy single-folder install working
 * without a migration step (no folders.json on disk → just the default
 * entry; create a secondary folder → folders.json gets created lazily).
 *
 * Single-writer assumption: vault-folder is a single-process app and
 * the index is only ever mutated from the main thread's UI flow. No
 * locking; atomic file replace via [VaultFolderStore.atomicWrite].
 */
object VaultFolders {

    private const val INDEX_FILE = "folders.json"
    private const val INDEX_VERSION = 1

    /** Display-name length limits. Hard caps so a malformed index can't
     *  blow up the UI; not security-critical. */
    private const val MIN_NAME_LEN = 1
    private const val MAX_NAME_LEN = 64

    data class FolderInfo(
        val id: String,
        val name: String,
        val createdAtMs: Long,
        val isDefault: Boolean,
    )

    private fun secondaryDir(ctx: Context): File =
        File(ctx.filesDir, "vault-folder-secondary").apply { mkdirs() }

    private fun indexFile(ctx: Context): File =
        File(secondaryDir(ctx), INDEX_FILE)

    /**
     * List every folder. The default folder is included iff it has a
     * header on disk (i.e., a vault has been initialised). Secondary
     * folders are read from the index and filtered to the ones that
     * still have a header on disk — orphan index entries (deleted dir,
     * stale index) are silently skipped so the user isn't presented
     * with un-unlockable cards.
     */
    fun list(ctx: Context): List<FolderInfo> {
        val out = mutableListOf<FolderInfo>()
        if (VaultFolder.exists(ctx, VaultFolder.DEFAULT_FOLDER_ID)) {
            out += FolderInfo(
                id = VaultFolder.DEFAULT_FOLDER_ID,
                name = "Default",
                createdAtMs = 0L, // legacy folder has no recorded creation time
                isDefault = true,
            )
        }
        out += readSecondaries(ctx).filter { VaultFolder.exists(ctx, it.id) }
        return out
    }

    /**
     * Reserve a new folder id + persist the index entry. Returns the
     * id; the caller drives the biometric prompt and then calls
     * [VaultFolder.create] with this id to seed the per-folder KEK +
     * empty metadata.
     *
     * Reserving the row before the biometric prompt means a cancel /
     * fail leaves an orphan index entry (no header on disk). [list]
     * filters those out, and [pruneOrphans] cleans them on demand.
     */
    fun reserveNew(ctx: Context, name: String): FolderInfo {
        val cleaned = sanitizeName(name)
        val id = UUID.randomUUID().toString()
        val info = FolderInfo(
            id = id,
            name = cleaned,
            createdAtMs = System.currentTimeMillis(),
            isDefault = false,
        )
        val current = readSecondaries(ctx).toMutableList()
        current += info
        writeSecondaries(ctx, current)
        return info
    }

    /** Update a folder's display name. Refuses on the default folder
     *  (its display name is hardcoded). */
    fun rename(ctx: Context, folderId: String, newName: String) {
        require(folderId != VaultFolder.DEFAULT_FOLDER_ID) {
            "cannot rename the default folder"
        }
        val cleaned = sanitizeName(newName)
        val updated = readSecondaries(ctx).map { f ->
            if (f.id == folderId) f.copy(name = cleaned) else f
        }
        writeSecondaries(ctx, updated)
    }

    /**
     * Delete a folder. Wipes the per-folder dir (header, metadata,
     * blobs) AND removes the index entry. Refuses on the default
     * folder — deleting it would orphan the vault setup state and
     * the user has to intentionally re-bootstrap; we don't expose
     * that as a one-tap action.
     */
    fun delete(ctx: Context, folderId: String): Boolean {
        require(folderId != VaultFolder.DEFAULT_FOLDER_ID) {
            "cannot delete the default folder"
        }
        val dir = VaultFolder.vaultDir(ctx, folderId)
        val ok = runCatching { dir.deleteRecursively() }.getOrDefault(false)
        val updated = readSecondaries(ctx).filter { it.id != folderId }
        writeSecondaries(ctx, updated)
        return ok
    }

    /** Drop index entries whose dirs no longer exist. Cosmetic. */
    fun pruneOrphans(ctx: Context) {
        val live = readSecondaries(ctx).filter { VaultFolder.exists(ctx, it.id) }
        writeSecondaries(ctx, live)
    }

    // ---------- index file IO ----------

    private fun readSecondaries(ctx: Context): List<FolderInfo> {
        val f = indexFile(ctx)
        if (!f.exists()) return emptyList()
        return runCatching {
            val text = f.readText(Charsets.UTF_8)
            val o = JSONObject(text)
            val arr = o.optJSONArray("folders") ?: JSONArray()
            (0 until arr.length()).map { i ->
                val e = arr.getJSONObject(i)
                FolderInfo(
                    id = e.getString("id"),
                    name = e.optString("name", "(unnamed)"),
                    createdAtMs = e.optLong("createdAtMs", 0L),
                    isDefault = false,
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun writeSecondaries(ctx: Context, folders: List<FolderInfo>) {
        val arr = JSONArray()
        for (f in folders) {
            arr.put(JSONObject().apply {
                put("id", f.id)
                put("name", f.name)
                put("createdAtMs", f.createdAtMs)
            })
        }
        val o = JSONObject().apply {
            put("version", INDEX_VERSION)
            put("folders", arr)
        }
        VaultFolderStore.atomicWrite(indexFile(ctx), o.toString().toByteArray(Charsets.UTF_8))
    }

    private fun sanitizeName(raw: String): String {
        val trimmed = raw.trim()
        require(trimmed.length in MIN_NAME_LEN..MAX_NAME_LEN) {
            "folder name must be $MIN_NAME_LEN..$MAX_NAME_LEN chars; got ${trimmed.length}"
        }
        return trimmed
    }
}
