package com.understory.vaultfolder

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import com.understory.security.Crypto
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/**
 * Encrypted file storage. Each user-imported file becomes its own
 * AES-GCM envelope (`f-{uuid}.bin`) under the vault's master KEK; a
 * separate `metadata.bin` keeps the directory of original names + sizes
 * + timestamps, also encrypted under the same KEK.
 *
 * On-disk layout under `ctx.filesDir/vault-folder/`:
 *
 *   metadata.bin     — header_v1 || iv12 || ct(JSON contents) || tag16
 *   f-{uuid}.bin     — header_v1 || iv12 || ct(file bytes) || tag16
 *   f-{uuid}.bin
 *   ...
 *
 * Each blob is independently AES-GCM-encrypted with a fresh per-blob
 * IV; the master KEK is shared across all blobs in this vault.
 *
 * Why per-file blobs (not one big container):
 *   - Adding a file doesn't rewrite the whole vault.
 *   - A corrupt blob loses one file, not the whole vault.
 *   - Deletes can use atomic file delete + metadata rewrite.
 *
 * Per-file size cap (20 MiB) is enforced on import — vault-folder is
 * for documents, keys, recovery codes, photos. Bigger media isn't its
 * use case. The cap also prevents accidentally encrypting a video the
 * user thought was tiny.
 */
class VaultFolderStore internal constructor(
    ctx: Context,
    private val kek: ByteArray,
    @Volatile private var contentsState: VaultFolderContents,
    /** Which folder this store backs. Defaults to the legacy single-folder
     *  vault for back-compat with callers that haven't migrated to
     *  multi-folder. New folders pass their own id. */
    val folderId: String = VaultFolder.DEFAULT_FOLDER_ID,
) {
    // Always store the application context — never an Activity context.
    // VaultFolderStore lives in the VaultFolderManager process-singleton,
    // which survives across activity recreation. Holding an Activity
    // context here would leak the entire view hierarchy every time the
    // activity is recreated (which on Samsung happens during SAF
    // round-trips). Application context is process-scoped and stable —
    // contentResolver / filesDir / etc. all work identically through it.
    //
    // Lint's StaticFieldLeak analyzer is structural — it flags any Context
    // field reachable from a singleton — and doesn't trace the
    // applicationContext coercion. The suppression below is annotated with
    // this contract so a future regression that drops the .applicationContext
    // call would still be caught at code review (the comment + the
    // suppression contract have to be removed in lockstep).
    @SuppressLint("StaticFieldLeak")
    private val ctx: Context = ctx.applicationContext
    /** Public read-only view of metadata. */
    val contents: VaultFolderContents get() = contentsState

    /** Per-file size cap. */
    val maxFileSize: Long = MAX_FILE_BYTES

    /**
     * Add a new file. [inputUri] is a SAF-granted read URI; we copy +
     * encrypt the bytes under a fresh blob id, then update the
     * metadata. Back-compat shim for callers that don't need shred.
     */
    fun addFile(inputUri: Uri, displayName: String, mimeType: String?): VaultFolderEntry {
        return when (val r = addFile(inputUri, displayName, mimeType, IngestOptions.READ_ONLY)) {
            is AddResult.Added -> r.entry
            is AddResult.AddedSourceShredded -> r.entry
            is AddResult.AddedSourceShredFailed -> r.entry
        }
    }

    /**
     * Add a new file with explicit ingest options.
     *
     * When [opts] requests source deletion, after a successful encrypt
     * we attempt `ContentResolver.delete(uri, null, null)`. That only
     * succeeds when the URI was granted with FLAG_GRANT_WRITE_URI_
     * PERMISSION (typically OpenDocument or DocumentTree pickers, NOT
     * bare ACTION_VIEW). On failure the import IS NOT rolled back —
     * the encrypted copy in the vault is the user's primary copy now;
     * the shred-failed result lets the UI surface the source-deletion
     * failure so the user can manually delete the original.
     */
    fun addFile(
        inputUri: Uri,
        displayName: String,
        mimeType: String?,
        opts: IngestOptions,
    ): AddResult {
        val plaintext = readBoundedBytes(inputUri)
        val blobId = UUID.randomUUID().toString()
        val sizeBytes = plaintext.size.toLong()
        try {
            writeBlob(blobId, plaintext)
        } finally {
            Crypto.wipe(plaintext)
        }
        val entry = VaultFolderEntry(
            id = blobId,
            name = displayName,
            mimeType = mimeType ?: "application/octet-stream",
            sizeBytes = sizeBytes,
            createdAtMs = System.currentTimeMillis(),
        )
        contentsState = contentsState.copy(entries = contentsState.entries + entry)
        saveMetadata()

        if (!opts.deleteSourceAfterImport) return AddResult.Added(entry)

        val shred = runCatching {
            ctx.contentResolver.delete(inputUri, null, null)
        }
        return when {
            shred.isSuccess && (shred.getOrNull() ?: 0) > 0 -> AddResult.AddedSourceShredded(entry)
            shred.isSuccess -> AddResult.AddedSourceShredFailed(
                entry,
                "ContentResolver.delete returned 0 rows — the source provider " +
                    "didn't honor the delete (likely a read-only URI grant from " +
                    "ACTION_VIEW; OpenDocument grants WRITE which most providers " +
                    "treat as deletable).",
            )
            else -> AddResult.AddedSourceShredFailed(
                entry,
                "Shred failed: ${shred.exceptionOrNull()?.message ?: "unknown"}",
            )
        }
    }

    /**
     * Export a file to [outputUri]. Decrypts the blob and writes the
     * plaintext to the SAF-granted output URI.
     */
    fun exportFile(entry: VaultFolderEntry, outputUri: Uri) {
        val plaintext = readBlob(entry.id)
        try {
            ctx.contentResolver.openOutputStream(outputUri, "w").use { out ->
                requireNotNull(out) { "couldn't open output stream" }
                out.write(plaintext)
            }
        } finally {
            Crypto.wipe(plaintext)
        }
    }

    /** Permanently delete the blob + metadata entry. */
    fun deleteFile(entry: VaultFolderEntry) {
        val file = File(blobsDir(), "f-${entry.id}.bin")
        runCatching { file.delete() }
        contentsState = contentsState.copy(
            entries = contentsState.entries.filter { it.id != entry.id },
        )
        saveMetadata()
    }

    /**
     * Lock — wipe the in-memory KEK. After this the store is unusable;
     * the caller must obtain a new instance via [VaultFolder.unlock].
     */
    fun lock() {
        Crypto.wipe(kek)
        contentsState = VaultFolderContents(emptyList())
    }

    private fun saveMetadata() {
        val json = serializeContents(contentsState).toByteArray(Charsets.UTF_8)
        val ct = Crypto.aesGcmEncrypt(kek, json)
        Crypto.wipe(json)
        atomicWrite(File(VaultFolder.vaultDir(ctx, folderId), METADATA_FILE), ct)
    }

    private fun writeBlob(blobId: String, plaintext: ByteArray) {
        val ct = Crypto.aesGcmEncrypt(kek, plaintext)
        atomicWrite(File(blobsDir(), "f-$blobId.bin"), ct)
    }

    private fun readBlob(blobId: String): ByteArray {
        val file = File(blobsDir(), "f-$blobId.bin")
        require(file.exists()) { "blob ${blobId} missing on disk" }
        val ct = file.readBytes()
        return Crypto.aesGcmDecrypt(kek, ct)
    }

    private fun blobsDir(): File = VaultFolder.vaultDir(ctx, folderId)

    private fun readBoundedBytes(uri: Uri): ByteArray {
        ctx.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "couldn't open input stream" }
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var total = 0
            while (true) {
                val n = input.read(buf); if (n < 0) break
                total += n
                require(total <= MAX_FILE_BYTES) {
                    "file too large (>${MAX_FILE_BYTES / (1024 * 1024)} MiB); " +
                        "vault-folder is for documents and small media, not video archives"
                }
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    companion object {
        private const val MAX_FILE_BYTES: Long = 20L * 1024 * 1024
        const val METADATA_FILE = "metadata.bin"

        internal fun atomicWrite(target: File, bytes: ByteArray) {
            target.parentFile?.mkdirs()
            val tmp = File(target.parentFile, "${target.name}.tmp")
            try {
                tmp.outputStream().use { out: OutputStream -> out.write(bytes) }
                try {
                    Files.move(
                        tmp.toPath(),
                        target.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE,
                    )
                } catch (_: Throwable) {
                    if (!tmp.renameTo(target)) {
                        target.delete()
                        check(tmp.renameTo(target)) { "atomic write failed for ${target.name}" }
                    }
                }
            } finally {
                runCatching { if (tmp.exists()) tmp.delete() }
            }
        }

        internal fun serializeContents(c: VaultFolderContents): String {
            val arr = JSONArray()
            for (e in c.entries) arr.put(e.toJson())
            return JSONObject().apply { put("entries", arr) }.toString()
        }

        internal fun parseContents(text: String): VaultFolderContents {
            val o = JSONObject(text)
            val arr = o.optJSONArray("entries") ?: JSONArray()
            val entries = mutableListOf<VaultFolderEntry>()
            for (i in 0 until arr.length()) {
                entries += VaultFolderEntry.fromJson(arr.getJSONObject(i))
            }
            return VaultFolderContents(entries)
        }
    }
}

data class VaultFolderEntry(
    val id: String,
    val name: String,
    val mimeType: String,
    val sizeBytes: Long,
    val createdAtMs: Long,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("mime", mimeType)
        put("size", sizeBytes)
        put("created", createdAtMs)
    }

    companion object {
        fun fromJson(o: JSONObject): VaultFolderEntry = VaultFolderEntry(
            id = o.optString("id", UUID.randomUUID().toString()),
            name = o.optString("name", "(unnamed)"),
            mimeType = o.optString("mime", "application/octet-stream"),
            sizeBytes = o.optLong("size", 0),
            createdAtMs = o.optLong("created", System.currentTimeMillis()),
        )
    }
}

data class VaultFolderContents(val entries: List<VaultFolderEntry>)

/**
 * Options driving a single [VaultFolderStore.addFile] call.
 *
 * [deleteSourceAfterImport] (a.k.a. "shred") asks the store to call
 * `ContentResolver.delete` on the source URI after the encrypted
 * copy is committed. Whether the delete actually succeeds depends on
 * what permissions the URI was granted with — see [AddResult] for
 * the three terminal states.
 */
data class IngestOptions(
    val deleteSourceAfterImport: Boolean,
) {
    companion object {
        /** Don't touch the source. Default for plain-pick flows. */
        val READ_ONLY = IngestOptions(deleteSourceAfterImport = false)

        /** Try to delete the source after a successful encrypt. */
        val SHRED_SOURCE = IngestOptions(deleteSourceAfterImport = true)
    }
}

/**
 * Three terminal states for [VaultFolderStore.addFile]:
 *
 * - [Added]: the encrypted copy is in the vault; the source is intact
 *   (either by request, or by default).
 * - [AddedSourceShredded]: the encrypted copy is in the vault AND the
 *   source URI was successfully deleted via ContentResolver.
 * - [AddedSourceShredFailed]: the encrypted copy is in the vault but
 *   the shred attempt failed. The source is still on the user's
 *   filesystem; UI should surface the [reason] so the user can delete
 *   manually if they wish.
 *
 * The import itself never rolls back when the shred fails: the
 * encrypted copy is the user's primary copy now, and double-deleting
 * (or losing the encrypted copy) would be worse than leaving the
 * source in place with a clear surface message.
 */
sealed class AddResult {
    abstract val entry: VaultFolderEntry

    data class Added(override val entry: VaultFolderEntry) : AddResult()
    data class AddedSourceShredded(override val entry: VaultFolderEntry) : AddResult()
    data class AddedSourceShredFailed(
        override val entry: VaultFolderEntry,
        val reason: String,
    ) : AddResult()
}
