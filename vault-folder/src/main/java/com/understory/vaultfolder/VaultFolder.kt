package com.understory.vaultfolder

import android.content.Context
import com.understory.security.Crypto
import java.io.File
import java.io.InputStream
import javax.crypto.Cipher

/**
 * Vault-folder bootstrap + unlock. Same snake-eats-tail pattern the
 * other suite vaults use: a 32-byte master KEK is generated at first
 * setup, wrapped under the device-credential-bound Keystore key, and
 * stored alongside the encrypted metadata + blobs. BiometricPrompt
 * gates each unlock; the released cipher decrypts the wrapped KEK,
 * which then decrypts everything else.
 *
 * On-disk layout:
 *
 *   filesDir/vault-folder/                  (legacy: folderId == "default")
 *     header.bin       — wrapped-KEK bundle
 *     metadata.bin     — see VaultFolderStore
 *     f-{uuid}.bin     — blobs
 *
 *   filesDir/vault-folder-secondary/        (multi-folder: any other id)
 *     folders.json     — index (see [VaultFolders])
 *     {folderId}/
 *       header.bin
 *       metadata.bin
 *       f-{uuid}.bin
 *
 * The default folder is hardcoded to live at the legacy path so devices
 * that already have a vault don't need migration. New folders created
 * via [VaultFolders.create] live under `vault-folder-secondary/<id>/`.
 *
 * The header is laid out the same as passgen/aegis vault headers (V2
 * format), minus the content-blob trailer — content lives in
 * [VaultFolderStore.METADATA_FILE] and the per-blob files instead of
 * being concatenated with the header.
 */
object VaultFolder {

    private const val VERSION_V1: Byte = 1

    private const val MAX_IV_LEN = 256
    private const val MAX_WRAPPED_KEK_LEN = 256
    const val MASTER_KEK_BYTES = 32

    /** Reserved id for the legacy single-folder vault. Never assigned to
     *  a user-created folder; [VaultFolders.create] rejects it. */
    const val DEFAULT_FOLDER_ID = "default"

    /**
     * Dir holding the data files for [folderId]. Default folder lives
     * at the legacy path; secondaries live under
     * `vault-folder-secondary/<id>/`.
     */
    fun vaultDir(ctx: Context, folderId: String = DEFAULT_FOLDER_ID): File =
        if (folderId == DEFAULT_FOLDER_ID) {
            File(ctx.filesDir, "vault-folder").apply { mkdirs() }
        } else {
            File(File(ctx.filesDir, "vault-folder-secondary"), folderId).apply { mkdirs() }
        }

    private fun headerFile(ctx: Context, folderId: String = DEFAULT_FOLDER_ID): File =
        File(vaultDir(ctx, folderId), "header.bin")

    fun exists(ctx: Context, folderId: String = DEFAULT_FOLDER_ID): Boolean =
        headerFile(ctx, folderId).exists()

    /**
     * Sweep an orphan `.tmp` left by an interrupted write. Pure
     * housekeeping — the real files are atomically moved into place.
     */
    private fun sweepTmp(ctx: Context, folderId: String) {
        runCatching {
            vaultDir(ctx, folderId).listFiles { _, name -> name.endsWith(".tmp") }
                ?.forEach { it.delete() }
        }
    }

    /** First-time setup. Caller has authenticated via BiometricPrompt. */
    fun create(
        ctx: Context,
        deviceAuthEncryptCipher: Cipher,
        folderId: String = DEFAULT_FOLDER_ID,
    ): VaultFolderStore {
        sweepTmp(ctx, folderId)
        val masterKek = Crypto.randomBytes(MASTER_KEK_BYTES)
        try {
            val wrappedKekCt = deviceAuthEncryptCipher.doFinal(masterKek)
            val wrappedKekIv = deviceAuthEncryptCipher.iv

            writeHeader(ctx, folderId, wrappedKekIv, wrappedKekCt)

            val store = VaultFolderStore(ctx, masterKek.copyOf(), VaultFolderContents(emptyList()), folderId)
            // Persist an empty metadata.bin so unlock has something to decode.
            persistEmptyMetadata(ctx, folderId, masterKek)
            return store
        } finally {
            Crypto.wipe(masterKek)
        }
    }

    /** Unlock. Caller has authenticated via BiometricPrompt with the IV from [ivForUnlock]. */
    fun unlock(
        ctx: Context,
        deviceAuthDecryptCipher: Cipher,
        folderId: String = DEFAULT_FOLDER_ID,
    ): VaultFolderStore {
        sweepTmp(ctx, folderId)
        val (header, _) = readHeader(ctx, folderId)
        val masterKek = deviceAuthDecryptCipher.doFinal(header.wrappedKekCt)
        val metadataFile = File(vaultDir(ctx, folderId), VaultFolderStore.METADATA_FILE)
        val contents = if (metadataFile.exists()) {
            val ct = metadataFile.readBytes()
            val pt = Crypto.aesGcmDecrypt(masterKek, ct)
            try {
                VaultFolderStore.parseContents(String(pt, Charsets.UTF_8))
            } finally {
                Crypto.wipe(pt)
            }
        } else {
            VaultFolderContents(emptyList())
        }
        return VaultFolderStore(ctx, masterKek, contents, folderId)
    }

    /** IV from disk, fed back into [Crypto.deviceAuthCipherForDecrypt]. */
    fun ivForUnlock(ctx: Context, folderId: String = DEFAULT_FOLDER_ID): ByteArray =
        readHeader(ctx, folderId).first.wrappedKekIv

    private fun persistEmptyMetadata(ctx: Context, folderId: String, kek: ByteArray) {
        val empty = VaultFolderStore.serializeContents(VaultFolderContents(emptyList()))
            .toByteArray(Charsets.UTF_8)
        val ct = Crypto.aesGcmEncrypt(kek, empty)
        Crypto.wipe(empty)
        VaultFolderStore.atomicWrite(File(vaultDir(ctx, folderId), VaultFolderStore.METADATA_FILE), ct)
    }

    private fun writeHeader(ctx: Context, folderId: String, iv: ByteArray, ct: ByteArray) {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(VERSION_V1))
        out.write(intBE(iv.size))
        out.write(iv)
        out.write(intBE(ct.size))
        out.write(ct)
        VaultFolderStore.atomicWrite(headerFile(ctx, folderId), out.toByteArray())
    }

    private data class Header(val wrappedKekIv: ByteArray, val wrappedKekCt: ByteArray)

    private fun readHeader(ctx: Context, folderId: String): Pair<Header, ByteArray> {
        val f = headerFile(ctx, folderId)
        require(f.exists()) { "vault-folder($folderId) not initialised" }
        f.inputStream().use { input ->
            val v = input.read()
            require(v == VERSION_V1.toInt()) { "expected v1 header, got $v" }
            val ivLen = readIntBE(input)
            require(ivLen in 1..MAX_IV_LEN) { "header iv length out of range: $ivLen" }
            val iv = ByteArray(ivLen); input.readFully(iv)
            val ctLen = readIntBE(input)
            require(ctLen in 1..MAX_WRAPPED_KEK_LEN) { "header ct length out of range: $ctLen" }
            val ct = ByteArray(ctLen); input.readFully(ct)
            require(input.read() == -1) { "trailing bytes in header" }
            return Header(iv, ct) to ByteArray(0)
        }
    }

    private fun intBE(n: Int): ByteArray = byteArrayOf(
        ((n ushr 24) and 0xFF).toByte(),
        ((n ushr 16) and 0xFF).toByte(),
        ((n ushr 8) and 0xFF).toByte(),
        (n and 0xFF).toByte(),
    )

    private fun readIntBE(input: InputStream): Int {
        val b = ByteArray(4); input.readFully(b)
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun InputStream.readFully(buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = read(buf, off, buf.size - off)
            require(n >= 0) { "short read" }
            off += n
        }
    }
}
