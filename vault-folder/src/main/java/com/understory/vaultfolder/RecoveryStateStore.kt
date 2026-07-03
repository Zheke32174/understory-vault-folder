package com.understory.vaultfolder

import android.content.Context
import com.understory.security.VaultRecovery
import org.json.JSONObject
import android.util.Base64
import java.io.File

/**
 * Persists the app's non-secret [VaultRecovery.RecoveryState] (§4.3). vault-
 * folder holds no SharedPreferences, so this writes a tiny cleartext
 * `recovery_state.bin` under the app's filesDir — the fields (an Argon2id
 * verifier + salt + last-export bookkeeping) are one-way and useless to an
 * attacker without the recovery key, so cleartext-at-rest is safe (design §3.3
 * KDoc on [VaultRecovery.RecoveryState]).
 *
 * Presence of this file also signals "the user enrolled a recovery key at
 * setup" — the Setup escrow step writes it, the honest skip path does not.
 */
object RecoveryStateStore {

    private const val FILE = "recovery_state.bin"

    private fun file(ctx: Context): File = File(ctx.filesDir, FILE)

    fun exists(ctx: Context): Boolean = file(ctx).exists()

    fun save(ctx: Context, state: VaultRecovery.RecoveryState) {
        val o = JSONObject().apply {
            put("verifier", Base64.encodeToString(state.verifier, Base64.NO_WRAP))
            put("verifierSalt", Base64.encodeToString(state.verifierSalt, Base64.NO_WRAP))
            put("lastExportMs", state.lastExportMs)
            put("lastExportItemCount", state.lastExportItemCount)
        }
        VaultFolderStore.atomicWrite(file(ctx), o.toString().toByteArray(Charsets.UTF_8))
    }

    fun load(ctx: Context): VaultRecovery.RecoveryState? {
        val f = file(ctx)
        if (!f.exists()) return null
        return runCatching {
            val o = JSONObject(f.readText(Charsets.UTF_8))
            VaultRecovery.RecoveryState(
                verifier = Base64.decode(o.getString("verifier"), Base64.NO_WRAP),
                verifierSalt = Base64.decode(o.getString("verifierSalt"), Base64.NO_WRAP),
                lastExportMs = o.optLong("lastExportMs", 0L),
                lastExportItemCount = o.optInt("lastExportItemCount", 0),
            )
        }.getOrNull()
    }

    fun clear(ctx: Context) {
        runCatching { file(ctx).delete() }
    }
}
