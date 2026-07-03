package com.understory.vaultfolder

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

/**
 * The single canonical BiometricPrompt driver for vault-folder (§6.1 / A11.1,
 * A11.2). Replaces the two divergent copies that existed in MainActivity
 * (main-executor, full cancel set — correct) and FoldersScreen (background
 * executor, missing ERROR_CANCELED — buggy). One shim, one behavior:
 *
 *  - callbacks run on the MAIN executor, so onSuccess/onError/onCancel may touch
 *    Compose state and the store singleton directly (no cross-thread hop);
 *  - the cancel set includes ERROR_CANCELED (system-initiated cancel) alongside
 *    ERROR_USER_CANCELED / ERROR_NEGATIVE_BUTTON, so a system cancel renders as a
 *    neutral "cancelled" line, not a red "Auth failed".
 */
internal fun promptDeviceAuth(
    activity: FragmentActivity,
    title: String,
    subtitle: String,
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
            if (errorCode in CANCEL_CODES) onCancel() else onError(errString.toString())
        }
    }
    val prompt = BiometricPrompt(activity, executor, callback)
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

private val CANCEL_CODES = setOf(
    BiometricPrompt.ERROR_USER_CANCELED,
    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
    BiometricPrompt.ERROR_CANCELED,
)
