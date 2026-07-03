package com.understory.vaultfolder

import com.understory.security.BaseCapabilityProvider

/**
 * vault-folder's capability beacon. Consumers translate
 * `(com.understory.vaultfolder, version=1)` into [SuiteCapability.FILE_VAULT]
 * via their KNOWN_PEERS table.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
