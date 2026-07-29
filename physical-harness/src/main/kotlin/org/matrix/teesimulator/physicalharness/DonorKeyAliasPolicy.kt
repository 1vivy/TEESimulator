package org.matrix.teesimulator.physicalharness

import java.util.UUID

internal object DonorKeyAliasPolicy {
    private const val PREFIX = "teesim_donor_key_v1_"

    fun aliasFor(keyId: UUID): String = PREFIX + keyId.toString().replace("-", "")

    fun isOwnedAlias(alias: String): Boolean = alias.startsWith(PREFIX)
}
