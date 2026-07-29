package org.matrix.TEESimulator.twophone

import kotlin.test.Test
import kotlin.test.assertEquals

class TargetTlsClientContractTest {
    @Test
    fun targetTlsIdentityUsesTheDedicatedVersionedAlias() {
        assertEquals(
            "teesim_target_tls_client_v1",
            AndroidKeyStoreTargetTlsClientIdentity.KEY_ALIAS,
        )
    }
}
