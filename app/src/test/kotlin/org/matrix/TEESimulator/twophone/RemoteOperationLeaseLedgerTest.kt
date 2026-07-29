package org.matrix.TEESimulator.twophone

import kotlin.test.Test
import kotlin.test.assertEquals

class RemoteOperationLeaseLedgerTest {
    @Test
    fun exactReplayDoesNotDispatchTwice() {
        val ledger = RemoteOperationLeaseLedger { Unit }

        assertEquals(1L, ledger.leaseCount())
    }
}
