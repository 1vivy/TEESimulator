package org.matrix.TEESimulator.rka.journal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.DirectCallRunner
import org.matrix.TEESimulator.rka.broker.FakeIrpcEndpoint
import org.matrix.TEESimulator.rka.broker.FakeResolver
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.RkpKeyCount

class RkpJournalRecoveryTest {
    @Test
    fun generatingIsQuarantined() {
        val store = FailSecondWriteStore()
        val calls = intArrayOf(0)
        val client =
            IrpcClient(
                FakeResolver(irpc = FakeIrpcEndpoint(onGenerate = { calls[0] += 1 })),
                DirectCallRunner,
            )
        val generator = DurableIrpcKeyBatchGenerator(client, RkpJournal(store))

        assertThrows(IllegalStateException::class.java) {
            generator.generate(
                (RkpKeyCount.parse(1) as org.matrix.TEESimulator.rka.broker.BrokerOutcome.Success)
                    .value,
                BrokerDeadline.at(5_000),
                BrokerCancellation.active(),
            )
        }
        assertEquals(RkpJournalState.QUARANTINED, RkpJournal(store).recover()?.state)
        assertEquals(1, calls[0])
    }
}

private class FailSecondWriteStore : RkpJournalStore {
    private var value: ByteArray? = null
    private var writes = 0

    override fun read(): ByteArray? = value?.copyOf()

    override fun replace(value: ByteArray) {
        writes += 1
        if (writes == 2) throw IllegalStateException("injected")
        this.value = value.copyOf()
    }
}
