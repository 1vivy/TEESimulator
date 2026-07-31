package org.matrix.TEESimulator.rka.journal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.DirectCallRunner
import org.matrix.TEESimulator.rka.broker.FakeIrpcEndpoint
import org.matrix.TEESimulator.rka.broker.FakeResolver
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.RkpKeyCount
import org.matrix.TEESimulator.rka.broker.testSpki

class RkpJournalIntegrityTest {
    @Test
    fun rejectsForgedDeterministicHandle() {
        val record = recorded()
        val encoded = RkpJournalCodec.encode(record)
        val handleOffset = encoded.indexOfSubsequence(record.entries.single().handle.copyBytes())
        encoded[handleOffset] = (encoded[handleOffset].toInt() xor 1).toByte()

        assertThrows(IllegalArgumentException::class.java) { RkpJournalCodec.decode(encoded) }
    }

    @Test
    fun rejectsSpkiAndResolvedIdentityMutation() {
        val recorded = recorded()
        val encoded = RkpJournalCodec.encode(recorded)
        val spki = recorded.entries.single().copySpkiDer()
        val spkiOffset = encoded.indexOfSubsequence(spki)
        encoded[spkiOffset] = (encoded[spkiOffset].toInt() xor 1).toByte()
        assertThrows(IllegalArgumentException::class.java) { RkpJournalCodec.decode(encoded) }

        val identityEncoded = RkpJournalCodec.encode(recorded)
        val identityOffset = identityEncoded.indexOfSubsequence("fake-irpc".toByteArray())
        identityEncoded[identityOffset] = (identityEncoded[identityOffset].toInt() xor 1).toByte()
        assertThrows(IllegalArgumentException::class.java) {
            RkpJournalCodec.decode(identityEncoded)
        }
    }

    @Test
    fun identitySwapIsRejectedBeforeHardwareGeneration() {
        val calls = intArrayOf(0)
        val endpoints =
            ArrayDeque(
                listOf(
                    FakeIrpcEndpoint(),
                    FakeIrpcEndpoint(componentName = "swapped", onGenerate = { calls[0] += 1 }),
                )
            )
        val client =
            IrpcClient(FakeResolver(irpcProvider = { endpoints.removeFirst() }), DirectCallRunner)
        val store = IntegrityJournalStore()

        val outcome =
            DurableIrpcKeyBatchGenerator(client, RkpJournal(store))
                .generate(count(1), BrokerDeadline.at(5_000), BrokerCancellation.active())

        assertTrue(outcome is BrokerOutcome.Failure)
        assertEquals(0, calls[0])
        assertEquals(RkpJournalState.QUARANTINED, RkpJournalCodec.decode(store.read()!!).state)
    }

    private fun recorded(): RkpJournalRecord {
        val journal = RkpJournal(IntegrityJournalStore())
        val generating = journal.begin(count(1), identity())
        return journal.record(
            generating,
            journal.deriveEntries(generating, listOf(byteArrayOf(1) to testSpki())),
        ) {}
    }

    private fun count(value: Int): RkpKeyCount =
        (RkpKeyCount.parse(value) as BrokerOutcome.Success).value

    private fun identity(): RkpIrpcIdentity =
        RkpIrpcIdentity(
            IrpcClient.IRPC_DESCRIPTOR,
            IrpcClient.DEFAULT_TEE_SERVICE,
            "TEE",
            "fake-irpc",
            IrpcClient.REQUIRED_VERSION,
        )
}

private class IntegrityJournalStore : RkpJournalStore {
    private var value: ByteArray? = null

    override fun read(): ByteArray? = value?.copyOf()

    override fun replace(value: ByteArray) {
        this.value = value.copyOf()
    }
}

private fun ByteArray.indexOfSubsequence(candidate: ByteArray): Int =
    indices.first { start ->
        start + candidate.size <= size &&
            candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
    }
