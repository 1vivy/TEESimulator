package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IrpcKeyBatchTest {
    @Test
    fun preservesHardwareOrderAndRedactsBlobs() {
        val batch =
            IrpcKeyBatch(
                testIrpcIdentity(),
                listOf(
                    IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(91)),
                    IrpcGeneratedKey(byteArrayOf(2), testSpki(), byteArrayOf(92)),
                ),
            )

        assertArrayEquals(byteArrayOf(1), batch.publicKeys()[0])
        assertArrayEquals(byteArrayOf(2), batch.publicKeys()[1])
        assertEquals("IrpcKeyBatch(count=2)", batch.toString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsDuplicatePublicKeys() {
        IrpcKeyBatch(
            testIrpcIdentity(),
            listOf(
                IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(2)),
                IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(3)),
            ),
        )
    }

    @Test
    fun retainedBlobIsWipedAndRemovedOnClear() {
        val wiped = mutableListOf<ByteArray>()
        val owner = BrokerKeyBlobOwner { wiped += it }
        val batch =
            IrpcKeyBatch(
                testIrpcIdentity(),
                listOf(IrpcGeneratedKey(byteArrayOf(1), testSpki(), byteArrayOf(81, 82, 83, 84))),
                owner,
            )
        batch.retain(listOf(ByteArray(32) { 7 }))

        owner.clear()

        assertTrue(owner.isEmpty())
        assertTrue(wiped.single().all { it == 0.toByte() })
        assertFalse(batch.toString().toByteArray().containsSubsequence(byteArrayOf(81, 82, 83, 84)))
    }
}

private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean =
    indices.any { start ->
        start + candidate.size <= size &&
            candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
    }
