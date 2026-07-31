package org.matrix.TEESimulator.rka.broker

import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class IrpcCertificateRequestTest {
    @Test
    fun rawHalCsrIsHashedAfterExactOrderedV2Call() {
        val endpoint =
            FakeIrpcEndpoint(
                generatedSequence =
                    ArrayDeque(
                        listOf(
                            IrpcGeneratedKey(byteArrayOf(1), distinctTestSpki(1), byteArrayOf(11)),
                            IrpcGeneratedKey(byteArrayOf(2), distinctTestSpki(2), byteArrayOf(12)),
                        )
                    ),
                certificateRequest = byteArrayOf(0x98.toByte(), 0x01, 0x80.toByte()),
            )
        val client = IrpcClient(FakeResolver(irpc = endpoint), DirectCallRunner)
        val batch =
            client
                .generateKeyBatch(
                    RkpKeyCount.parse(2).success(),
                    BrokerDeadline.at(5_000),
                    BrokerCancellation.active(),
                )
                .success()
        val challenge = ByteArray(16) { (it + 20).toByte() }

        val request =
            client
                .generateCertificateRequest(
                    batch,
                    AttestationChallenge.parse(challenge).success(),
                    BrokerDeadline.at(5_000),
                    BrokerCancellation.active(),
                )
                .success()

        assertEquals(1, endpoint.certificateRequests.size)
        assertArrayEquals(byteArrayOf(1), endpoint.certificateRequests.single().first[0])
        assertArrayEquals(byteArrayOf(2), endpoint.certificateRequests.single().first[1])
        assertArrayEquals(challenge, endpoint.certificateRequests.single().second)
        val rawCsr = byteArrayOf(0x98.toByte(), 0x01, 0x80.toByte())
        assertArrayEquals(rawCsr, request.copyBytes())
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(rawCsr), request.halCsrHash())
    }

    private fun <T> BrokerOutcome<T>.success(): T = (this as BrokerOutcome.Success).value
}
