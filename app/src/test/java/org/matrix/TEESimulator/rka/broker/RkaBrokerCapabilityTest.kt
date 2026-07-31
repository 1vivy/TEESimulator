package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RkaBrokerCapabilityTest {
    @Test
    fun resolvesOnlyDefaultTeeV3Capability() {
        val resolver = FakeResolver()
        val broker = BrokerCapability.forResolver(resolver, DirectCallRunner)

        val outcome =
            broker.inspect(
                BrokerCaller.external(uid = 10_042, daemonUid = 0),
                BrokerDeadline.at(5_000),
                BrokerCancellation.active(),
            )

        val report = outcome.success()
        assertEquals(IrpcClient.DEFAULT_TEE_SERVICE, resolver.irpcNames.single())
        assertEquals(KeyMintClient.DEFAULT_TEE_SERVICE, resolver.keyMintNames.single())
        assertEquals(3, report.irpc.version)
        assertEquals(20, report.irpc.maxCsrKeys)
        assertEquals(BrokerSecurityLevel.TEE, report.irpc.securityLevel)
        assertEquals(BrokerSecurityLevel.TEE, report.keyMint.securityLevel)
    }

    @Test
    fun rejectsEveryNonV3IrpcVersion() {
        listOf(1, 2, 4).forEach { version ->
            val resolver = FakeResolver(irpc = FakeIrpcEndpoint(version = version))
            val outcome =
                BrokerCapability.forResolver(resolver, DirectCallRunner)
                    .inspect(
                        BrokerCaller.external(uid = 10_042, daemonUid = 0),
                        BrokerDeadline.at(5_000),
                        BrokerCancellation.active(),
                    )

            assertEquals(
                BrokerError.UnsupportedIrpcVersion(version),
                (outcome as BrokerOutcome.Failure).error,
            )
        }
    }

    @Test
    fun challengeEdgesAreParsedOnceAndDefensivelyOwned() {
        assertTrue(AttestationChallenge.parse(ByteArray(15)) is BrokerOutcome.Failure)
        val sixteenSource = ByteArray(16) { it.toByte() }
        val sixteen = AttestationChallenge.parse(sixteenSource).success()
        assertTrue(AttestationChallenge.parse(ByteArray(64)) is BrokerOutcome.Success)
        assertTrue(AttestationChallenge.parse(ByteArray(65)) is BrokerOutcome.Failure)

        sixteenSource.fill(99)
        val firstCopy = sixteen.copyBytes()
        firstCopy.fill(88)
        assertArrayEquals(ByteArray(16) { it.toByte() }, sixteen.copyBytes())
        assertEquals("AttestationChallenge(length=16)", sixteen.toString())
    }

    @Test
    fun keyCountEdgesAreBounded() {
        assertTrue(RkpKeyCount.parse(0) is BrokerOutcome.Failure)
        assertEquals(1, RkpKeyCount.parse(1).success().value)
        assertEquals(20, RkpKeyCount.parse(20).success().value)
        assertTrue(RkpKeyCount.parse(21) is BrokerOutcome.Failure)
    }

    @Test
    fun generatedPublicMaterialIsDefensivelyOwnedAndOpaqueBlobIsRedacted() {
        val publicKey = byteArrayOf(1, 2, 3)
        val keyBlob = byteArrayOf(9, 8, 7)
        val resolver =
            FakeResolver(
                irpc =
                    FakeIrpcEndpoint(generated = IrpcGeneratedKey(publicKey, testSpki(), keyBlob))
            )
        val client = IrpcClient(resolver, DirectCallRunner)

        val batch =
            client
                .generateKeyBatch(
                    RkpKeyCount.parse(1).success(),
                    BrokerDeadline.at(5_000),
                    BrokerCancellation.active(),
                )
                .success()

        publicKey.fill(0)
        keyBlob.fill(0)
        val exported = batch.publicKeys()
        assertArrayEquals(byteArrayOf(1, 2, 3), exported.single())
        exported.single().fill(4)
        assertArrayEquals(byteArrayOf(1, 2, 3), batch.publicKeys().single())
        assertFalse(batch.toString().contains("9"))
        assertEquals("IrpcKeyBatch(count=1)", batch.toString())
    }

    @Test
    fun selfCallsBypassBeforeAnyServiceLookup() {
        val resolver = FakeResolver()
        val outcome =
            BrokerCapability.forResolver(resolver, DirectCallRunner)
                .inspect(
                    BrokerCaller.external(uid = 0, daemonUid = 0),
                    BrokerDeadline.at(5_000),
                    BrokerCancellation.active(),
                )

        assertTrue(outcome === BrokerOutcome.SelfCallBypass)
        assertTrue(resolver.irpcNames.isEmpty())
        assertTrue(resolver.keyMintNames.isEmpty())
    }

    private fun <T> BrokerOutcome<T>.success(): T = (this as BrokerOutcome.Success).value
}
