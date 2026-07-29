package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DonorStateSecurityBootstrapTest {
    @Test
    fun existingStateWithValidMacOpensOnlyWithoutReadingState() {
        val rig = BootstrapTestRig(statePresent = true, macPresent = true)

        val result = rig.bootstrap.bootstrap()

        assertSame(rig.existingMac, result)
        assertEquals(1, rig.macStore.openCalls)
        rig.assertNoCreateDeleteWriteOrRead()
    }

    @Test
    fun existingStateWithoutMacFailsClosedWithoutReadingOrReplacingAnything() {
        val rig = BootstrapTestRig(statePresent = true, macPresent = false)

        assertFailsWith<DonorStateSecurityBootstrapException.UnverifiableState> {
            rig.bootstrap.bootstrap()
        }

        assertEquals(0, rig.macStore.openCalls)
        rig.assertNoCreateDeleteWriteOrRead()
    }

    @Test
    fun existingStateWithInvalidMacFailsClosedWithoutCreatingOrDeleting() {
        val rig = BootstrapTestRig(statePresent = true, macPresent = true)
        val invalidMac = TestBootstrapFailure()
        rig.macStore.openFailure = invalidMac

        val failure =
            assertFailsWith<DonorStateSecurityBootstrapException.UnverifiableState> {
                rig.bootstrap.bootstrap()
            }

        assertSame(invalidMac, failure.cause)
        assertEquals(1, rig.macStore.openCalls)
        rig.assertNoCreateDeleteWriteOrRead()
    }

    @Test
    fun missingStateWithDonorAliasesFailsClosedRegardlessOfMacPresence() {
        listOf(false, true).forEach { macPresent ->
            val rig =
                BootstrapTestRig(
                    statePresent = false,
                    macPresent = macPresent,
                    donorAliasesPresent = true,
                )

            assertFailsWith<DonorStateSecurityBootstrapException.InconsistentArtifacts> {
                rig.bootstrap.bootstrap()
            }

            assertEquals(0, rig.macStore.openCalls)
            rig.assertNoCreateDeleteWriteOrRead()
        }
    }

    @Test
    fun missingStateWithPreExistingMacFailsClosedWithoutOpeningOrReplacingIt() {
        val rig = BootstrapTestRig(statePresent = false, macPresent = true)

        assertFailsWith<DonorStateSecurityBootstrapException.InconsistentArtifacts> {
            rig.bootstrap.bootstrap()
        }

        assertEquals(0, rig.macStore.openCalls)
        rig.assertNoCreateDeleteWriteOrRead()
    }

    @Test
    fun trueFirstBootCreatesOneMacAndWritesAuthenticatedEmptyRevisionZero() {
        val rig = BootstrapTestRig()

        val result = rig.bootstrap.bootstrap()

        assertSame(rig.createdMac, result)
        assertEquals(2, rig.stateStore.artifactChecks)
        assertEquals(2, rig.aliasSource.calls)
        assertEquals(2, rig.macStore.existenceChecks)
        assertEquals(1, rig.macStore.createCalls)
        assertEquals(1, rig.stateStore.writeCalls)
        assertEquals(0, rig.stateStore.readCalls)
        val snapshot = DonorStateCodec(result).decode(rig.stateStore.bytes!!)
        assertEquals(0uL, snapshot.revision)
        assertTrue(snapshot.keys.isEmpty())
        assertTrue(snapshot.mutations.isEmpty())
    }

    @Test
    fun preCreateRecheckReclassifiesEveryRacingArtifactWithoutCreating() {
        val stateWon = BootstrapTestRig(macPresent = true)
        stateWon.stateStore.artifactResults.addAll(listOf(false, true))
        stateWon.macStore.existenceResults.addAll(listOf(false, true))
        assertSame(stateWon.existingMac, stateWon.bootstrap.bootstrap())
        assertEquals(1, stateWon.macStore.openCalls)
        stateWon.assertNoCreateDeleteWriteOrRead()

        val donorWon = BootstrapTestRig()
        donorWon.stateStore.artifactResults.addAll(listOf(false, false))
        donorWon.aliasSource.results.addAll(listOf(false, true))
        assertFailsWith<DonorStateSecurityBootstrapException.InconsistentArtifacts> {
            donorWon.bootstrap.bootstrap()
        }
        donorWon.assertNoCreateDeleteWriteOrRead()

        val macWon = BootstrapTestRig()
        macWon.stateStore.artifactResults.addAll(listOf(false, false))
        macWon.aliasSource.results.addAll(listOf(false, false))
        macWon.macStore.existenceResults.addAll(listOf(false, true))
        assertFailsWith<DonorStateSecurityBootstrapException.InconsistentArtifacts> {
            macWon.bootstrap.bootstrap()
        }
        macWon.assertNoCreateDeleteWriteOrRead()
    }

    @Test
    fun failureBeforeStateWriteRollsBackOnlyTheMacCreatedByThisCall() {
        val rig = BootstrapTestRig()
        val writeFailure = TestBootstrapFailure()
        rig.stateStore.writeFailure = writeFailure

        val failure = assertFailsWith<TestBootstrapFailure> { rig.bootstrap.bootstrap() }

        assertSame(writeFailure, failure)
        assertEquals(1, rig.macStore.createCalls)
        assertEquals(1, rig.macStore.deleteCalls)
        assertSame(rig.createdMac, rig.macStore.deletedMac)
        assertEquals(0, rig.stateStore.readCalls)
    }

    @Test
    fun reportedFailureAfterCommitRetainsMacForAConservativeRetry() {
        val rig = BootstrapTestRig()
        val writeFailure = TestBootstrapFailure()
        rig.stateStore.commitBeforeWriteFailure = true
        rig.stateStore.writeFailure = writeFailure

        assertSame(
            writeFailure,
            assertFailsWith<TestBootstrapFailure> { rig.bootstrap.bootstrap() },
        )

        assertEquals(0, rig.macStore.deleteCalls)
        assertSame(rig.createdMac, rig.bootstrap.bootstrap())
        assertEquals(1, rig.macStore.openCalls)
        assertEquals(1, rig.macStore.createCalls)
        assertEquals(1, rig.stateStore.writeCalls)
        assertEquals(0, rig.stateStore.readCalls)
        DonorStateCodec(rig.createdMac).decode(rig.stateStore.bytes!!)
    }

    @Test
    fun donorAliasAppearingDuringFailureCleanupRetainsCreatedMac() {
        val rig = BootstrapTestRig()
        val writeFailure = TestBootstrapFailure()
        rig.stateStore.writeFailure = writeFailure
        rig.aliasSource.results.addAll(listOf(false, false, true))

        assertSame(
            writeFailure,
            assertFailsWith<TestBootstrapFailure> { rig.bootstrap.bootstrap() },
        )

        assertEquals(0, rig.macStore.deleteCalls)
        assertEquals(0, rig.stateStore.readCalls)
    }

    @Test
    fun rollbackDeleteFailureIsSuppressedUnderTheOriginalWriteFailure() {
        val rig = BootstrapTestRig()
        val writeFailure = TestBootstrapFailure()
        val rollbackFailure = TestRollbackFailure()
        rig.stateStore.writeFailure = writeFailure
        rig.macStore.deleteFailure = rollbackFailure

        val failure = assertFailsWith<TestBootstrapFailure> { rig.bootstrap.bootstrap() }

        assertSame(writeFailure, failure)
        assertEquals(1, failure.suppressed.size)
        assertSame(rollbackFailure, failure.suppressed.single())
        assertEquals(0, rig.stateStore.readCalls)
    }

    @Test
    fun failedCleanupProbeRetainsMacAndIsSuppressedConservatively() {
        val rig = BootstrapTestRig()
        val writeFailure = TestBootstrapFailure()
        val probeFailure = TestProbeFailure()
        rig.stateStore.writeFailure = writeFailure
        rig.stateStore.artifactFailureAtCheck = 3
        rig.stateStore.artifactFailure = probeFailure

        val failure = assertFailsWith<TestBootstrapFailure> { rig.bootstrap.bootstrap() }

        assertSame(writeFailure, failure)
        assertSame(probeFailure, failure.suppressed.single())
        assertEquals(0, rig.macStore.deleteCalls)
    }

    @Test
    fun concurrentCallersCreateAndWriteOnceThenAllReceiveTheUsableMac() {
        val rig = BootstrapTestRig()
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)
        try {
            val futures =
                List(24) {
                    executor.submit<HandleMac> {
                        start.await()
                        rig.bootstrap.bootstrap()
                    }
                }
            start.countDown()

            val results = futures.map { it.get(5, TimeUnit.SECONDS) }

            assertTrue(results.all { it === rig.createdMac })
            assertEquals(1, rig.macStore.createCalls)
            assertEquals(1, rig.stateStore.writeCalls)
            assertEquals(23, rig.macStore.openCalls)
            assertEquals(0, rig.macStore.deleteCalls)
            assertEquals(0, rig.stateStore.readCalls)
            DonorStateCodec(results.first()).decode(rig.stateStore.bytes!!)
        } finally {
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}

private class BootstrapTestRig(
    statePresent: Boolean = false,
    macPresent: Boolean = false,
    donorAliasesPresent: Boolean = false,
) {
    val existingMac = TestHandleMac(testBytes(32, 61))
    val createdMac = TestHandleMac(testBytes(32, 62))
    val stateStore = FakeBootstrapStateStore(statePresent)
    val macStore = FakeDonorStateMacStore(macPresent, existingMac, createdMac)
    val aliasSource = FakeDonorOwnedAliasSource(donorAliasesPresent)
    val bootstrap = DonorStateSecurityBootstrap(stateStore, stateStore, macStore, aliasSource)

    fun assertNoCreateDeleteWriteOrRead() {
        assertEquals(0, macStore.createCalls)
        assertEquals(0, macStore.deleteCalls)
        assertEquals(0, stateStore.writeCalls)
        assertEquals(0, stateStore.readCalls)
    }
}

private class FakeBootstrapStateStore(@Volatile var artifactsPresent: Boolean) :
    DonorStateArtifactProbe, DonorStateBlobStore {
    val artifactResults = ArrayDeque<Boolean>()
    var artifactChecks = 0
    var readCalls = 0
    var writeCalls = 0
    var bytes: ByteArray? = null
    var writeFailure: RuntimeException? = null
    var commitBeforeWriteFailure = false
    var artifactFailureAtCheck: Int? = null
    var artifactFailure: RuntimeException? = null

    override fun hasArtifacts(): Boolean {
        artifactChecks += 1
        if (artifactChecks == artifactFailureAtCheck) throw artifactFailure!!
        return artifactResults.removeFirstOrNull() ?: artifactsPresent
    }

    override fun read(): ByteArray? {
        readCalls += 1
        throw AssertionError("bootstrap must not read state")
    }

    override fun write(blob: ByteArray) {
        writeCalls += 1
        val failure = writeFailure
        if (failure != null && !commitBeforeWriteFailure) throw failure
        bytes = blob.copyOf()
        artifactsPresent = true
        if (failure != null) throw failure
    }
}

private class FakeDonorStateMacStore(
    @Volatile private var present: Boolean,
    private val existingMac: HandleMac,
    private val createdMac: HandleMac,
) : DonorStateMacStore {
    val existenceResults = ArrayDeque<Boolean>()
    var existenceChecks = 0
    var openCalls = 0
    var createCalls = 0
    var deleteCalls = 0
    var deletedMac: HandleMac? = null
    var openFailure: RuntimeException? = null
    var deleteFailure: RuntimeException? = null

    override fun exists(): Boolean {
        existenceChecks += 1
        return existenceResults.removeFirstOrNull() ?: present
    }

    override fun openExisting(): HandleMac {
        openCalls += 1
        openFailure?.let { throw it }
        check(present)
        return if (createCalls == 0) existingMac else createdMac
    }

    override fun createNew(): HandleMac {
        createCalls += 1
        check(!present)
        present = true
        return createdMac
    }

    override fun deleteCreated(mac: HandleMac) {
        deleteCalls += 1
        deletedMac = mac
        deleteFailure?.let { throw it }
        check(mac === createdMac)
        present = false
    }
}

private class FakeDonorOwnedAliasSource(private val present: Boolean) : DonorOwnedAliasSource {
    val results = ArrayDeque<Boolean>()
    var calls = 0

    override fun hasOwnedAliases(): Boolean {
        calls += 1
        return results.removeFirstOrNull() ?: present
    }
}

private class TestBootstrapFailure : RuntimeException()

private class TestRollbackFailure : RuntimeException()

private class TestProbeFailure : RuntimeException()
