package org.matrix.teesimulator.physicalharness

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class DonorRuntimeOwnerLifecycleTest {
    @Test
    fun invalidAndUnknownProfilesPerformNoSensitiveOrServerAccess() {
        val rig = DonorRuntimeTestRig()

        assertFailsWith<DonorProfileException.InvalidProfileId> {
            rig.owner.start("../profile", Instant.now())
        }
        assertFailsWith<DonorRuntimeException.Unavailable> {
            rig.owner.start("unknown.profile", Instant.now())
        }

        assertEquals(1, rig.source.calls.get())
        assertEquals(0, rig.identityCalls.get())
        assertEquals(0, rig.processCalls.get())
        assertEquals(0, rig.callerCalls.get())
        assertEquals(0, rig.serverFactory.createCalls.get())
        assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
    }

    @Test
    fun identityOpenFailurePrecedesProcessCallerAndServerAccess() {
        val rig = DonorRuntimeTestRig()
        val cause = TestRuntimeFailure()
        rig.identityFailure = cause

        val failure =
            assertFailsWith<DonorRuntimeException.Unavailable> {
                rig.owner.start("approved.profile", Instant.now())
            }

        assertSame(cause, failure.cause)
        assertEquals(0, rig.processCalls.get())
        assertEquals(0, rig.callerCalls.get())
        assertEquals(0, rig.serverFactory.createCalls.get())
        assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
    }

    @Test
    fun processFailureCreatesNoServerAndRetriesRatherThanCachingFailure() {
        val rig = DonorRuntimeTestRig()
        val cause = TestRuntimeFailure()
        rig.processFailure = cause

        val failure =
            assertFailsWith<DonorRuntimeException.Unavailable> {
                rig.owner.start("approved.profile", Instant.now())
            }
        assertSame(cause, failure.cause)
        assertEquals(0, rig.callerCalls.get())
        assertEquals(0, rig.serverFactory.createCalls.get())

        rig.processFailure = null
        assertEquals(
            DonorRuntimeStartResult.STARTED,
            rig.owner.start("approved.profile", Instant.now()),
        )
        assertEquals(2, rig.processCalls.get())
    }

    @Test
    fun serverCreateAndStartFailuresRollBackAndPermitRetry() {
        val createRig = DonorRuntimeTestRig()
        val createCause = TestRuntimeFailure()
        createRig.serverFactory.createFailure = createCause

        val createFailure =
            assertFailsWith<DonorRuntimeException.Unavailable> {
                createRig.owner.start("approved.profile", Instant.now())
            }
        assertSame(createCause, createFailure.cause)
        assertEquals(DonorRuntimeState.STOPPED, createRig.owner.state)
        createRig.serverFactory.createFailure = null
        assertEquals(
            DonorRuntimeStartResult.STARTED,
            createRig.owner.start("approved.profile", Instant.now()),
        )
        assertEquals(1, createRig.processCalls.get())

        val startRig = DonorRuntimeTestRig()
        val startCause = TestRuntimeFailure()
        startRig.serverFactory.nextStartFailure = startCause
        val startFailure =
            assertFailsWith<DonorRuntimeException.Unavailable> {
                startRig.owner.start("approved.profile", Instant.now())
            }
        assertSame(startCause, startFailure.cause)
        assertEquals(1, startRig.serverFactory.servers.single().closeCalls.get())
        assertEquals(DonorRuntimeState.STOPPED, startRig.owner.state)

        assertEquals(
            DonorRuntimeStartResult.STARTED,
            startRig.owner.start("approved.profile", Instant.now()),
        )
        assertEquals(1, startRig.processCalls.get())
        assertEquals(2, startRig.serverFactory.createCalls.get())
    }

    @Test
    fun repeatedSameProfileStartIsIdempotentAndConflictPreservesOriginalServer() {
        val fixture = DonorProfileFixture()
        val original = fixture.profile()
        val conflicting = fixture.profile(profileId = "other.profile")
        val rig = DonorRuntimeTestRig(listOf(original, conflicting))

        assertEquals(
            DonorRuntimeStartResult.STARTED,
            rig.owner.start(original.profileId, fixture.now),
        )
        assertEquals(
            DonorRuntimeStartResult.ALREADY_RUNNING,
            rig.owner.start(original.profileId, fixture.now),
        )
        assertFailsWith<DonorRuntimeException.ConflictingProfile> {
            rig.owner.start(conflicting.profileId, fixture.now)
        }

        assertEquals(1, rig.identityCalls.get())
        assertEquals(1, rig.processCalls.get())
        assertEquals(1, rig.serverFactory.createCalls.get())
        assertEquals(0, rig.serverFactory.servers.single().closeCalls.get())
        assertEquals(DonorRuntimeState.RUNNING, rig.owner.state)
    }

    @Test
    fun stopIsIdempotentAndRestartReusesProcessButCreatesANewServer() {
        val rig = DonorRuntimeTestRig()
        rig.owner.start("approved.profile", Instant.now())

        assertEquals(DonorRuntimeStopResult.STOPPED, rig.owner.stop())
        assertEquals(DonorRuntimeStopResult.ALREADY_STOPPED, rig.owner.stop())
        assertEquals(1, rig.serverFactory.servers.single().closeCalls.get())
        assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)

        assertEquals(
            DonorRuntimeStartResult.STARTED,
            rig.owner.start("approved.profile", Instant.now()),
        )
        assertEquals(1, rig.processCalls.get())
        assertEquals(2, rig.identityCalls.get())
        assertEquals(2, rig.serverFactory.createCalls.get())
    }
}
