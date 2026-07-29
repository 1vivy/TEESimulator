package org.matrix.teesimulator.physicalharness

import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DonorRuntimeOwnerConcurrencyTest {
    @Test
    fun concurrentSameProfileStartsCreateAndStartExactlyOnce() {
        val rig = DonorRuntimeTestRig()
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)
        try {
            val futures =
                List(24) {
                    executor.submit<DonorRuntimeStartResult> {
                        start.await()
                        rig.owner.start("approved.profile", Instant.now())
                    }
                }
            start.countDown()

            val results = futures.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it == DonorRuntimeStartResult.STARTED })
            assertEquals(23, results.count { it == DonorRuntimeStartResult.ALREADY_RUNNING })
            assertEquals(1, rig.identityCalls.get())
            assertEquals(1, rig.processCalls.get())
            assertEquals(1, rig.serverFactory.createCalls.get())
            assertEquals(1, rig.serverFactory.servers.single().startCalls.get())
        } finally {
            rig.owner.stop()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun conflictingStartWaitsForInFlightStartThenRejectsWithoutClosingIt() {
        val fixture = DonorProfileFixture()
        val original = fixture.profile()
        val conflicting = fixture.profile(profileId = "other.profile")
        val rig = DonorRuntimeTestRig(listOf(original, conflicting))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        rig.serverFactory.startEntered = entered
        rig.serverFactory.releaseStart = release
        val executor = Executors.newFixedThreadPool(2)
        try {
            val first =
                executor.submit<DonorRuntimeStartResult> {
                    rig.owner.start(original.profileId, fixture.now)
                }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertEquals(DonorRuntimeState.STARTING, rig.owner.state)
            val second =
                executor.submit<DonorRuntimeException.ConflictingProfile> {
                    assertFailsWith { rig.owner.start(conflicting.profileId, fixture.now) }
                }
            assertTrue(!second.isDone)
            release.countDown()

            assertEquals(DonorRuntimeStartResult.STARTED, first.get(5, TimeUnit.SECONDS))
            second.get(5, TimeUnit.SECONDS)
            assertEquals(0, rig.serverFactory.servers.single().closeCalls.get())
            assertEquals(DonorRuntimeState.RUNNING, rig.owner.state)
        } finally {
            release.countDown()
            rig.owner.stop()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun stopWaitsForInFlightStartAndThenClosesTheStartedServer() {
        val rig = DonorRuntimeTestRig()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        rig.serverFactory.startEntered = entered
        rig.serverFactory.releaseStart = release
        val executor = Executors.newFixedThreadPool(2)
        try {
            val start =
                executor.submit<DonorRuntimeStartResult> {
                    rig.owner.start("approved.profile", Instant.now())
                }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val stop = executor.submit<DonorRuntimeStopResult> { rig.owner.stop() }
            assertTrue(!stop.isDone)
            release.countDown()

            assertEquals(DonorRuntimeStartResult.STARTED, start.get(5, TimeUnit.SECONDS))
            assertEquals(DonorRuntimeStopResult.STOPPED, stop.get(5, TimeUnit.SECONDS))
            assertEquals(1, rig.serverFactory.servers.single().closeCalls.get())
            assertEquals(DonorRuntimeState.STOPPED, rig.owner.state)
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}
