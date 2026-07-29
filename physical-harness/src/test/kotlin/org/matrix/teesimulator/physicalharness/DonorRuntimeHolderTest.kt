package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DonorRuntimeHolderTest {
    @Test
    fun failedCreationIsNotCachedAndSuccessfulOwnerSurvivesRecreation() {
        val holder = DonorRuntimeHolder()
        val expected = FakeServiceRuntime()
        val calls = AtomicInteger()
        val factory = DonorRuntimeControlFactory {
            if (calls.getAndIncrement() == 0) throw TestServiceFailure()
            expected
        }

        assertFailsWith<TestServiceFailure> { holder.getOrCreate(factory) }
        assertSame(expected, holder.getOrCreate(factory))
        assertSame(expected, holder.getOrCreate(factory))
        assertEquals(2, calls.get())
    }

    @Test
    fun concurrentServiceInstancesReceiveExactlyOneRuntimeOwner() {
        val holder = DonorRuntimeHolder()
        val expected = FakeServiceRuntime()
        val calls = AtomicInteger()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val factory = DonorRuntimeControlFactory {
            calls.incrementAndGet()
            entered.countDown()
            release.await()
            expected
        }
        val callers = Executors.newFixedThreadPool(8)
        try {
            val results =
                List(24) { callers.submit<DonorRuntimeControl> { holder.getOrCreate(factory) } }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            release.countDown()

            assertTrue(results.map { it.get(5, TimeUnit.SECONDS) }.all { it === expected })
            assertEquals(1, calls.get())
        } finally {
            release.countDown()
            callers.shutdownNow()
            assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}
