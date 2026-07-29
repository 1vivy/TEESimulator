package org.matrix.teesimulator.physicalharness

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DonorProcessHolderTest {
    @Test
    fun failedCreationIsNotCachedAndTheSuccessfulRetryIsRetained() {
        val holder = DonorProcessHolder<TestDonorProcess>()
        val calls = AtomicInteger()
        val expected = TestDonorProcess()
        val factory =
            PhysicalDonorProcessFactory<TestDonorProcess> {
                if (calls.getAndIncrement() == 0) throw TestRuntimeFailure()
                expected
            }

        kotlin.test.assertFailsWith<TestRuntimeFailure> { holder.getOrCreate(factory) }
        assertSame(expected, holder.getOrCreate(factory))
        assertSame(expected, holder.getOrCreate(factory))
        assertEquals(2, calls.get())
    }

    @Test
    fun concurrentCallersShareExactlyOneSuccessfulProcess() {
        val holder = DonorProcessHolder<TestDonorProcess>()
        val calls = AtomicInteger()
        val expected = TestDonorProcess()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val factory =
            PhysicalDonorProcessFactory<TestDonorProcess> {
                calls.incrementAndGet()
                entered.countDown()
                release.await()
                expected
            }
        val executor = Executors.newFixedThreadPool(8)
        try {
            val futures =
                List(24) { executor.submit<TestDonorProcess> { holder.getOrCreate(factory) } }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            release.countDown()

            assertTrue(futures.map { it.get(5, TimeUnit.SECONDS) }.all { it === expected })
            assertEquals(1, calls.get())
        } finally {
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}

internal class TestDonorProcess

internal class TestRuntimeFailure : RuntimeException()
