package org.matrix.teesimulator.rkahost.evidence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class ContinuousLivenessTest {
    private val service = ServiceIdentity("keystore2", "init", 42, 100, "/system/bin/keystore2", 0)
    private val properties = mapOf("ro.build.fingerprint" to "build-A")

    @Test
    fun requires_two_fresh_samples_before_live_receipt() {
        // Given: a sentinel with only its initial observation.
        val clock = FakeClock(1_000)
        val sentinel = sentinel(clock).observe(sample(1_000, 1_000), service)

        // When: liveness is asserted.
        val failure =
            assertThrows(SentinelViolation::class.java) { sentinel.assertLive("commit-A") }

        // Then: one or truncated streams are not live.
        assertEquals(Violation.INSUFFICIENT_SAMPLES, failure.violation)
    }

    @Test
    fun accepts_exact_two_second_device_and_host_intervals_and_binds_observation_times() {
        // Given: two samples exactly two seconds apart on independent monotonic clocks.
        val clock = FakeClock(3_000)
        val sentinel =
            sentinel(clock)
                .observe(sample(1_000, 1_000), service)
                .observe(sample(3_000, 3_000), service)

        // When: a fresh assertion is made.
        val receipt = sentinel.assertLive("commit-A")

        // Then: both observation endpoints and assertion time are receipt-bound.
        assertEquals(1_000, receipt.headObservedAtMillis)
        assertEquals(3_000, receipt.tailObservedAtMillis)
        assertEquals(3_000, receipt.assertedAtMillis)
        assertFalse(receipt.sampleChainHash.isEmpty())
    }

    @Test
    fun rejects_observation_gap_even_when_device_uptime_moves_little() {
        // Given: a host observation gap that device uptime alone cannot expose.
        val clock = FakeClock(3_600_000)
        val sentinel = sentinel(clock).observe(sample(1_000, 0), service)

        // When: the next observation arrives an hour later with a one second uptime change.
        val failure =
            assertThrows(SentinelViolation::class.java) {
                sentinel.observe(sample(2_000, 3_600_000), service)
            }

        // Then: continuity fails on trusted host monotonic time.
        assertEquals(Violation.OBSERVATION_GAP, failure.violation)
    }

    @Test
    fun rejects_frozen_backward_and_divergent_clocks() {
        // Given: independently controlled device and host clocks.
        val frozen = sentinel(FakeClock(1_000)).observe(sample(1_000, 1_000), service)
        val backward = sentinel(FakeClock(1_000)).observe(sample(1_000, 1_000), service)
        val divergent = sentinel(FakeClock(2_000)).observe(sample(1_000, 1_000), service)

        // When/Then: duplicate, backward, and forged elapsed values cannot continue a stream.
        assertEquals(
            Violation.OBSERVATION_NOT_INCREASING,
            assertThrows(SentinelViolation::class.java) {
                    frozen.observe(sample(2_000, 1_000), service)
                }
                .violation,
        )
        assertEquals(
            Violation.OBSERVATION_NOT_INCREASING,
            assertThrows(SentinelViolation::class.java) {
                    backward.observe(sample(2_000, 999), service)
                }
                .violation,
        )
        assertEquals(
            Violation.CLOCK_DRIFT,
            assertThrows(SentinelViolation::class.java) {
                    divergent.observe(sample(3_000, 2_000), service)
                }
                .violation,
        )
    }

    @Test
    fun rejects_stale_tail_at_assertion_time() {
        // Given: a formerly valid two-sample stream.
        val clock = FakeClock(1_000)
        val sentinel =
            sentinel(clock).observe(sample(0, 0), service).observe(sample(1_000, 1_000), service)
        clock.now = 3_001

        // When: the old tail is asserted after its freshness budget.
        val failure =
            assertThrows(SentinelViolation::class.java) { sentinel.assertLive("commit-A") }

        // Then: an old valid stream cannot be replayed as live.
        assertEquals(Violation.STALE_ASSERTION, failure.violation)
    }

    @Test
    fun accepts_bounded_scheduling_drift_and_rejects_the_next_millisecond() {
        // Given: the fixed 250 millisecond scheduling tolerance around a one second observation.
        val accepted = sentinel(FakeClock(1_750)).observe(sample(0, 0), service)
        val rejected = sentinel(FakeClock(1_749)).observe(sample(0, 0), service)

        // When/Then: the inclusive boundary remains narrow and deterministic.
        accepted.observe(sample(1_250, 1_000), service).assertLive("commit-A")
        assertEquals(
            Violation.CLOCK_DRIFT,
            assertThrows(SentinelViolation::class.java) {
                    rejected.observe(sample(1_251, 1_000), service)
                }
                .violation,
        )
    }

    private fun sentinel(clock: FakeClock) =
        NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A", clock)

    private fun sample(uptime: Long, observedAt: Long) =
        SentinelSample("boot-A", uptime, properties, emptySet(), observedAt)

    private class FakeClock(var now: Long) : MonotonicClock {
        override fun nowMillis(): Long = now
    }
}
