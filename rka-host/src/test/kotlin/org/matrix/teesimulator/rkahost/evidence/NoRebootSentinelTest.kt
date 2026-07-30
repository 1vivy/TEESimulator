package org.matrix.teesimulator.rkahost.evidence

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class NoRebootSentinelTest {
    private val service = ServiceIdentity("keystore2", "init", 42, 100, "/system/bin/keystore2", 0)
    private val properties =
        mapOf("ro.build.fingerprint" to "build-A", "ro.build.version.release" to "16")

    @Test
    fun stable_stream_is_valid() {
        // Given: serial-redacted, contiguous donor samples with one exact service identity.
        val sentinel = NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")

        // When: a synthetic stream stays on the same boot, properties, and service.
        val receipt =
            sentinel
                .observe(sample(0), service)
                .observe(sample(2_000), service)
                .assertLive("commit-A")

        // Then: the receipt binds only the serial hash and the two second edge is valid.
        assertEquals(2, receipt.sampleCount)
        assertFalse(receipt.canonical().contains("serial-A"))
        assertEquals(2_000, receipt.tailUptimeMillis)
    }

    @Test
    fun rejects_boot_drift() {
        // Given: a started sentinel.
        val sentinel =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                .observe(sample(0), service)

        // When: the boot identifier changes.
        val failure =
            assertThrows(SentinelViolation::class.java) {
                sentinel.observe(sample(1_000, boot = "boot-B"), service)
            }

        // Then: it hard-fails.
        assertEquals(Violation.BOOT_ID_DRIFT, failure.violation)
    }

    @Test
    fun rejects_non_increasing_uptime_and_property_and_forbidden_process() {
        // Given: a valid first sample.
        val sentinel =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                .observe(sample(1_000), service)

        // When/Then: every no-reboot invariant rejects its own drift.
        assertEquals(
            Violation.UPTIME_NOT_INCREASING,
            assertThrows(SentinelViolation::class.java) { sentinel.observe(sample(1_000), service) }
                .violation,
        )
        val propertiesDrift =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                .observe(sample(1_000), service)
        assertEquals(
            Violation.PROPERTY_HASH_DRIFT,
            assertThrows(SentinelViolation::class.java) {
                    propertiesDrift.observe(
                        sample(
                            1_500,
                            properties = properties + ("ro.build.fingerprint" to "build-B"),
                        ),
                        service,
                    )
                }
                .violation,
        )
        val processDrift =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                .observe(sample(1_000), service)
        assertEquals(
            Violation.FORBIDDEN_PROCESS,
            assertThrows(SentinelViolation::class.java) {
                    processDrift.observe(sample(1_500, forbidden = setOf(99)), service)
                }
                .violation,
        )
    }

    @Test
    fun rejects_gap_larger_than_two_seconds_and_unapproved_restart() {
        // Given: a valid first sample.
        val sentinel =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                .observe(sample(0), service)

        // When/Then: an over-gap and a changed start time are hard failures.
        assertEquals(
            Violation.SAMPLE_GAP,
            assertThrows(SentinelViolation::class.java) { sentinel.observe(sample(2_001), service) }
                .violation,
        )
        val restart =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                .observe(sample(0), service)
        assertEquals(
            Violation.UNAPPROVED_SERVICE_RESTART,
            assertThrows(SentinelViolation::class.java) {
                    restart.observe(sample(1_000), service.copy(startTimeTicks = 101))
                }
                .violation,
        )
    }

    @Test
    fun rejects_secret_properties_and_raw_identifiers_in_quarantine() {
        // Given: an invalid secret-looking property name.
        val forbidden = sample(0, properties = mapOf("persist.rkp.token" to "not-recorded"))

        // When: a sample is constructed.
        val failure =
            assertThrows(IllegalArgumentException::class.java) {
                NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A")
                    .observe(forbidden, service)
            }

        // Then: neither raw serial nor a value is admitted to the receipt surface.
        assertEquals("PROPERTY_NOT_ALLOWLISTED", failure.message)
        assertFalse(Quarantine.redacted(Violation.BOOT_ID_DRIFT).contains("serial"))
    }

    private fun sample(
        uptime: Long,
        boot: String = "boot-A",
        properties: Map<String, String> = this.properties,
        forbidden: Set<Int> = emptySet(),
    ) =
        SentinelSample(
            boot,
            uptime,
            properties,
            forbidden,
            Instant.ofEpochMilli(1_700_000_000_000L + uptime),
        )
}
