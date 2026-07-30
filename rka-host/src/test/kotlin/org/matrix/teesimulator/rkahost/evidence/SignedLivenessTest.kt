package org.matrix.teesimulator.rkahost.evidence

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SignedLivenessTest {
    private val service = ServiceIdentity("keystore2", "init", 42, 100, "/system/bin/keystore2", 0)
    private val properties = mapOf("ro.build.fingerprint" to "build-A")
    private val signer = DigestSigner("test-key")

    @Test
    fun signs_one_hundred_continuous_samples_over_more_than_two_minutes() {
        val live = live((0 until 100).map { it * 1_500L to it * 1_500L })
        val encoded = issue(live, "nonce-hundred", 148_500)

        assertEquals(100, verify(encoded, "nonce-hundred").sampleCount)
        assertTrue(encoded.contains("max_device_interval_millis=1500\n"))
        assertTrue(encoded.contains("max_observation_interval_millis=1500\n"))
        assertTrue(encoded.contains("max_interval_drift_millis=0\n"))
    }

    @Test
    fun rejects_a_late_adjacent_device_gap_before_signing() {
        val sentinel =
            sentinel(3_501).observe(sample(0, 0), service).observe(sample(1_500, 1_500), service)

        assertEquals(
            Violation.SAMPLE_GAP,
            assertThrows(SentinelViolation::class.java) {
                    sentinel.observe(sample(3_501, 3_000), service)
                }
                .violation,
        )
    }

    @Test
    fun rejects_a_late_adjacent_scheduling_drift_before_signing() {
        val sentinel =
            sentinel(3_251).observe(sample(0, 0), service).observe(sample(1_500, 1_500), service)

        assertEquals(
            Violation.CLOCK_DRIFT,
            assertThrows(SentinelViolation::class.java) {
                    sentinel.observe(sample(3_000, 3_251), service)
                }
                .violation,
        )
    }

    @Test
    fun rejects_stale_tail_before_signing() {
        val sentinel =
            sentinel(5_001).observe(sample(0, 0), service).observe(sample(1_500, 1_500), service)

        assertEquals(
            Violation.STALE_ASSERTION,
            assertThrows(SentinelViolation::class.java) { sentinel.assertLive(5_001) }.violation,
        )
    }

    @Test
    fun rejects_reordered_and_duplicate_samples_before_signing() {
        val reordered = sentinel(1_500).observe(sample(1_000, 1_000), service)
        val duplicate = sentinel(1_500).observe(sample(1_000, 1_000), service)

        assertEquals(
            Violation.UPTIME_NOT_INCREASING,
            assertThrows(SentinelViolation::class.java) {
                    reordered.observe(sample(999, 1_001), service)
                }
                .violation,
        )
        assertEquals(
            Violation.OBSERVATION_NOT_INCREASING,
            assertThrows(SentinelViolation::class.java) {
                    duplicate.observe(sample(1_001, 1_000), service)
                }
                .violation,
        )
    }

    @Test
    fun rejects_tampered_signed_aggregates_times_and_chain() {
        val encoded =
            issue(live(listOf(0L to 0L, 1_500L to 1_500L, 3_000L to 3_000L)), "nonce-tamper", 3_000)
        val binding = binding("nonce-tamper")
        val mutations =
            listOf(
                "max_device_interval_millis=1500\n" to "max_device_interval_millis=1499\n",
                "max_observation_interval_millis=1500\n" to
                    "max_observation_interval_millis=1499\n",
                "max_interval_drift_millis=0\n" to "max_interval_drift_millis=1\n",
                "sample_count=3\n" to "sample_count=4\n",
                "head_observed_at=0\n" to "head_observed_at=1\n",
            )

        mutations.forEach { (from, to) ->
            assertThrows(ReceiptException::class.java) {
                ReceiptVerifier(signer).verify(encoded.replace(from, to), binding)
            }
        }
        val tamperedChain =
            encoded.replace(
                Regex("sample_chain_hash=[^\\n]+"),
                "sample_chain_hash=${"f".repeat(64)}",
            )
        assertEquals(
            "RECEIPT_SIGNATURE_INVALID",
            assertThrows(ReceiptException::class.java) {
                    ReceiptVerifier(signer).verify(tamperedChain, binding)
                }
                .message,
        )
    }

    @Test
    fun rejects_impossible_resigned_adjacent_aggregates() {
        val encoded =
            issue(
                live(listOf(0L to 0L, 1_500L to 1_500L, 3_000L to 3_000L)),
                "nonce-resigned",
                3_000,
            )
        val impossible =
            resign(
                encoded.replace(
                    "max_device_interval_millis=1500\n",
                    "max_device_interval_millis=2001\n",
                )
            )

        assertEquals(
            "RECEIPT_TIME_INVALID",
            assertThrows(ReceiptException::class.java) {
                    ReceiptVerifier(signer).verify(impossible, binding("nonce-resigned"))
                }
                .message,
        )
    }

    private fun live(points: List<Pair<Long, Long>>): LiveSentinelEvidence {
        val sentinel = sentinel(points.last().second)
        points.forEach { (uptimeMillis, observedAtMillis) ->
            sentinel.observe(sample(uptimeMillis, observedAtMillis), service)
        }
        return sentinel.assertLive(points.last().second)
    }

    private fun issue(live: LiveSentinelEvidence, nonce: String, monotonicMillis: Long): String =
        EvidenceIssuer.sign(
            live,
            binding(nonce),
            ReceiptMaterial(
                EvidenceHash.sha256("trace"),
                EvidenceHash.sha256("artifact"),
                monotonicMillis = monotonicMillis,
            ),
            signer,
        )

    private fun verify(encoded: String, nonce: String): VerifiedEvidence =
        ReceiptVerifier(signer).verify(encoded, binding(nonce))

    private fun binding(nonce: String) =
        ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", nonce)

    private fun resign(encoded: String): String {
        val unsigned = encoded.substringBefore("signer=")
        val signature =
            Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(signer.sign(unsigned.toByteArray()))
        return unsigned + "signer=${signer.keyId}\n" + "signature=$signature\n"
    }

    private fun sentinel(nowMillis: Long) =
        NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A", MonotonicClock { nowMillis })

    private fun sample(uptimeMillis: Long, observedAtMillis: Long) =
        SentinelSample("boot-A", uptimeMillis, properties, emptySet(), observedAtMillis)
}
