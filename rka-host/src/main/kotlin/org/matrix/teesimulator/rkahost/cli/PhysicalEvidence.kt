package org.matrix.teesimulator.rkahost.cli

import java.util.Base64
import org.matrix.teesimulator.rkahost.evidence.AdbCommandTracePolicy
import org.matrix.teesimulator.rkahost.evidence.CommandRejected

data class PairBinding(
    val pairHash: String,
    val donorSerialHash: String,
    val candidateSerialHash: String,
    val profileSha256: String,
) {
    companion object {
        fun from(pair: DevicePairSnapshot): PairBinding =
            PairBinding(
                Hashes.sha256(pair.canonical().toByteArray()),
                Hashes.sha256(pair.donor.value.toByteArray()),
                Hashes.sha256(pair.candidate.value.toByteArray()),
                pair.profileSha256,
            )
    }
}

data class SentinelBaseline(
    val sentinelId: String,
    val nonce: String,
    val binding: PairBinding,
    val donorBootId: String,
    val candidateBootId: String,
    val donorStartMillis: Long,
    val candidateStartMillis: Long,
    val authority: SentinelPhase = SentinelPhase.ROOT_AUTHORITATIVE,
    val samplerSha256: String = "0".repeat(64),
    val scope: SentinelScope = SentinelScope.PAIR,
    val commandTracePolicySha256: String = AdbCommandTracePolicy.policySha256,
) {
    fun canonical(): String =
        """{"authority":"${authority.name}","candidate_boot_id":"$candidateBootId","candidate_serial_sha256":"${binding.candidateSerialHash}","candidate_start_millis":$candidateStartMillis,"command_trace_policy_sha256":"$commandTracePolicySha256","donor_boot_id":"$donorBootId","donor_serial_sha256":"${binding.donorSerialHash}","donor_start_millis":$donorStartMillis,"nonce":"$nonce","pair_sha256":"${binding.pairHash}","profile_sha256":"${binding.profileSha256}","sampler_sha256":"$samplerSha256","scope":"${scope.name}","sentinel_id":"$sentinelId","version":5}
"""

    companion object {
        private val pattern =
            Regex(
                """\{"authority":"(ROOT_AUTHORITATIVE)","candidate_boot_id":"([A-Za-z0-9._-]{1,128})","candidate_serial_sha256":"([0-9a-f]{64})","candidate_start_millis":([0-9]+),"command_trace_policy_sha256":"([0-9a-f]{64})","donor_boot_id":"([A-Za-z0-9._-]{1,128})","donor_serial_sha256":"([0-9a-f]{64})","donor_start_millis":([0-9]+),"nonce":"([A-Za-z0-9._-]{1,128})","pair_sha256":"([0-9a-f]{64})","profile_sha256":"([0-9a-f]{64})","sampler_sha256":"([0-9a-f]{64})","scope":"(PAIR|DONOR)","sentinel_id":"([A-Za-z0-9._-]{1,128})","version":5\}\n"""
            )

        fun parse(raw: String): SentinelBaseline {
            val value =
                pattern.matchEntire(raw)?.groupValues ?: throw HostCliException("BASELINE_INVALID")
            return SentinelBaseline(
                value[14],
                value[9],
                PairBinding(value[10], value[7], value[3], value[11]),
                value[6],
                value[2],
                value[8].toLong(),
                value[4].toLong(),
                SentinelPhase.valueOf(value[1]),
                value[12],
                SentinelScope.valueOf(value[13]),
                value[5],
            )
        }
    }
}

object PhysicalReceipt {
    private val pattern =
        Regex(
            """\{"artifact_sha256":"([0-9a-f]{64})","candidate_boot_id":"([A-Za-z0-9._-]{1,128})","candidate_end_millis":([0-9]+),"candidate_start_millis":([0-9]+),"command_trace_b64":"([A-Za-z0-9_-]+)","command_trace_policy_sha256":"([0-9a-f]{64})","command_trace_sha256":"([0-9a-f]{64})","command_trace_verdict":"CLEAN","donor_boot_id":"([A-Za-z0-9._-]{1,128})","donor_end_millis":([0-9]+),"donor_start_millis":([0-9]+),"kind":"physical-release","nonce":"([A-Za-z0-9._-]{1,128})","pair_sha256":"([A-Za-z0-9._-]{1,128})","sentinel_id":"([A-Za-z0-9._-]{1,128})","source_sha":"([0-9a-f]{40,64})","transport":"DIRECT","version":3\}\n"""
        )

    fun create(
        baseline: SentinelBaseline,
        donorBootId: String,
        candidateBootId: String,
        donorEndMillis: Long,
        candidateEndMillis: Long,
        sourceSha: String,
        artifactSha: String,
        trace: List<List<String>>,
    ): String {
        val assessment = validateCommandTrace { AdbCommandTracePolicy.issue(trace) }
        if (baseline.commandTracePolicySha256 != assessment.policySha256) {
            throw HostCliException("COMMAND_TRACE_POLICY_MISMATCH")
        }
        val encodedTrace =
            Base64.getUrlEncoder().withoutPadding().encodeToString(assessment.encoded)
        return """{"artifact_sha256":"$artifactSha","candidate_boot_id":"$candidateBootId","candidate_end_millis":$candidateEndMillis,"candidate_start_millis":${baseline.candidateStartMillis},"command_trace_b64":"$encodedTrace","command_trace_policy_sha256":"${assessment.policySha256}","command_trace_sha256":"${assessment.traceSha256}","command_trace_verdict":"${assessment.verdict.name}","donor_boot_id":"$donorBootId","donor_end_millis":$donorEndMillis,"donor_start_millis":${baseline.donorStartMillis},"kind":"physical-release","nonce":"${baseline.nonce}","pair_sha256":"${baseline.binding.pairHash}","sentinel_id":"${baseline.sentinelId}","source_sha":"$sourceSha","transport":"DIRECT","version":3}
"""
    }

    fun verify(
        raw: String,
        baseline: SentinelBaseline,
        currentBinding: PairBinding,
        sourceSha: String,
        artifactSha: String,
        nonce: String,
    ): String {
        if (baseline.binding != currentBinding) throw HostCliException("PAIR_BINDING_MISMATCH")
        if (raw.contains(""""kind":"task5-probe"""")) {
            throw HostCliException("PROBE_ONLY_EVIDENCE")
        }
        val value =
            pattern.matchEntire(raw)?.groupValues ?: throw HostCliException("MANIFEST_INVALID")
        val trace =
            try {
                Base64.getUrlDecoder().decode(value[5])
            } catch (_: IllegalArgumentException) {
                throw HostCliException("COMMAND_TRACE_INVALID")
            }
        if (
            value[6] != baseline.commandTracePolicySha256 ||
                value[6] != AdbCommandTracePolicy.policySha256
        ) {
            throw HostCliException("COMMAND_TRACE_POLICY_MISMATCH")
        }
        validateCommandTrace { AdbCommandTracePolicy.verify(trace, value[7]) }
        if (value[1] != artifactSha) throw HostCliException("ARTIFACT_SHA_MISMATCH")
        if (value[14] != sourceSha) throw HostCliException("SOURCE_SHA_MISMATCH")
        if (value[11] != nonce || value[11] != baseline.nonce) {
            throw HostCliException("NONCE_STALE")
        }
        if (value[12] != baseline.binding.pairHash || value[13] != baseline.sentinelId) {
            throw HostCliException("SENTINEL_IDENTITY_MISMATCH")
        }
        if (value[8] != baseline.donorBootId || value[2] != baseline.candidateBootId) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            value[10].toLong() != baseline.donorStartMillis ||
                value[4].toLong() != baseline.candidateStartMillis ||
                value[9].toLong() <= baseline.donorStartMillis ||
                value[3].toLong() <= baseline.candidateStartMillis
        ) {
            throw HostCliException("SENTINEL_CONTINUITY_MISSING")
        }
        return value[1]
    }

    private fun <T> validateCommandTrace(block: () -> T): T =
        try {
            block()
        } catch (failure: CommandRejected) {
            throw HostCliException(failure.message ?: "COMMAND_TRACE_INVALID")
        }
}
