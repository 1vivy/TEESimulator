package org.matrix.teesimulator.rkahost.cli

import java.util.Base64
import org.matrix.teesimulator.rkahost.evidence.AdbCommandTracePolicy

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
    val commandTraceGenesisSha256: String = "0".repeat(64),
    val commandTraceSessionId: String = "0".repeat(32),
    val commandTraceInitialHeadSha256: String = "0".repeat(64),
    val commandTraceInitialEventCount: Int = 0,
    val deploySurface: DeploySurfaceBinding = DeploySurfaceBinding.TEST,
) {
    fun canonical(): String =
        """{"authority":"${authority.name}","candidate_boot_id":"$candidateBootId","candidate_serial_sha256":"${binding.candidateSerialHash}","candidate_start_millis":$candidateStartMillis,"command_trace_genesis_sha256":"$commandTraceGenesisSha256","command_trace_initial_event_count":$commandTraceInitialEventCount,"command_trace_initial_head_sha256":"$commandTraceInitialHeadSha256","command_trace_policy_sha256":"$commandTracePolicySha256","command_trace_session_id":"$commandTraceSessionId","deploy_entrypoint_path_sha256":"${deploySurface.entrypointPathSha256}","deploy_entrypoint_sha256":"${deploySurface.entrypointSha256}","deploy_surface_sha256":"${deploySurface.surfaceSha256}","donor_boot_id":"$donorBootId","donor_serial_sha256":"${binding.donorSerialHash}","donor_start_millis":$donorStartMillis,"nonce":"$nonce","pair_sha256":"${binding.pairHash}","profile_sha256":"${binding.profileSha256}","sampler_sha256":"$samplerSha256","scope":"${scope.name}","sentinel_id":"$sentinelId","version":7}
"""

    companion object {
        private val pattern =
            Regex(
                """\{"authority":"(ROOT_AUTHORITATIVE)","candidate_boot_id":"([A-Za-z0-9._-]{1,128})","candidate_serial_sha256":"([0-9a-f]{64})","candidate_start_millis":([0-9]+),"command_trace_genesis_sha256":"([0-9a-f]{64})","command_trace_initial_event_count":(0),"command_trace_initial_head_sha256":"([0-9a-f]{64})","command_trace_policy_sha256":"([0-9a-f]{64})","command_trace_session_id":"([0-9a-f]{32})","deploy_entrypoint_path_sha256":"([0-9a-f]{64})","deploy_entrypoint_sha256":"([0-9a-f]{64})","deploy_surface_sha256":"([0-9a-f]{64})","donor_boot_id":"([A-Za-z0-9._-]{1,128})","donor_serial_sha256":"([0-9a-f]{64})","donor_start_millis":([0-9]+),"nonce":"([A-Za-z0-9._-]{1,128})","pair_sha256":"([0-9a-f]{64})","profile_sha256":"([0-9a-f]{64})","sampler_sha256":"([0-9a-f]{64})","scope":"(PAIR|DONOR)","sentinel_id":"([A-Za-z0-9._-]{1,128})","version":7\}\n"""
            )

        fun parse(raw: String): SentinelBaseline {
            val value =
                pattern.matchEntire(raw)?.groupValues ?: throw HostCliException("BASELINE_INVALID")
            return SentinelBaseline(
                value[21],
                value[16],
                PairBinding(value[17], value[14], value[3], value[18]),
                value[13],
                value[2],
                value[15].toLong(),
                value[4].toLong(),
                SentinelPhase.valueOf(value[1]),
                value[19],
                SentinelScope.valueOf(value[20]),
                value[8],
                value[5],
                value[9],
                value[7],
                value[6].toInt(),
                DeploySurfaceBinding(value[11], value[10], value[12]),
            )
        }
    }
}

object PhysicalReceipt {
    private val pattern =
        Regex(
            """\{"artifact_sha256":"([0-9a-f]{64})","candidate_boot_id":"([A-Za-z0-9._-]{1,128})","candidate_end_millis":([0-9]+),"candidate_start_millis":([0-9]+),"command_trace_b64":"([A-Za-z0-9_-]+)","command_trace_event_count":([1-9][0-9]*),"command_trace_genesis_sha256":"([0-9a-f]{64})","command_trace_head_sha256":"([0-9a-f]{64})","command_trace_policy_sha256":"([0-9a-f]{64})","command_trace_session_id":"([0-9a-f]{32})","command_trace_verdict":"CLEAN","deploy_entrypoint_path_sha256":"([0-9a-f]{64})","deploy_entrypoint_sha256":"([0-9a-f]{64})","deploy_surface_sha256":"([0-9a-f]{64})","donor_boot_id":"([A-Za-z0-9._-]{1,128})","donor_end_millis":([0-9]+),"donor_start_millis":([0-9]+),"kind":"physical-release","nonce":"([A-Za-z0-9._-]{1,128})","pair_sha256":"([0-9a-f]{64})","sentinel_id":"([A-Za-z0-9._-]{1,128})","source_sha":"([0-9a-f]{40,64})","transport":"DIRECT","version":5\}\n"""
        )

    fun create(
        baseline: SentinelBaseline,
        donorBootId: String,
        candidateBootId: String,
        donorEndMillis: Long,
        candidateEndMillis: Long,
        sourceSha: String,
        artifactSha: String,
        trace: ValidatedPersistentTrace,
    ): String {
        if (
            trace.verdict != "CLEAN" ||
                trace.binding.eventCount < 1 ||
                baseline.commandTracePolicySha256 != AdbCommandTracePolicy.policySha256 ||
                baseline.commandTraceGenesisSha256 != trace.binding.genesisSha256 ||
                baseline.commandTraceSessionId != trace.binding.sessionId
        ) {
            throw HostCliException("COMMAND_TRACE_POLICY_MISMATCH")
        }
        val encodedTrace = Base64.getUrlEncoder().withoutPadding().encodeToString(trace.canonical)
        return """{"artifact_sha256":"$artifactSha","candidate_boot_id":"$candidateBootId","candidate_end_millis":$candidateEndMillis,"candidate_start_millis":${baseline.candidateStartMillis},"command_trace_b64":"$encodedTrace","command_trace_event_count":${trace.binding.eventCount},"command_trace_genesis_sha256":"${trace.binding.genesisSha256}","command_trace_head_sha256":"${trace.binding.headSha256}","command_trace_policy_sha256":"${baseline.commandTracePolicySha256}","command_trace_session_id":"${trace.binding.sessionId}","command_trace_verdict":"CLEAN","deploy_entrypoint_path_sha256":"${baseline.deploySurface.entrypointPathSha256}","deploy_entrypoint_sha256":"${baseline.deploySurface.entrypointSha256}","deploy_surface_sha256":"${baseline.deploySurface.surfaceSha256}","donor_boot_id":"$donorBootId","donor_end_millis":$donorEndMillis,"donor_start_millis":${baseline.donorStartMillis},"kind":"physical-release","nonce":"${baseline.nonce}","pair_sha256":"${baseline.binding.pairHash}","sentinel_id":"${baseline.sentinelId}","source_sha":"$sourceSha","transport":"DIRECT","version":5}
"""
    }

    fun verify(
        raw: String,
        baselinePath: java.nio.file.Path,
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
            value[9] != baseline.commandTracePolicySha256 ||
                value[9] != AdbCommandTracePolicy.policySha256
        ) {
            throw HostCliException("COMMAND_TRACE_POLICY_MISMATCH")
        }
        val validated = PersistentAdbTrace.validateSnapshot(trace, baselinePath, baseline)
        if (
            validated.verdict != "CLEAN" ||
                validated.binding.eventCount.toString() != value[6] ||
                validated.binding.genesisSha256 != value[7] ||
                validated.binding.headSha256 != value[8] ||
                validated.binding.sessionId != value[10]
        )
            throw HostCliException("COMMAND_TRACE_MISMATCH")
        if (
            value[11] != baseline.deploySurface.entrypointPathSha256 ||
                value[12] != baseline.deploySurface.entrypointSha256 ||
                value[13] != baseline.deploySurface.surfaceSha256
        ) {
            throw HostCliException("DEPLOY_SOURCE_BINDING_MISMATCH")
        }
        if (value[1] != artifactSha) throw HostCliException("ARTIFACT_SHA_MISMATCH")
        if (value[20] != sourceSha) throw HostCliException("SOURCE_SHA_MISMATCH")
        if (value[17] != nonce || value[17] != baseline.nonce) {
            throw HostCliException("NONCE_STALE")
        }
        if (value[18] != baseline.binding.pairHash || value[19] != baseline.sentinelId) {
            throw HostCliException("SENTINEL_IDENTITY_MISMATCH")
        }
        if (value[14] != baseline.donorBootId || value[2] != baseline.candidateBootId) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            value[16].toLong() != baseline.donorStartMillis ||
                value[4].toLong() != baseline.candidateStartMillis ||
                value[15].toLong() <= baseline.donorStartMillis ||
                value[3].toLong() <= baseline.candidateStartMillis
        ) {
            throw HostCliException("SENTINEL_CONTINUITY_MISSING")
        }
        return value[1]
    }
}
