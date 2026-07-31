package org.matrix.teesimulator.rkahost.cli

object PhysicalManifest {
    private val pattern =
        Regex(
            """\{"artifact_sha256":"([0-9a-f]{64})","command_trace_sha256":"([0-9a-f]{64})","contains_reboot":(false|true),"kind":"([a-z0-9-]+)","nonce":"([A-Za-z0-9._-]{1,128})","sample_chain_sha256":"([0-9a-f]{64})","sample_count":([0-9]+),"source_sha":"([0-9a-f]{40,64})","transport":"([A-Z_]+)","version":1\}\n"""
        )

    fun canonical(
        sourceSha: String,
        artifactSha: String,
        nonce: String,
        sampleChain: String,
        sampleCount: Int,
    ): String =
        """{"artifact_sha256":"$artifactSha","command_trace_sha256":"${Hashes.sha256("no-reboot".toByteArray())}","contains_reboot":false,"kind":"physical-release","nonce":"$nonce","sample_chain_sha256":"$sampleChain","sample_count":$sampleCount,"source_sha":"$sourceSha","transport":"DIRECT","version":1}
"""

    fun verify(raw: String, sourceSha: String, artifactSha: String, nonce: String): String {
        val values =
            pattern.matchEntire(raw)?.groupValues ?: throw HostCliException("MANIFEST_INVALID")
        if (values[4] != "physical-release") throw HostCliException("PROBE_ONLY_EVIDENCE")
        if (values[3] != "false") throw HostCliException("REBOOT_TRACE_FORBIDDEN")
        if (values[9] != "DIRECT") throw HostCliException("DIRECT_TRANSPORT_REQUIRED")
        if (values[7].toInt() < 2 || values[6] == "0".repeat(64)) {
            throw HostCliException("SENTINEL_CONTINUITY_MISSING")
        }
        if (values[8] != sourceSha) throw HostCliException("SOURCE_SHA_MISMATCH")
        if (values[1] != artifactSha) throw HostCliException("ARTIFACT_SHA_MISMATCH")
        if (values[5] != nonce) throw HostCliException("NONCE_STALE")
        return values[1]
    }
}
