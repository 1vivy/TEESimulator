package org.matrix.teesimulator.rkahost.cli

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64

data class SentinelBaseline(
    val sentinelId: String,
    val nonce: String,
    val pairHash: String,
    val donorBootId: String,
    val candidateBootId: String,
    val donorStartMillis: Long,
    val candidateStartMillis: Long,
) {
    fun canonical(): String =
        """{"candidate_boot_id":"$candidateBootId","candidate_start_millis":$candidateStartMillis,"donor_boot_id":"$donorBootId","donor_start_millis":$donorStartMillis,"nonce":"$nonce","pair_sha256":"$pairHash","sentinel_id":"$sentinelId","version":1}
"""

    companion object {
        private val pattern =
            Regex(
                """\{"candidate_boot_id":"([A-Za-z0-9._-]{1,128})","candidate_start_millis":([0-9]+),"donor_boot_id":"([A-Za-z0-9._-]{1,128})","donor_start_millis":([0-9]+),"nonce":"([A-Za-z0-9._-]{1,128})","pair_sha256":"([A-Za-z0-9._-]{1,128})","sentinel_id":"([A-Za-z0-9._-]{1,128})","version":1\}\n"""
            )

        fun parse(raw: String): SentinelBaseline {
            val value =
                pattern.matchEntire(raw)?.groupValues ?: throw HostCliException("BASELINE_INVALID")
            return SentinelBaseline(
                value[7],
                value[5],
                value[6],
                value[3],
                value[1],
                value[4].toLong(),
                value[2].toLong(),
            )
        }
    }
}

object BaselineStore {
    private val fileMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)

    fun create(path: Path, baseline: SentinelBaseline) {
        val parent = path.toAbsolutePath().parent ?: throw HostCliException("BASELINE_PATH_UNSAFE")
        if (
            Files.exists(path, LinkOption.NOFOLLOW_LINKS) ||
                Files.isSymbolicLink(path) ||
                !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) ||
                Files.isSymbolicLink(parent)
        ) {
            throw HostCliException(
                if (Files.isSymbolicLink(path)) "BASELINE_PATH_UNSAFE"
                else "BASELINE_ALREADY_EXISTS"
            )
        }
        val temporary = Files.createTempFile(parent, ".baseline-", ".tmp")
        try {
            Files.setPosixFilePermissions(temporary, fileMode)
            FileChannel.open(temporary, StandardOpenOption.WRITE).use {
                it.write(ByteBuffer.wrap(baseline.canonical().toByteArray()))
                it.force(true)
            }
            try {
                Files.createLink(path, temporary)
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                throw HostCliException("BASELINE_ALREADY_EXISTS")
            }
            FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    fun read(path: Path): SentinelBaseline {
        if (
            Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
                Files.getPosixFilePermissions(path) != fileMode
        ) {
            throw HostCliException("BASELINE_PATH_UNSAFE")
        }
        return SentinelBaseline.parse(Files.readString(path))
    }
}

object PhysicalReceipt {
    private val pattern =
        Regex(
            """\{"artifact_sha256":"([0-9a-f]{64})","candidate_boot_id":"([A-Za-z0-9._-]{1,128})","candidate_end_millis":([0-9]+),"candidate_start_millis":([0-9]+),"command_trace_b64":"([A-Za-z0-9_-]+)","command_trace_sha256":"([0-9a-f]{64})","contains_reboot":false,"donor_boot_id":"([A-Za-z0-9._-]{1,128})","donor_end_millis":([0-9]+),"donor_start_millis":([0-9]+),"kind":"physical-release","nonce":"([A-Za-z0-9._-]{1,128})","pair_sha256":"([A-Za-z0-9._-]{1,128})","sentinel_id":"([A-Za-z0-9._-]{1,128})","source_sha":"([0-9a-f]{40,64})","transport":"DIRECT","version":2\}\n"""
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
        validateTrace(trace)
        val traceBytes = encodeTrace(trace)
        val encodedTrace = Base64.getUrlEncoder().withoutPadding().encodeToString(traceBytes)
        return """{"artifact_sha256":"$artifactSha","candidate_boot_id":"$candidateBootId","candidate_end_millis":$candidateEndMillis,"candidate_start_millis":${baseline.candidateStartMillis},"command_trace_b64":"$encodedTrace","command_trace_sha256":"${Hashes.sha256(traceBytes)}","contains_reboot":false,"donor_boot_id":"$donorBootId","donor_end_millis":$donorEndMillis,"donor_start_millis":${baseline.donorStartMillis},"kind":"physical-release","nonce":"${baseline.nonce}","pair_sha256":"${baseline.pairHash}","sentinel_id":"${baseline.sentinelId}","source_sha":"$sourceSha","transport":"DIRECT","version":2}
"""
    }

    fun verify(
        raw: String,
        baseline: SentinelBaseline,
        sourceSha: String,
        artifactSha: String,
        nonce: String,
    ): String {
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
        if (Hashes.sha256(trace) != value[6]) throw HostCliException("COMMAND_TRACE_MISMATCH")
        decodeTrace(trace).also(::validateTrace)
        if (value[1] != artifactSha) throw HostCliException("ARTIFACT_SHA_MISMATCH")
        if (value[13] != sourceSha) throw HostCliException("SOURCE_SHA_MISMATCH")
        if (value[10] != nonce || value[10] != baseline.nonce) {
            throw HostCliException("NONCE_STALE")
        }
        if (value[11] != baseline.pairHash || value[12] != baseline.sentinelId) {
            throw HostCliException("SENTINEL_IDENTITY_MISMATCH")
        }
        if (value[7] != baseline.donorBootId || value[2] != baseline.candidateBootId) {
            throw HostCliException("BOOT_ID_DRIFT")
        }
        if (
            value[9].toLong() != baseline.donorStartMillis ||
                value[4].toLong() != baseline.candidateStartMillis ||
                value[8].toLong() <= baseline.donorStartMillis ||
                value[3].toLong() <= baseline.candidateStartMillis
        ) {
            throw HostCliException("SENTINEL_CONTINUITY_MISSING")
        }
        return value[1]
    }

    private fun encodeTrace(trace: List<List<String>>): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(trace.size)
                trace.forEach { argv ->
                    output.writeInt(argv.size)
                    argv.forEach {
                        val token = it.toByteArray()
                        output.writeInt(token.size)
                        output.write(token)
                    }
                }
            }
            bytes.toByteArray()
        }

    private fun decodeTrace(raw: ByteArray): List<List<String>> =
        try {
            java.io.DataInputStream(raw.inputStream()).use { input ->
                val count = input.readInt()
                if (count !in 1..10_000) throw HostCliException("COMMAND_TRACE_INVALID")
                List(count) {
                        val arguments = input.readInt()
                        if (arguments !in 1..128) throw HostCliException("COMMAND_TRACE_INVALID")
                        List(arguments) {
                            val size = input.readInt()
                            if (size !in 1..65_536) throw HostCliException("COMMAND_TRACE_INVALID")
                            input
                                .readNBytes(size)
                                .also {
                                    if (it.size != size)
                                        throw HostCliException("COMMAND_TRACE_INVALID")
                                }
                                .toString(Charsets.UTF_8)
                        }
                    }
                    .also {
                        if (input.read() != -1) throw HostCliException("COMMAND_TRACE_INVALID")
                    }
            }
        } catch (failure: HostCliException) {
            throw failure
        } catch (_: Exception) {
            throw HostCliException("COMMAND_TRACE_INVALID")
        }

    private fun validateTrace(trace: List<List<String>>) {
        if (trace.isEmpty()) throw HostCliException("COMMAND_TRACE_MISSING")
        if (
            trace.flatten().any {
                it.lowercase() in setOf("reboot", "killall", "pkill", "task5-probe")
            }
        ) {
            throw HostCliException("REBOOT_TRACE_FORBIDDEN")
        }
    }
}
