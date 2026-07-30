package org.matrix.teesimulator.rkahost.evidence

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

enum class EndpointRole {
    DONOR,
    CANDIDATE,
}

data class ServiceIdentity(
    val serviceName: String,
    val initOwner: String,
    val pid: Int,
    val startTimeTicks: Long,
    val executable: String,
    val approvedRestartGeneration: Long,
) {
    init {
        require(serviceName.matches(Regex("[A-Za-z0-9_.-]{1,128}"))) { "SERVICE_NAME_INVALID" }
        require(initOwner.matches(Regex("[A-Za-z0-9_.-]{1,128}"))) { "SERVICE_OWNER_INVALID" }
        require(pid > 0 && startTimeTicks > 0) { "SERVICE_PROCESS_INVALID" }
        require(executable.startsWith("/") && !executable.contains("..")) {
            "SERVICE_EXECUTABLE_INVALID"
        }
        require(approvedRestartGeneration >= 0) { "SERVICE_GENERATION_INVALID" }
    }

    fun canonical(): String =
        listOf(serviceName, initOwner, pid, startTimeTicks, executable, approvedRestartGeneration)
            .joinToString("|")
}

data class SentinelSample(
    val bootId: String,
    val uptimeMillis: Long,
    val donorProperties: Map<String, String>,
    val forbiddenProcessPids: Set<Int>,
    val observedAtMillis: Long,
) {
    init {
        require(bootId.matches(Regex("[A-Za-z0-9._-]{1,128}"))) { "BOOT_ID_INVALID" }
        require(uptimeMillis >= 0) { "UPTIME_INVALID" }
        require(observedAtMillis >= 0) { "OBSERVED_AT_INVALID" }
        require(forbiddenProcessPids.all { it > 0 }) { "FORBIDDEN_PID_INVALID" }
    }
}

object EvidenceHash {
    fun sha256(value: String): String = sha256(value.toByteArray(StandardCharsets.UTF_8))

    fun sha256(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    fun propertyHash(properties: Map<String, String>): String {
        require(properties.isNotEmpty()) { "PROPERTY_SET_EMPTY" }
        return sha256(
            properties.toSortedMap().entries.joinToString("\n") { (name, value) ->
                "$name=${b64(value)}"
            }
        )
    }

    fun b64(value: String): String =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(value.toByteArray(StandardCharsets.UTF_8))
}

object DonorPropertyPolicy {
    private val allowed =
        setOf(
            "ro.build.fingerprint",
            "ro.build.version.release",
            "ro.build.version.incremental",
            "ro.vendor.build.fingerprint",
        )
    private val secretWords =
        Regex("(?i)(secret|token|password|credential|key|alias|blob|private|auth)")

    fun validate(properties: Map<String, String>) {
        require(properties.keys.all { it in allowed && !secretWords.containsMatchIn(it) }) {
            "PROPERTY_NOT_ALLOWLISTED"
        }
        require(properties.values.none { it.contains('\n') || it.contains('\u0000') }) {
            "PROPERTY_VALUE_INVALID"
        }
    }
}

data class SentinelReceipt(
    val serialHash: String,
    val role: EndpointRole,
    val profileId: String,
    val commit: String,
    val bootId: String,
    val headUptimeMillis: Long,
    val tailUptimeMillis: Long,
    val headObservedAtMillis: Long,
    val tailObservedAtMillis: Long,
    val assertedAtMillis: Long,
    val sampleChainHash: String,
    val sampleCount: Int,
    val service: ServiceIdentity,
    val propertyNames: List<String>,
    val propertyHash: String,
    val commandTraceHash: String,
) {
    fun canonical(): String =
        listOf(
                serialHash,
                role.name,
                profileId,
                commit,
                bootId,
                headUptimeMillis,
                tailUptimeMillis,
                headObservedAtMillis,
                tailObservedAtMillis,
                assertedAtMillis,
                sampleChainHash,
                sampleCount,
                service.canonical(),
                propertyNames.joinToString(","),
                propertyHash,
                commandTraceHash,
            )
            .joinToString("\n")
}

enum class Violation {
    BOOT_ID_DRIFT,
    UPTIME_NOT_INCREASING,
    SAMPLE_GAP,
    OBSERVATION_NOT_INCREASING,
    OBSERVATION_GAP,
    CLOCK_DRIFT,
    INSUFFICIENT_SAMPLES,
    STALE_ASSERTION,
    PROPERTY_HASH_DRIFT,
    FORBIDDEN_PROCESS,
    UNAPPROVED_SERVICE_RESTART,
}

fun interface MonotonicClock {
    fun nowMillis(): Long
}

class SentinelViolation(val violation: Violation) :
    IllegalStateException("SENTINEL_${violation.name}")

object Quarantine {
    fun redacted(violation: Violation): String = "QUARANTINE_${violation.name}"
}
