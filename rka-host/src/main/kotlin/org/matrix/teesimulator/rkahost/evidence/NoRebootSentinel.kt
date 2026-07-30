package org.matrix.teesimulator.rkahost.evidence

class NoRebootSentinel(
    serial: String,
    private val role: EndpointRole,
    private val profileId: String,
) {
    private val serialHash = EvidenceHash.sha256(serial)
    private var first: SentinelSample? = null
    private var previous: SentinelSample? = null
    private var service: ServiceIdentity? = null
    private var count = 0

    init {
        require(serial.matches(Regex("[A-Za-z0-9._:-]{1,128}"))) { "SERIAL_INVALID" }
        require(profileId.matches(Regex("[A-Za-z0-9._-]{1,128}"))) { "PROFILE_INVALID" }
    }

    fun observe(sample: SentinelSample, identity: ServiceIdentity): NoRebootSentinel {
        DonorPropertyPolicy.validate(sample.donorProperties)
        if (sample.forbiddenProcessPids.isNotEmpty())
            throw SentinelViolation(Violation.FORBIDDEN_PROCESS)
        val established = first
        if (established == null) {
            first = sample
            previous = sample
            service = identity
            count = 1
            return this
        }
        val last = checkNotNull(previous)
        if (sample.bootId != established.bootId) throw SentinelViolation(Violation.BOOT_ID_DRIFT)
        if (sample.uptimeMillis <= last.uptimeMillis)
            throw SentinelViolation(Violation.UPTIME_NOT_INCREASING)
        if (sample.uptimeMillis - last.uptimeMillis > MAX_GAP_MILLIS)
            throw SentinelViolation(Violation.SAMPLE_GAP)
        if (
            EvidenceHash.propertyHash(sample.donorProperties) !=
                EvidenceHash.propertyHash(established.donorProperties)
        )
            throw SentinelViolation(Violation.PROPERTY_HASH_DRIFT)
        if (identity != service) throw SentinelViolation(Violation.UNAPPROVED_SERVICE_RESTART)
        previous = sample
        count += 1
        return this
    }

    fun assertLive(
        commit: String,
        commandTraceHash: String = EvidenceHash.sha256("no-command"),
    ): SentinelReceipt {
        require(commit.matches(Regex("[A-Za-z0-9._/-]{1,160}"))) { "COMMIT_INVALID" }
        val head = checkNotNull(first) { "SENTINEL_EMPTY" }
        val tail = checkNotNull(previous)
        val selectedService = checkNotNull(service)
        return SentinelReceipt(
            serialHash,
            role,
            profileId,
            commit,
            head.bootId,
            head.uptimeMillis,
            tail.uptimeMillis,
            count,
            selectedService,
            head.donorProperties.keys.sorted(),
            EvidenceHash.propertyHash(head.donorProperties),
            commandTraceHash,
        )
    }

    companion object {
        const val MAX_GAP_MILLIS = 2_000L
    }
}

data class ServiceExpectation(
    val serviceName: String,
    val initOwner: String,
    val executable: String,
)

enum class SelectorFailure {
    ZERO_MATCHES,
    MULTIPLE_MATCHES,
    FORGED_METADATA,
    START_TIME_AMBIGUITY,
}

class SelectorException(val failure: SelectorFailure) :
    IllegalStateException("SELECTOR_${failure.name}")

class ExactServiceSelector(private val expected: ServiceExpectation) {
    fun select(candidates: List<ServiceIdentity>): ServiceIdentity {
        val exact =
            candidates.filter {
                it.serviceName == expected.serviceName &&
                    it.initOwner == expected.initOwner &&
                    it.executable == expected.executable
            }
        if (exact.isEmpty()) {
            if (candidates.any { it.serviceName == expected.serviceName })
                throw SelectorException(SelectorFailure.FORGED_METADATA)
            throw SelectorException(SelectorFailure.ZERO_MATCHES)
        }
        if (exact.size != 1) throw SelectorException(SelectorFailure.MULTIPLE_MATCHES)
        return exact.single()
    }

    fun requireStable(before: ServiceIdentity, after: ServiceIdentity): ServiceIdentity {
        if (
            before.serviceName != after.serviceName ||
                before.initOwner != after.initOwner ||
                before.executable != after.executable ||
                before.pid != after.pid ||
                before.startTimeTicks != after.startTimeTicks
        )
            throw SelectorException(SelectorFailure.START_TIME_AMBIGUITY)
        return after
    }
}
