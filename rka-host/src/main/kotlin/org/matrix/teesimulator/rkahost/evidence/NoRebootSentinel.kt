package org.matrix.teesimulator.rkahost.evidence

class NoRebootSentinel(
    serial: String,
    private val role: EndpointRole,
    private val profileId: String,
    private val clock: MonotonicClock = MonotonicClock { System.nanoTime() / 1_000_000L },
) {
    private val serialHash = EvidenceHash.sha256(serial)
    private var first: SentinelSample? = null
    private var previous: SentinelSample? = null
    private var service: ServiceIdentity? = null
    private var count = 0
    private var sampleChainHash = EvidenceHash.sha256("sentinel-sample-chain-v1")
    private val samples = mutableListOf<Pair<SentinelSample, ServiceIdentity>>()

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
            appendSample(sample, identity)
            return this
        }
        val last = checkNotNull(previous)
        if (sample.bootId != established.bootId) throw SentinelViolation(Violation.BOOT_ID_DRIFT)
        if (sample.uptimeMillis <= last.uptimeMillis)
            throw SentinelViolation(Violation.UPTIME_NOT_INCREASING)
        val deviceElapsed = sample.uptimeMillis - last.uptimeMillis
        if (deviceElapsed > MAX_GAP_MILLIS) throw SentinelViolation(Violation.SAMPLE_GAP)
        if (sample.observedAtMillis <= last.observedAtMillis)
            throw SentinelViolation(Violation.OBSERVATION_NOT_INCREASING)
        val observedElapsed = sample.observedAtMillis - last.observedAtMillis
        if (observedElapsed > MAX_GAP_MILLIS) throw SentinelViolation(Violation.OBSERVATION_GAP)
        if (kotlin.math.abs(deviceElapsed - observedElapsed) > MAX_SCHEDULING_DRIFT_MILLIS)
            throw SentinelViolation(Violation.CLOCK_DRIFT)
        if (
            EvidenceHash.propertyHash(sample.donorProperties) !=
                EvidenceHash.propertyHash(established.donorProperties)
        )
            throw SentinelViolation(Violation.PROPERTY_HASH_DRIFT)
        if (identity != service) throw SentinelViolation(Violation.UNAPPROVED_SERVICE_RESTART)
        previous = sample
        count += 1
        appendSample(sample, identity)
        return this
    }

    fun assertLive(assertedAtMillis: Long = clock.nowMillis()): LiveSentinelEvidence {
        val head = checkNotNull(first) { "SENTINEL_EMPTY" }
        val tail = checkNotNull(previous)
        val selectedService = checkNotNull(service)
        if (count < MINIMUM_SAMPLES || count != samples.size || count > MAXIMUM_SAMPLES)
            throw SentinelViolation(Violation.INSUFFICIENT_SAMPLES)
        val (derivedChainHash, derivedCount) = deriveSamples()
        if (derivedCount != count || derivedChainHash != sampleChainHash)
            throw SentinelViolation(Violation.INSUFFICIENT_SAMPLES)
        if (assertedAtMillis < 0 || assertedAtMillis < tail.observedAtMillis)
            throw SentinelViolation(Violation.STALE_ASSERTION)
        if (assertedAtMillis - tail.observedAtMillis > MAX_GAP_MILLIS)
            throw SentinelViolation(Violation.STALE_ASSERTION)
        return LiveSentinelEvidence.derived(LiveValues(
            serialHash,
            role,
            profileId,
            head.bootId,
            head.uptimeMillis,
            tail.uptimeMillis,
            head.observedAtMillis,
            tail.observedAtMillis,
            assertedAtMillis,
            sampleChainHash,
            count,
            selectedService,
            head.donorProperties.keys.sorted(),
            EvidenceHash.propertyHash(head.donorProperties),
        ))
    }

    companion object {
        const val MAX_GAP_MILLIS = 2_000L
        const val MAX_SCHEDULING_DRIFT_MILLIS = 250L
        const val MINIMUM_SAMPLES = 2
        const val MAXIMUM_SAMPLES = 1_024
    }

    private fun appendSample(sample: SentinelSample, identity: ServiceIdentity) {
        samples += sample to identity
        sampleChainHash =
            EvidenceHash.sha256(
                listOf(
                        sampleChainHash,
                        sample.bootId,
                        sample.uptimeMillis,
                        sample.observedAtMillis,
                        EvidenceHash.propertyHash(sample.donorProperties),
                        sample.forbiddenProcessPids.sorted().joinToString(","),
                        identity.canonical(),
                    )
                    .joinToString("\n")
            )
    }

    private fun deriveSamples(): Pair<String, Int> {
        var chain = EvidenceHash.sha256("sentinel-sample-chain-v1")
        samples.forEach { (sample, identity) ->
            chain =
                EvidenceHash.sha256(
                    listOf(
                            chain,
                            sample.bootId,
                            sample.uptimeMillis,
                            sample.observedAtMillis,
                            EvidenceHash.propertyHash(sample.donorProperties),
                            sample.forbiddenProcessPids.sorted().joinToString(","),
                            identity.canonical(),
                        )
                        .joinToString("\n")
                )
        }
        return chain to samples.size
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
