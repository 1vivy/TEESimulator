package org.matrix.teesimulator.physicalharness

import android.content.Context
import java.security.MessageDigest
import java.time.Instant

enum class DonorRuntimeState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    STOP_FAILED,
}

enum class DonorRuntimeStartResult {
    STARTED,
    ALREADY_RUNNING,
}

enum class DonorRuntimeStopResult {
    STOPPED,
    ALREADY_STOPPED,
}

sealed class DonorRuntimeException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class ConflictingProfile : DonorRuntimeException("a different donor profile is active")

    class Unavailable(cause: Throwable? = null) :
        DonorRuntimeException("donor runtime unavailable", cause)
}

class DonorRuntimeOwner<P : Any>(
    private val configSource: DonorConfigSource,
    private val identityOpener: DonorTlsIdentityOpener,
    private val processHolder: DonorProcessHolder<P>,
    private val processFactory: PhysicalDonorProcessFactory<P>,
    private val callerResolver: DonorCallerResolver,
    private val serverFactory: PinnedDonorServerFactory<P>,
) : DonorRuntimeControl {
    private val monitor = Any()
    @Volatile private var inspectedState = DonorRuntimeState.STOPPED
    private var server: DonorServer? = null
    private var activeFingerprint: ByteArray? = null

    override val state: DonorRuntimeState
        get() = inspectedState

    override fun start(profileId: String, now: Instant): DonorRuntimeStartResult =
        synchronized(monitor) {
            DonorProfile.requireValidProfileId(profileId)
            val profile = loadProfile(profileId, now)
            val fingerprint = profile.fingerprint
            when (inspectedState) {
                DonorRuntimeState.RUNNING -> {
                    if (MessageDigest.isEqual(checkNotNull(activeFingerprint), fingerprint)) {
                        return@synchronized DonorRuntimeStartResult.ALREADY_RUNNING
                    }
                    throw DonorRuntimeException.ConflictingProfile()
                }
                DonorRuntimeState.STOPPED -> startStopped(profile, fingerprint, now)
                DonorRuntimeState.STARTING,
                DonorRuntimeState.STOPPING,
                DonorRuntimeState.STOP_FAILED -> throw DonorRuntimeException.Unavailable()
            }
        }

    override fun stop(): DonorRuntimeStopResult {
        val nowNanos = System.nanoTime()
        val timeoutNanos = 5_000_000_000L
        val deadlineNanos =
            if (nowNanos > Long.MAX_VALUE - timeoutNanos) Long.MAX_VALUE
            else nowNanos + timeoutNanos
        return stopUntil(deadlineNanos)
    }

    override fun stopUntil(deadlineNanos: Long): DonorRuntimeStopResult =
        synchronized(monitor) {
            when (inspectedState) {
                DonorRuntimeState.STOPPED -> DonorRuntimeStopResult.ALREADY_STOPPED
                DonorRuntimeState.RUNNING,
                DonorRuntimeState.STOP_FAILED -> stopOwnedServer(deadlineNanos)
                DonorRuntimeState.STARTING,
                DonorRuntimeState.STOPPING -> throw DonorRuntimeException.Unavailable()
            }
        }

    private fun loadProfile(profileId: String, now: Instant): DonorProfile {
        val profile =
            try {
                configSource.load(profileId, now)
            } catch (failure: DonorProfileException.InvalidProfileId) {
                throw failure
            } catch (failure: Throwable) {
                throw DonorRuntimeException.Unavailable(failure)
            }
        if (profile == null || profile.profileId != profileId) {
            throw DonorRuntimeException.Unavailable()
        }
        return profile
    }

    private fun startStopped(
        profile: DonorProfile,
        fingerprint: ByteArray,
        now: Instant,
    ): DonorRuntimeStartResult {
        inspectedState = DonorRuntimeState.STARTING
        var candidate: DonorServer? = null
        try {
            val identity = identityOpener.open(profile.expectedDonorPin, now)
            val process = processHolder.getOrCreate(processFactory)
            val caller = callerResolver.resolve()
            candidate = serverFactory.create(profile, identity, process, caller)
            candidate.start()
            server = candidate
            activeFingerprint = fingerprint.copyOf()
            inspectedState = DonorRuntimeState.RUNNING
            return DonorRuntimeStartResult.STARTED
        } catch (failure: Throwable) {
            closeFailedCandidate(candidate, fingerprint, failure)
        }
    }

    private fun closeFailedCandidate(
        candidate: DonorServer?,
        fingerprint: ByteArray,
        failure: Throwable,
    ): Nothing {
        if (candidate == null) {
            server = null
            activeFingerprint = null
            inspectedState = DonorRuntimeState.STOPPED
            throw DonorRuntimeException.Unavailable(failure)
        }

        val nowNanos = System.nanoTime()
        val timeoutNanos = 5_000_000_000L
        val deadlineNanos =
            if (nowNanos > Long.MAX_VALUE - timeoutNanos) Long.MAX_VALUE
            else nowNanos + timeoutNanos
        val outcome =
            try {
                candidate.closeUntil(deadlineNanos)
            } catch (closeFailure: Throwable) {
                DonorServerCloseOutcome.Incomplete(closeFailure)
            }
        when (outcome) {
            DonorServerCloseOutcome.Closed -> {
                server = null
                activeFingerprint = null
                inspectedState = DonorRuntimeState.STOPPED
            }
            is DonorServerCloseOutcome.Incomplete -> {
                outcome.cause?.takeIf { it !== failure }?.let(failure::addSuppressed)
                server = candidate
                activeFingerprint = fingerprint.copyOf()
                inspectedState = DonorRuntimeState.STOP_FAILED
            }
        }
        throw DonorRuntimeException.Unavailable(failure)
    }

    private fun stopOwnedServer(deadlineNanos: Long): DonorRuntimeStopResult {
        inspectedState = DonorRuntimeState.STOPPING
        val activeServer = checkNotNull(server)
        val outcome =
            try {
                activeServer.closeUntil(deadlineNanos)
            } catch (failure: Throwable) {
                DonorServerCloseOutcome.Incomplete(failure)
            }
        return when (outcome) {
            DonorServerCloseOutcome.Closed -> {
                server = null
                activeFingerprint = null
                inspectedState = DonorRuntimeState.STOPPED
                DonorRuntimeStopResult.STOPPED
            }
            is DonorServerCloseOutcome.Incomplete -> {
                inspectedState = DonorRuntimeState.STOP_FAILED
                throw DonorRuntimeException.Unavailable(outcome.cause)
            }
        }
    }

    companion object {
        fun production(
            context: Context,
            configSource: DonorConfigSource =
                StoredDonorConfigSource(DonorPublicProfileStore(context)),
        ): DonorRuntimeOwner<PhysicalDonorProcess> {
            val applicationContext = context.applicationContext
            return DonorRuntimeOwner(
                configSource,
                AndroidDonorTlsIdentityOpener,
                ProductionDonorProcessHolder.instance,
                AndroidPhysicalDonorProcessFactory(applicationContext),
                AndroidDonorCallerResolver(applicationContext),
                ProductionPinnedDonorServerFactory(),
            )
        }
    }
}
