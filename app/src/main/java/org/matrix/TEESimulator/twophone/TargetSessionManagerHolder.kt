package org.matrix.TEESimulator.twophone

import java.time.Instant
import org.matrix.teesimulator.twophone.FixturePackageIdentity
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.TargetPublicProfile
import org.matrix.teesimulator.twophone.TargetPublicProfileStore
import org.matrix.teesimulator.twophone.WireCallerIdentity

object TargetSessionManagerHolder {
    private val monitor = Any()
    @Volatile private var manager: TargetSessionManager? = null
    private var binding: TargetSessionBinding? = null
    @Volatile private var terminallyClosed = false

    fun getOrCreate(
        expectedFixtureIdentity: FixturePackageIdentity,
        caller: WireCallerIdentity,
    ): TargetSessionManager =
        getOrCreate(expectedFixtureIdentity, caller) { create(expectedFixtureIdentity, caller) }

    fun getOrCreate(
        expectedFixtureIdentity: FixturePackageIdentity,
        caller: WireCallerIdentity,
        source: () -> TargetSessionManager,
    ): TargetSessionManager {
        val requestedBinding = TargetSessionBinding(expectedFixtureIdentity, caller)
        return synchronized(monitor) {
            if (terminallyClosed) throw TargetSessionException.Closed()
            manager?.let { existing ->
                if (binding != requestedBinding) throw TargetSessionException.IdentityMismatch()
                return@synchronized existing
            }
            val created = source()
            manager = created
            binding = requestedBinding
            created
        }
    }

    private fun create(
        expectedFixtureIdentity: FixturePackageIdentity,
        caller: WireCallerIdentity,
    ): TargetSessionManager =
        getOrCreate(
            profileLoader = {
                TargetPublicProfileStore(
                        expectedFixtureIdentity,
                        AndroidTargetPublicProfileAtomicFileFacade(),
                    )
                    .load()
            },
            managerFactory = { profile ->
                val expectedTargetPin = SpkiPin.parse(profile.targetIdentity.pin.toString())
                val identity =
                    AndroidKeyStoreTargetTlsClientIdentity.openExisting(
                        expectedTargetPin,
                        Instant.now(),
                    )
                TargetSessionManager(
                    profile,
                    PinnedJsseTargetClientContext.create(identity, profile),
                    caller,
                )
            },
        )

    internal fun getOrCreate(
        profileLoader: () -> TargetPublicProfile?,
        managerFactory: (TargetPublicProfile) -> TargetSessionManager,
    ): TargetSessionManager =
        synchronized(monitor) {
            if (terminallyClosed) throw TargetSessionException.Closed()
            manager
                ?: managerFactory(profileLoader() ?: throw TargetSessionException.MissingProfile())
                    .also { manager = it }
        }

    fun close(): TargetCloseOutcome =
        synchronized(monitor) {
            terminallyClosed = true
            val active = manager ?: return@synchronized TargetCloseOutcome.Closed
            active.close()
        }

    internal fun resetForTest() {
        synchronized(monitor) {
            manager?.close()
            manager = null
            binding = null
            terminallyClosed = false
        }
    }

    private data class TargetSessionBinding(
        val fixtureIdentity: FixturePackageIdentity,
        val caller: WireCallerIdentity,
    )
}
