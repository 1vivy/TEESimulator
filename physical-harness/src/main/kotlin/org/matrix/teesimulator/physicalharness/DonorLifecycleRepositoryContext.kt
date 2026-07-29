package org.matrix.teesimulator.physicalharness

import java.security.MessageDigest
import org.matrix.teesimulator.twophone.DeleteRequestPayload
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.NormalizedWireCodec

internal class DonorLifecycleRepositoryContext(
    private val stateStore: AuthenticatedDonorStateStore,
    val keyStore: DurableAndroidKeyStore,
    val authenticator: HandleAuthenticator,
) {
    private var snapshot: DonorStateSnapshot? = null
    private var reloadRequired = true
    private var globallyQuarantined = false

    val state: DonorStateSnapshot
        get() = snapshot ?: error("repository state is not loaded")

    fun requireNotQuarantined() {
        if (globallyQuarantined) throw DonorLifecycleRepositoryException.GlobalQuarantine()
    }

    fun ensureLoaded(): Boolean {
        requireNotQuarantined()
        if (!reloadRequired && snapshot != null) return false
        val loaded =
            try {
                stateStore.load()
            } catch (failure: Throwable) {
                handleLoadFailure(failure)
            }
        val candidate = loaded ?: DonorStateSnapshot(0uL, emptyList(), emptyList())
        try {
            validatePersistedHashes(candidate)
        } catch (failure: Throwable) {
            quarantine(failure)
        }
        val ownedAliases =
            try {
                keyStore.ownedAliases()
            } catch (failure: Throwable) {
                unavailable(failure)
            }
        val representedAliases =
            candidate.keys.mapTo(mutableSetOf(), DurableKeyRecord::internalAlias)
        if (ownedAliases.any { it !in representedAliases }) quarantine()
        snapshot = candidate
        reloadRequired = false
        return true
    }

    fun requireWritable() {
        if (state.revision == ULong.MAX_VALUE) {
            throw DonorLifecycleRepositoryException.RevisionExhausted()
        }
    }

    fun save(keys: List<DurableKeyRecord>, mutations: List<DurableMutationRecord>) {
        requireWritable()
        val next =
            try {
                DonorStateSnapshot(state.revision + 1uL, keys, mutations)
            } catch (failure: DonorStateQuarantineException) {
                quarantine(failure)
            }
        try {
            stateStore.save(next)
        } catch (failure: Throwable) {
            if (failure.isStateIntegrityFailure()) quarantine(failure)
            snapshot = null
            reloadRequired = true
            unavailable(failure)
        }
        snapshot = next
    }

    fun <T> keyStoreCall(block: () -> T): T =
        try {
            block()
        } catch (failure: DonorLifecycleRepositoryException) {
            throw failure
        } catch (failure: Throwable) {
            unavailable(failure)
        }

    fun expectedPayloadHash(mutation: DurableMutationRecord): ByteArray =
        when (mutation.kind) {
            DurableMutationKind.GENERATE -> {
                val intent = mutation.generateIntent!!
                NormalizedWireCodec.payloadHash(
                    GenerateRequestPayload(
                        mutation.mutationId,
                        intent.logicalNameHash,
                        intent.challenge,
                        intent.keySpec,
                    )
                )
            }
            DurableMutationKind.DELETE ->
                NormalizedWireCodec.payloadHash(
                    DeleteRequestPayload(
                        mutation.mutationId,
                        authenticator.createKeyHandle(mutation.scope, mutation.keyId),
                    )
                )
        }

    fun quarantine(cause: Throwable? = null): Nothing {
        globallyQuarantined = true
        snapshot = null
        reloadRequired = false
        throw DonorLifecycleRepositoryException.GlobalQuarantine().also {
            if (cause != null) it.addSuppressed(cause)
        }
    }

    fun unavailable(cause: Throwable): Nothing {
        throw DonorLifecycleRepositoryException.Unavailable(cause)
    }

    private fun validatePersistedHashes(candidate: DonorStateSnapshot) {
        candidate.mutations.forEach { mutation ->
            if (!MessageDigest.isEqual(mutation.payloadHash, expectedPayloadHash(mutation))) {
                quarantine()
            }
        }
    }

    private fun handleLoadFailure(failure: Throwable): Nothing {
        if (failure.isStateIntegrityFailure()) quarantine(failure)
        unavailable(failure)
    }

    private fun Throwable.isStateIntegrityFailure(): Boolean =
        this is DonorStateCorruptionException ||
            this is DonorStateQuarantineException ||
            this is DonorStateBlobStoreException ||
            this is HandleAuthenticatorException
}
