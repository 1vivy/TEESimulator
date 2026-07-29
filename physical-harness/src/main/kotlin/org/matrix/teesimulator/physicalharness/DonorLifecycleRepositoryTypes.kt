package org.matrix.teesimulator.physicalharness

import java.util.UUID
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.WireKeyMetadata

sealed class DonorLifecycleRepositoryException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class ReplayConflict : DonorLifecycleRepositoryException("durable request replay conflict")

    class InvalidHandle : DonorLifecycleRepositoryException("invalid durable key handle")

    class InvalidState : DonorLifecycleRepositoryException("invalid durable key state")

    class GlobalQuarantine : DonorLifecycleRepositoryException("durable donor state quarantined")

    class Unavailable(cause: Throwable) :
        DonorLifecycleRepositoryException("durable donor unavailable", cause)

    class RevisionExhausted : DonorLifecycleRepositoryException("durable revision exhausted")
}

internal class ResolvedDonorKey(
    val keyId: UUID,
    val internalAlias: String,
    metadata: WireKeyMetadata,
) {
    private val stableMetadata = metadata.defensiveCopy()

    val metadata: WireKeyMetadata
        get() = stableMetadata.defensiveCopy()
}

internal fun WireKeyMetadata.withState(state: KeyState) =
    WireKeyMetadata(state, attestationChallenge, publicKey, certificateChain, keySpec)

internal fun DurableKeyRecord.withState(
    state: KeyState,
    metadata: WireKeyMetadata? = this.metadata?.withState(state),
) = DurableKeyRecord(keyId, scope, logicalNameHash, internalAlias, state, metadata)

internal fun DurableMutationRecord.withPhase(phase: DurableMutationPhase) =
    DurableMutationRecord(kind, phase, scope, mutationId, payloadHash, keyId, generateIntent)
