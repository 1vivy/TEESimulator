package org.matrix.teesimulator.physicalharness

import java.security.MessageDigest
import java.util.UUID
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.BackendGeneratedKey
import org.matrix.teesimulator.twophone.GenerateRequestPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.WireKeyMetadata

internal class DonorLifecycleGeneration(
    private val context: DonorLifecycleRepositoryContext,
    private val keyIdFactory: () -> UUID,
) {
    fun validate(scope: HandleScope, command: BackendGenerate) {
        if (scope.caller != command.caller) invalidState()
        val expected =
            NormalizedWireCodec.payloadHash(
                GenerateRequestPayload(
                    command.generationId,
                    command.logicalNameHash,
                    command.challenge,
                    command.keySpec,
                )
            )
        if (!MessageDigest.isEqual(expected, command.payloadHash)) replayConflict()
        requireFixedKeySpec(command.keySpec)
    }

    fun execute(scope: HandleScope, command: BackendGenerate): BackendGeneratedKey {
        val replay = findMutation(scope, command.generationId)
        if (replay != null) {
            if (!MessageDigest.isEqual(replay.payloadHash, command.payloadHash)) replayConflict()
            return when (replay.phase) {
                DurableMutationPhase.COMMITTED -> resultFor(replay)
                DurableMutationPhase.PREPARED ->
                    reconcile(replay, failOnQuarantine = true) ?: invalidState()
                DurableMutationPhase.QUARANTINED -> invalidState()
            }
        }
        context.requireWritable()
        val keyId = allocateKeyId()
        val alias = DonorKeyAliasPolicy.aliasFor(keyId)
        val preparedKey =
            DurableKeyRecord(keyId, scope, command.logicalNameHash, alias, KeyState.CREATING, null)
        val preparedMutation =
            DurableMutationRecord(
                DurableMutationKind.GENERATE,
                DurableMutationPhase.PREPARED,
                scope,
                command.generationId,
                command.payloadHash,
                keyId,
                GenerateIntent(command.logicalNameHash, command.challenge, command.keySpec),
            )
        val keys =
            context.state.keys.map { key ->
                if (key.state == KeyState.ACTIVE && sameLogicalIdentity(key, scope, command)) {
                    key.withState(KeyState.SUPERSEDED)
                } else {
                    key
                }
            } + preparedKey
        context.save(keys, context.state.mutations + preparedMutation)
        return reconcile(preparedMutation, failOnQuarantine = true) ?: invalidState()
    }

    fun reconcile(
        mutation: DurableMutationRecord,
        failOnQuarantine: Boolean,
    ): BackendGeneratedKey? {
        context.requireWritable()
        val key = context.state.keys.single { it.keyId == mutation.keyId }
        val intent = mutation.generateIntent!!
        val metadata =
            when (
                val inspection =
                    context.keyStoreCall {
                        context.keyStore.inspect(
                            key.internalAlias,
                            key.scope.caller,
                            intent.challenge,
                        )
                    }
            ) {
                DurableKeyInspection.Absent ->
                    try {
                        context.keyStore.generate(
                            key.internalAlias,
                            intent.challenge,
                            key.scope.caller,
                        )
                    } catch (_: AndroidKeystoreDonorException.AttestationRejected) {
                        quarantine(key, mutation)
                        if (failOnQuarantine) invalidState() else return null
                    } catch (failure: Throwable) {
                        context.unavailable(failure)
                    }
                is DurableKeyInspection.Verified -> inspection.metadata
                DurableKeyInspection.Rejected -> {
                    quarantine(key, mutation)
                    if (failOnQuarantine) invalidState() else return null
                }
            }
        if (!metadataMatchesIntent(metadata, intent)) {
            quarantine(key, mutation)
            if (failOnQuarantine) invalidState() else return null
        }
        val committedMetadata = metadata.withState(KeyState.ACTIVE)
        val committedKey = key.withState(KeyState.ACTIVE, committedMetadata)
        val committedMutation = mutation.withPhase(DurableMutationPhase.COMMITTED)
        context.save(
            context.state.keys.map { if (it.keyId == key.keyId) committedKey else it },
            context.state.mutations.map {
                if (
                    it.kind == mutation.kind &&
                        it.scope == mutation.scope &&
                        it.mutationId == mutation.mutationId
                ) {
                    committedMutation
                } else {
                    it
                }
            },
        )
        return BackendGeneratedKey(
            context.authenticator.createKeyHandle(key.scope, key.keyId),
            committedMetadata,
        )
    }

    fun resultFor(mutation: DurableMutationRecord): BackendGeneratedKey {
        val key = context.state.keys.single { it.keyId == mutation.keyId }
        val metadata = key.metadata ?: invalidState()
        return BackendGeneratedKey(
            context.authenticator.createKeyHandle(key.scope, key.keyId),
            metadata.withState(KeyState.ACTIVE),
        )
    }

    private fun quarantine(key: DurableKeyRecord, mutation: DurableMutationRecord) {
        val quarantinedKey = key.withState(KeyState.QUARANTINED, metadata = null)
        val quarantinedMutation = mutation.withPhase(DurableMutationPhase.QUARANTINED)
        context.save(
            context.state.keys.map { if (it.keyId == key.keyId) quarantinedKey else it },
            context.state.mutations.map {
                if (
                    it.kind == mutation.kind &&
                        it.scope == mutation.scope &&
                        it.mutationId == mutation.mutationId
                ) {
                    quarantinedMutation
                } else {
                    it
                }
            },
        )
    }

    private fun findMutation(scope: HandleScope, id: UUID): DurableMutationRecord? =
        context.state.mutations.singleOrNull {
            it.scope == scope && it.kind == DurableMutationKind.GENERATE && it.mutationId == id
        }

    private fun sameLogicalIdentity(
        key: DurableKeyRecord,
        scope: HandleScope,
        command: BackendGenerate,
    ): Boolean =
        key.scope == scope && MessageDigest.isEqual(key.logicalNameHash, command.logicalNameHash)

    private fun metadataMatchesIntent(metadata: WireKeyMetadata, intent: GenerateIntent): Boolean =
        MessageDigest.isEqual(metadata.attestationChallenge, intent.challenge) &&
            metadata.keySpec == intent.keySpec

    private fun allocateKeyId(): UUID {
        repeat(MAX_KEY_ID_ALLOCATION_ATTEMPTS) {
            val candidate = keyIdFactory()
            if (context.state.keys.none { it.keyId == candidate }) return candidate
        }
        context.unavailable(KeyIdAllocationFailure())
    }

    private fun replayConflict(): Nothing = throw DonorLifecycleRepositoryException.ReplayConflict()

    private fun invalidState(): Nothing = throw DonorLifecycleRepositoryException.InvalidState()

    private class KeyIdAllocationFailure : RuntimeException("durable key ID allocation failed")

    private companion object {
        const val MAX_KEY_ID_ALLOCATION_ATTEMPTS = 16
    }
}
