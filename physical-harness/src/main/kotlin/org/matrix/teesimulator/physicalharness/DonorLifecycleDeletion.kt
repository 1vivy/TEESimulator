package org.matrix.teesimulator.physicalharness

import java.security.MessageDigest
import java.util.UUID
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.KeyState

internal class DonorLifecycleDeletion(private val context: DonorLifecycleRepositoryContext) {
    fun execute(scope: HandleScope, command: BackendDelete) {
        val replay = findMutation(scope, command.deletionId)
        if (replay != null) {
            if (!MessageDigest.isEqual(replay.payloadHash, command.payloadHash)) replayConflict()
            when (replay.phase) {
                DurableMutationPhase.COMMITTED -> return
                DurableMutationPhase.PREPARED -> {
                    reconcile(replay, failOnQuarantine = true)
                    return
                }
                DurableMutationPhase.QUARANTINED -> invalidState()
            }
        }
        val key =
            context.state.keys.singleOrNull { it.keyId == command.handle.id } ?: invalidHandle()
        when (key.state) {
            KeyState.ACTIVE,
            KeyState.SUPERSEDED -> prepareLiveDeletion(key, scope, command)
            KeyState.DELETED -> commitDeletedReplay(key, scope, command)
            KeyState.CREATING,
            KeyState.DELETE_PENDING,
            KeyState.QUARANTINED,
            KeyState.ABSENT -> invalidState()
        }
    }

    fun reconcile(mutation: DurableMutationRecord, failOnQuarantine: Boolean) {
        context.requireWritable()
        val key = context.state.keys.single { it.keyId == mutation.keyId }
        val expected = key.metadata ?: invalidState()
        when (val inspection = inspect(key, expected)) {
            DurableKeyInspection.Absent -> commit(key, mutation)
            DurableKeyInspection.Rejected -> quarantine(key, mutation, failOnQuarantine)
            is DurableKeyInspection.Verified -> {
                if (!metadataMaterialEquals(inspection.metadata, expected)) {
                    quarantine(key, mutation, failOnQuarantine)
                    return
                }
                when (
                    val outcome =
                        context.keyStoreCall {
                            context.keyStore.deleteIfExact(
                                key.internalAlias,
                                key.scope.caller,
                                expected,
                            )
                        }
                ) {
                    DurableDeleteOutcome.ABSENT,
                    DurableDeleteOutcome.DELETED -> commit(key, mutation)
                    DurableDeleteOutcome.MISMATCH -> quarantine(key, mutation, failOnQuarantine)
                }
            }
        }
    }

    fun recoverDeleted(key: DurableKeyRecord): Boolean {
        val expected = key.metadata ?: invalidState()
        return when (val inspection = inspect(key, expected)) {
            DurableKeyInspection.Absent -> false
            DurableKeyInspection.Rejected -> {
                quarantineDeleted(key)
                false
            }
            is DurableKeyInspection.Verified -> {
                if (!metadataMaterialEquals(inspection.metadata, expected)) {
                    quarantineDeleted(key)
                    false
                } else {
                    context.requireWritable()
                    when (
                        context.keyStoreCall {
                            context.keyStore.deleteIfExact(
                                key.internalAlias,
                                key.scope.caller,
                                expected,
                            )
                        }
                    ) {
                        DurableDeleteOutcome.ABSENT,
                        DurableDeleteOutcome.DELETED -> true
                        DurableDeleteOutcome.MISMATCH -> {
                            quarantineDeleted(key)
                            false
                        }
                    }
                }
            }
        }
    }

    private fun prepareLiveDeletion(
        key: DurableKeyRecord,
        scope: HandleScope,
        command: BackendDelete,
    ) {
        context.requireWritable()
        val expected = key.metadata ?: invalidState()
        when (val inspection = inspect(key, expected)) {
            DurableKeyInspection.Absent,
            DurableKeyInspection.Rejected -> quarantineNew(key, scope, command)
            is DurableKeyInspection.Verified -> {
                if (!metadataMaterialEquals(inspection.metadata, expected)) {
                    quarantineNew(key, scope, command)
                    return
                }
                val pendingKey = key.withState(KeyState.DELETE_PENDING)
                val pendingMutation = newMutation(scope, command, DurableMutationPhase.PREPARED)
                context.save(
                    context.state.keys.map { if (it.keyId == key.keyId) pendingKey else it },
                    context.state.mutations + pendingMutation,
                )
                reconcile(pendingMutation, failOnQuarantine = true)
            }
        }
    }

    private fun commitDeletedReplay(
        key: DurableKeyRecord,
        scope: HandleScope,
        command: BackendDelete,
    ) {
        context.save(
            context.state.keys,
            context.state.mutations +
                newMutation(scope, command, DurableMutationPhase.COMMITTED, key.keyId),
        )
    }

    private fun commit(key: DurableKeyRecord, mutation: DurableMutationRecord) {
        val deletedKey = key.withState(KeyState.DELETED)
        val committedMutation = mutation.withPhase(DurableMutationPhase.COMMITTED)
        replace(key, mutation, deletedKey, committedMutation)
    }

    private fun quarantine(
        key: DurableKeyRecord,
        mutation: DurableMutationRecord,
        failOnQuarantine: Boolean,
    ) {
        val quarantinedKey = key.withState(KeyState.QUARANTINED)
        replace(key, mutation, quarantinedKey, mutation.withPhase(DurableMutationPhase.QUARANTINED))
        if (failOnQuarantine) invalidState()
    }

    private fun quarantineNew(key: DurableKeyRecord, scope: HandleScope, command: BackendDelete) {
        val quarantinedKey = key.withState(KeyState.QUARANTINED)
        context.save(
            context.state.keys.map { if (it.keyId == key.keyId) quarantinedKey else it },
            context.state.mutations +
                newMutation(scope, command, DurableMutationPhase.QUARANTINED, key.keyId),
        )
        invalidState()
    }

    private fun quarantineDeleted(key: DurableKeyRecord) {
        context.requireWritable()
        val quarantined = key.withState(KeyState.QUARANTINED)
        context.save(
            context.state.keys.map { if (it.keyId == key.keyId) quarantined else it },
            context.state.mutations,
        )
    }

    private fun replace(
        key: DurableKeyRecord,
        mutation: DurableMutationRecord,
        replacementKey: DurableKeyRecord,
        replacementMutation: DurableMutationRecord,
    ) {
        context.save(
            context.state.keys.map { if (it.keyId == key.keyId) replacementKey else it },
            context.state.mutations.map {
                if (
                    it.kind == mutation.kind &&
                        it.scope == mutation.scope &&
                        it.mutationId == mutation.mutationId
                ) {
                    replacementMutation
                } else {
                    it
                }
            },
        )
    }

    private fun inspect(
        key: DurableKeyRecord,
        expected: org.matrix.teesimulator.twophone.WireKeyMetadata,
    ): DurableKeyInspection =
        context.keyStoreCall {
            context.keyStore.inspect(
                key.internalAlias,
                key.scope.caller,
                expected.attestationChallenge,
            )
        }

    private fun newMutation(
        scope: HandleScope,
        command: BackendDelete,
        phase: DurableMutationPhase,
        keyId: UUID = command.handle.id,
    ) =
        DurableMutationRecord(
            DurableMutationKind.DELETE,
            phase,
            scope,
            command.deletionId,
            command.payloadHash,
            keyId,
            null,
        )

    private fun findMutation(scope: HandleScope, id: UUID): DurableMutationRecord? =
        context.state.mutations.singleOrNull {
            it.scope == scope && it.kind == DurableMutationKind.DELETE && it.mutationId == id
        }

    private fun replayConflict(): Nothing = throw DonorLifecycleRepositoryException.ReplayConflict()

    private fun invalidHandle(): Nothing = throw DonorLifecycleRepositoryException.InvalidHandle()

    private fun invalidState(): Nothing = throw DonorLifecycleRepositoryException.InvalidState()
}
