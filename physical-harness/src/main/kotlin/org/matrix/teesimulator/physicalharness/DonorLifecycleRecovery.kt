package org.matrix.teesimulator.physicalharness

import org.matrix.teesimulator.twophone.KeyState

internal class DonorLifecycleRecovery(
    private val context: DonorLifecycleRepositoryContext,
    private val generation: DonorLifecycleGeneration,
    private val deletion: DonorLifecycleDeletion,
) {
    fun recover() {
        verifyLiveKeys()
        val creating = context.state.keys.singleOrNull { it.state == KeyState.CREATING }
        if (creating != null) {
            val mutation =
                context.state.mutations.single {
                    it.keyId == creating.keyId &&
                        it.kind == DurableMutationKind.GENERATE &&
                        it.phase == DurableMutationPhase.PREPARED
                }
            generation.reconcile(mutation, failOnQuarantine = false)
        }
        val pending = context.state.keys.singleOrNull { it.state == KeyState.DELETE_PENDING }
        if (pending != null) {
            val mutation =
                context.state.mutations.single {
                    it.keyId == pending.keyId &&
                        it.kind == DurableMutationKind.DELETE &&
                        it.phase == DurableMutationPhase.PREPARED
                }
            deletion.reconcile(mutation, failOnQuarantine = false)
        }
        context.state.keys
            .filter { it.state == KeyState.DELETED }
            .forEach { key -> deletion.recoverDeleted(key) }
    }

    private fun verifyLiveKeys() {
        context.state.keys
            .filter { it.state == KeyState.ACTIVE || it.state == KeyState.SUPERSEDED }
            .forEach { key ->
                val expected = key.metadata ?: invalidState()
                val exact =
                    when (
                        val inspection =
                            context.keyStoreCall {
                                context.keyStore.inspect(
                                    key.internalAlias,
                                    key.scope.caller,
                                    expected.attestationChallenge,
                                )
                            }
                    ) {
                        DurableKeyInspection.Absent,
                        DurableKeyInspection.Rejected -> false
                        is DurableKeyInspection.Verified ->
                            metadataMaterialEquals(inspection.metadata, expected)
                    }
                if (!exact) {
                    quarantineLiveKey(key)
                }
            }
    }

    private fun quarantineLiveKey(key: DurableKeyRecord) {
        context.requireWritable()
        val generation =
            context.state.mutations.single {
                it.keyId == key.keyId && it.kind == DurableMutationKind.GENERATE
            }
        context.save(
            context.state.keys.map {
                if (it.keyId == key.keyId) it.withState(KeyState.QUARANTINED) else it
            },
            context.state.mutations.map {
                if (
                    it.kind == generation.kind &&
                        it.scope == generation.scope &&
                        it.mutationId == generation.mutationId
                ) {
                    it.withPhase(DurableMutationPhase.QUARANTINED)
                } else {
                    it
                }
            },
        )
    }

    private fun invalidState(): Nothing = throw DonorLifecycleRepositoryException.InvalidState()
}
