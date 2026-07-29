package org.matrix.teesimulator.physicalharness

import android.content.Context
import java.security.MessageDigest
import java.util.UUID
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.BackendGeneratedKey
import org.matrix.teesimulator.twophone.DeleteRequestPayload
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata

internal class DonorLifecycleRepository(
    stateStore: AuthenticatedDonorStateStore,
    keyStore: DurableAndroidKeyStore,
    private val authenticator: HandleAuthenticator,
    keyIdFactory: () -> UUID = UUID::randomUUID,
) {
    constructor(
        context: Context,
        mac: HandleMac,
    ) : this(
        CodecAuthenticatedDonorStateStore(
            AtomicFileDonorStateBlobStore(context),
            DonorStateCodec(mac),
        ),
        AndroidKeystoreDurableKeyStore(AndroidKeystoreDonor(context)),
        HandleAuthenticator(mac),
    )

    private val monitor = Any()
    private val context = DonorLifecycleRepositoryContext(stateStore, keyStore, authenticator)
    private val generation = DonorLifecycleGeneration(context, keyIdFactory)
    private val deletion = DonorLifecycleDeletion(context)
    private val recovery = DonorLifecycleRecovery(context, generation, deletion)
    private var recoveryRequired = false

    fun recover() {
        synchronized(monitor) {
            context.requireNotQuarantined()
            recoveryRequired = true
            context.ensureLoaded()
            runRequiredRecovery()
        }
    }

    fun generate(scope: HandleScope, command: BackendGenerate): BackendGeneratedKey =
        synchronized(monitor) {
            context.requireNotQuarantined()
            generation.validate(scope, command)
            ensureReady()
            generation.execute(scope, command)
        }

    fun metadata(scope: HandleScope, handle: WireKeyHandle): WireKeyMetadata =
        synchronized(monitor) {
            context.requireNotQuarantined()
            verifyHandle(scope, handle)
            ensureReady()
            val key = keyFor(handle)
            when (key.state) {
                KeyState.ACTIVE,
                KeyState.SUPERSEDED,
                KeyState.DELETE_PENDING,
                KeyState.DELETED -> key.metadata ?: invalidState()
                KeyState.CREATING,
                KeyState.QUARANTINED,
                KeyState.ABSENT -> invalidState()
            }
        }

    fun resolveForBegin(scope: HandleScope, handle: WireKeyHandle): ResolvedDonorKey =
        synchronized(monitor) {
            context.requireNotQuarantined()
            verifyHandle(scope, handle)
            ensureReady()
            val key = keyFor(handle)
            if (key.state != KeyState.ACTIVE && key.state != KeyState.SUPERSEDED) invalidState()
            ResolvedDonorKey(key.keyId, key.internalAlias, key.metadata ?: invalidState())
        }

    fun delete(scope: HandleScope, command: BackendDelete) {
        synchronized(monitor) {
            context.requireNotQuarantined()
            validateDelete(scope, command)
            ensureReady()
            deletion.execute(scope, command)
        }
    }

    private fun ensureReady() {
        val loaded = context.ensureLoaded()
        if (loaded) recoveryRequired = true
        if (
            recoveryRequired ||
                context.state.mutations.any { it.phase == DurableMutationPhase.PREPARED }
        ) {
            runRequiredRecovery()
        }
    }

    private fun runRequiredRecovery() {
        recovery.recover()
        recoveryRequired = false
    }

    private fun validateDelete(scope: HandleScope, command: BackendDelete) {
        if (scope.caller != command.caller) invalidHandle()
        verifyHandle(scope, command.handle)
        val deterministicHandle = authenticator.createKeyHandle(scope, command.handle.id)
        val expected =
            NormalizedWireCodec.payloadHash(
                DeleteRequestPayload(command.deletionId, deterministicHandle)
            )
        if (!MessageDigest.isEqual(expected, command.payloadHash)) {
            throw DonorLifecycleRepositoryException.ReplayConflict()
        }
    }

    private fun verifyHandle(scope: HandleScope, handle: WireKeyHandle) {
        if (!authenticator.verifyKeyHandle(scope, handle.id, handle)) invalidHandle()
    }

    private fun keyFor(handle: WireKeyHandle): DurableKeyRecord =
        context.state.keys.singleOrNull { it.keyId == handle.id } ?: invalidHandle()

    private fun invalidHandle(): Nothing = throw DonorLifecycleRepositoryException.InvalidHandle()

    private fun invalidState(): Nothing = throw DonorLifecycleRepositoryException.InvalidState()
}
