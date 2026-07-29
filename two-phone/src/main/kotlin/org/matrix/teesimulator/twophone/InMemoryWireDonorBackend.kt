package org.matrix.teesimulator.twophone

import java.security.MessageDigest
import java.util.UUID

class InMemoryWireDonorBackend(
    private val pair: PairIdentity,
    rootAdapter: FakeDonorAdapter,
    private val store: InMemoryWireDonorStore = InMemoryWireDonorStore(),
) : WireDonorBackend {
    private val donor = rootAdapter.forPresentedPair(pair)
    private val lifecycleMonitor = Any()
    private val openedOperations = mutableMapOf<UUID, OpenedOperation>()
    private var closed = false

    override fun generate(command: BackendGenerate): BackendGeneratedKey = active {
        mapFailures(WireErrorCode.INVALID_HANDLE) {
            synchronized(store.monitor) {
                val key =
                    mutationKey(WireMutationKind.GENERATE, command.generationId, command.caller)
                store.mutationJournal[key]?.let { stored ->
                    if (!stored.matches(command.payloadHash)) {
                        fail(WireErrorCode.REPLAY_CONFLICT)
                    }
                    val replay =
                        stored as? StoredBackendGeneration ?: fail(WireErrorCode.INTERNAL_ERROR)
                    return@synchronized replay.result()
                }

                val generated =
                    donor.generate(
                        GenerateRequest(
                            internalLogicalName(command.caller, command.logicalNameHash),
                            command.challenge,
                            command.caller.toHost(),
                        )
                    )
                val handle = generated.handle.toWire()
                val state = donor.metadata(generated.handle, command.caller.toHost()).state
                val metadata =
                    WireKeyMetadata(
                        state,
                        generated.attestationChallenge,
                        generated.publicKey,
                        generated.certificateChain,
                        command.keySpec,
                    )
                store.metadataByKeyId[handle.id] = metadata.defensiveCopy()
                val result = BackendGeneratedKey(handle, metadata)
                store.mutationJournal[key] = StoredBackendGeneration(command.payloadHash, result)
                result
            }
        }
    }

    override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata =
        active {
            mapFailures(WireErrorCode.INVALID_HANDLE) {
                synchronized(store.monitor) {
                    store.beforeMetadataDonorReadForTest?.invoke()
                    val safeHandle = handle.defensiveCopy()
                    val donorMetadata = donor.metadata(safeHandle.toHost(), caller.toHost())
                    val stored =
                        store.metadataByKeyId[safeHandle.id] ?: fail(WireErrorCode.INVALID_HANDLE)
                    val complete =
                        WireKeyMetadata(
                            donorMetadata.state,
                            stored.attestationChallenge,
                            donorMetadata.publicKey,
                            stored.certificateChain,
                            stored.keySpec,
                        )
                    store.metadataByKeyId[safeHandle.id] = complete.defensiveCopy()
                    complete.defensiveCopy()
                }
            }
        }

    override fun delete(command: BackendDelete) {
        active {
            mapFailures(WireErrorCode.INVALID_HANDLE) {
                synchronized(store.monitor) {
                    val key =
                        mutationKey(WireMutationKind.DELETE, command.deletionId, command.caller)
                    store.mutationJournal[key]?.let { stored ->
                        if (!stored.matches(command.payloadHash)) {
                            fail(WireErrorCode.REPLAY_CONFLICT)
                        }
                        if (stored !is StoredBackendDeletion) {
                            fail(WireErrorCode.INTERNAL_ERROR)
                        }
                        return@synchronized
                    }

                    val handle = command.handle
                    val hostHandle = handle.toHost()
                    donor.metadata(hostHandle, command.caller.toHost())
                    val storedMetadata =
                        store.metadataByKeyId[handle.id] ?: fail(WireErrorCode.INVALID_HANDLE)
                    donor.delete(hostHandle, command.caller.toHost())
                    val deleted = donor.metadata(hostHandle, command.caller.toHost())
                    store.metadataByKeyId[handle.id] =
                        WireKeyMetadata(
                            deleted.state,
                            storedMetadata.attestationChallenge,
                            deleted.publicKey,
                            storedMetadata.certificateChain,
                            storedMetadata.keySpec,
                        )
                    store.mutationJournal[key] = StoredBackendDeletion(command.payloadHash)
                }
            }
        }
    }

    override fun begin(
        handle: WireKeyHandle,
        spec: WireOperationSpec,
        caller: WireCallerIdentity,
    ): WireOperationHandle = active {
        mapFailures(WireErrorCode.INVALID_HANDLE) {
            require(spec.purpose == WireKeyPurpose.SIGN && spec.digest == WireDigest.SHA256)
            val operation = donor.begin(handle.defensiveCopy().toHost(), caller.toHost()).toWire()
            openedOperations[operation.id] = OpenedOperation(operation, caller)
            operation.defensiveCopy()
        }
    }

    override fun update(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray = active {
        withOpenedOperation(operation, caller, removeAfterSuccess = false) { opened ->
            store.beforeOperationDonorCallForTest?.invoke()
            donor.update(opened.handle.toHost(), opened.caller.toHost(), input.copyOf()).copyOf()
        }
    }

    override fun finish(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray = active {
        withOpenedOperation(operation, caller, removeAfterSuccess = true) { opened ->
            store.beforeOperationDonorCallForTest?.invoke()
            donor.finish(opened.handle.toHost(), opened.caller.toHost(), input.copyOf()).copyOf()
        }
    }

    override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) {
        active {
            withOpenedOperation(operation, caller, removeAfterSuccess = true) { opened ->
                store.beforeOperationDonorCallForTest?.invoke()
                donor.abort(opened.handle.toHost(), opened.caller.toHost())
            }
        }
    }

    override fun close() {
        synchronized(lifecycleMonitor) {
            if (closed) return
            closed = true
            val opened = openedOperations.values.toList()
            openedOperations.clear()
            opened.forEach(::closeOperation)
        }
    }

    private fun closeOperation(operation: OpenedOperation): CleanupResult = runCleanup {
        val host = operation.handle.toHost()
        if (donor.operationState(host).isOpen()) {
            val caller = operation.caller.toHost()
            store.closeAbortForTest?.invoke(host, caller) ?: donor.abort(host, caller)
        }
    }

    private fun abortAfterOperationFailure(operation: OpenedOperation): CleanupResult = runCleanup {
        val host = operation.handle.toHost()
        if (donor.operationState(host).isOpen()) {
            donor.abort(host, operation.caller.toHost())
        }
    }

    private inline fun runCleanup(block: () -> Unit): CleanupResult =
        try {
            block()
            CleanupResult.Completed
        } catch (failure: RuntimeException) {
            CleanupResult.Failed(failure)
        }

    private inline fun <T> active(block: () -> T): T =
        synchronized(lifecycleMonitor) {
            if (closed) fail(WireErrorCode.DONOR_UNAVAILABLE)
            block()
        }

    private inline fun <T> mapFailures(copiedHandleCode: WireErrorCode, block: () -> T): T =
        try {
            block()
        } catch (failure: WireBackendFailure) {
            throw failure
        } catch (failure: DonorException.WrongCaller) {
            throw WireBackendFailure(WireErrorCode.WRONG_CALLER, failure)
        } catch (failure: DonorException.WrongPair) {
            throw WireBackendFailure(WireErrorCode.WRONG_PAIR, failure)
        } catch (failure: DonorException.CopiedHandle) {
            throw WireBackendFailure(copiedHandleCode, failure)
        } catch (failure: DonorException.InvalidState) {
            throw WireBackendFailure(WireErrorCode.INVALID_STATE, failure)
        } catch (failure: IllegalArgumentException) {
            throw WireBackendFailure(WireErrorCode.INVALID_ARGUMENT, failure)
        } catch (failure: RuntimeException) {
            throw WireBackendFailure(WireErrorCode.INTERNAL_ERROR, failure)
        }

    private inline fun <T> withOpenedOperation(
        operation: WireOperationHandle,
        caller: WireCallerIdentity,
        removeAfterSuccess: Boolean,
        block: (OpenedOperation) -> T,
    ): T {
        val opened = requireOpenedOperation(operation, caller)
        return try {
            val result = mapFailures(WireErrorCode.INVALID_OPERATION_HANDLE) { block(opened) }
            if (removeAfterSuccess) {
                openedOperations.remove(opened.handle.id)
            }
            result
        } catch (failure: WireBackendFailure) {
            val cleanup = abortAfterOperationFailure(opened)
            openedOperations.remove(opened.handle.id)
            if (cleanup is CleanupResult.Failed && cleanup.failure !== failure) {
                failure.addSuppressed(cleanup.failure)
            }
            throw failure
        }
    }

    private fun requireOpenedOperation(
        operation: WireOperationHandle,
        caller: WireCallerIdentity,
    ): OpenedOperation {
        val opened = openedOperations[operation.id] ?: fail(WireErrorCode.INVALID_OPERATION_HANDLE)
        if (!opened.matches(operation)) {
            fail(WireErrorCode.INVALID_OPERATION_HANDLE)
        }
        if (opened.caller != caller) {
            fail(WireErrorCode.WRONG_CALLER)
        }
        return opened
    }

    private fun mutationKey(kind: WireMutationKind, id: UUID, caller: WireCallerIdentity) =
        WireMutationKey(
            pair.targetPin,
            pair.donorPin,
            caller.signingCertificateDigest,
            caller.attestationApplicationIdDigest,
            kind,
            id,
        )

    private fun internalLogicalName(
        caller: WireCallerIdentity,
        logicalNameHash: ByteArray,
    ): String =
        "wire-v1-" +
            canonicalBytes(
                    "wire-logical-name-v1".encodeToByteArray(),
                    pair.targetPin.encodeToByteArray(),
                    pair.donorPin.encodeToByteArray(),
                    caller.signingCertificateDigest.encodeToByteArray(),
                    caller.attestationApplicationIdDigest.encodeToByteArray(),
                    logicalNameHash,
                )
                .sha256()
                .toHex()

    private class OpenedOperation(handle: WireOperationHandle, val caller: WireCallerIdentity) {
        val handle = handle.defensiveCopy()

        fun matches(presented: WireOperationHandle): Boolean =
            handle.id == presented.id &&
                handle.keyId == presented.keyId &&
                MessageDigest.isEqual(handle.binding, presented.binding)
    }

    private sealed interface CleanupResult {
        data object Completed : CleanupResult

        class Failed(val failure: RuntimeException) : CleanupResult
    }

    private companion object {
        fun fail(code: WireErrorCode): Nothing = throw WireBackendFailure(code)
    }
}

private fun WireCallerIdentity.toHost() =
    CallerIdentity(0, signingCertificateDigest, attestationApplicationIdDigest)

private fun WireKeyHandle.toHost() = KeyHandle(id, binding)

private fun KeyHandle.toWire() = WireKeyHandle(id, binding)

private fun WireOperationHandle.toHost() = OperationHandle(id, keyId, binding)

private fun OperationHandle.toWire() = WireOperationHandle(id, keyId, binding)

private fun OperationState.isOpen(): Boolean =
    this == OperationState.BEGUN ||
        this == OperationState.AAD ||
        this == OperationState.DATA ||
        this == OperationState.FINISHING

class InMemoryWireDonorStore {
    internal val monitor = Any()
    internal val mutationJournal = mutableMapOf<WireMutationKey, StoredBackendMutation>()
    internal val metadataByKeyId = mutableMapOf<UUID, WireKeyMetadata>()
    internal var beforeMetadataDonorReadForTest: (() -> Unit)? = null
    internal var beforeOperationDonorCallForTest: (() -> Unit)? = null
    internal var closeAbortForTest: ((OperationHandle, CallerIdentity) -> Unit)? = null
}

internal enum class WireMutationKind {
    GENERATE,
    DELETE,
}

internal data class WireMutationKey(
    val targetPin: String,
    val donorPin: String,
    val signingCertificateDigest: String,
    val attestationApplicationIdDigest: String,
    val kind: WireMutationKind,
    val id: UUID,
)

internal sealed class StoredBackendMutation(payloadHash: ByteArray) {
    private val hashBytes = payloadHash.copyOf()

    fun matches(payloadHash: ByteArray): Boolean = MessageDigest.isEqual(hashBytes, payloadHash)
}

internal class StoredBackendGeneration(payloadHash: ByteArray, result: BackendGeneratedKey) :
    StoredBackendMutation(payloadHash) {
    private val storedResult = BackendGeneratedKey(result.handle, result.metadata)

    fun result(): BackendGeneratedKey =
        BackendGeneratedKey(storedResult.handle, storedResult.metadata)
}

internal class StoredBackendDeletion(payloadHash: ByteArray) : StoredBackendMutation(payloadHash)
