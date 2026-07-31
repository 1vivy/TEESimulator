package org.matrix.TEESimulator.rka.candidate

import java.security.SecureRandom

class RemoteCandidateService(
    private val admittedIdentity: IdentityHash,
    private val backend: RemoteCandidateBackend,
    private val store: RemoteCandidateStore,
    private val handleSource: () -> RemoteKeyHandle = {
        RemoteKeyHandle.of(ByteArray(16).also(SecureRandom()::nextBytes))
    },
) {
    private data class LiveOperation(
        val keyId: CandidateKeyId,
        val handle: RemoteOperationHandle,
        var state: CandidateOperationState,
        var totalInput: Int = 0,
    )

    private val operations = linkedMapOf<RemoteOperationHandle, LiveOperation>()
    private val operationStates = linkedMapOf<RemoteOperationHandle, CandidateOperationState>()

    init {
        store.operationStates().forEach { persisted ->
            val reconciled =
                if (persisted.state == CandidateOperationState.OPEN) {
                    persisted
                        .copy(state = CandidateOperationState.LOST)
                        .also(store::replaceOperation)
                } else {
                    persisted
                }
            operationStates[reconciled.handle] = reconciled.state
        }
    }

    @Synchronized
    fun resolve(uid: Int, namespace: Long): CandidateKeyId? =
        store
            .all()
            .firstOrNull {
                it.id.uid == uid &&
                    it.id.namespace == namespace &&
                    it.state != CandidateKeyState.DELETED
            }
            ?.id

    @Synchronized
    fun generate(request: CandidateGenerateRequest): CandidateRoute<CandidateKeyRecord> {
        if (request.identityHash != admittedIdentity) return CandidateRoute.PassThrough
        shapeError(request.shape)?.let {
            return CandidateRoute.Remote(CandidateResult.Failure(it))
        }
        if (store.find(request.id) != null) {
            return CandidateRoute.Remote(CandidateResult.Failure(CandidateError.STALE_HANDLE))
        }
        val aliasHandle = handleSource()
        val generated =
            backend.generate(
                RemoteGenerateCommand(
                    aliasHandle,
                    request.identityHash,
                    request.shape.copiedChallenge(),
                )
            )
        if (generated is CandidateResult.Failure) return CandidateRoute.Remote(generated)
        val material = (generated as CandidateResult.Success).value
        if (
            material.handle != aliasHandle ||
                material.characteristics != CandidateCharacteristics.foreground()
        ) {
            return CandidateRoute.Remote(CandidateResult.Failure(CandidateError.QUARANTINED))
        }
        val record =
            runCatching {
                    CandidateKeyRecord(
                        request.id,
                        request.identityHash,
                        material.donorEpoch,
                        material.profileEpoch,
                        material.handle,
                        material.certificateChain,
                        material.characteristics,
                        CandidateKeyState.ACTIVE,
                    )
                }
                .getOrElse {
                    return CandidateRoute.Remote(
                        CandidateResult.Failure(CandidateError.QUARANTINED)
                    )
                }
        store.replace(record)
        return CandidateRoute.Remote(CandidateResult.Success(record))
    }

    @Synchronized
    fun get(uid: Int, id: CandidateKeyId): CandidateRoute<CandidateKeyRecord> {
        val record = store.find(id) ?: return CandidateRoute.PassThrough
        ownershipError(uid, record)?.let {
            return CandidateRoute.Remote(CandidateResult.Failure(it))
        }
        val fetched = backend.get(record.remoteHandle)
        return CandidateRoute.Remote(
            if (fetched is CandidateResult.Failure) fetched else CandidateResult.Success(record)
        )
    }

    @Synchronized
    fun list(uid: Int, identityHash: IdentityHash): CandidateRoute<List<CandidateKeyRecord>> {
        if (identityHash != admittedIdentity) return CandidateRoute.PassThrough
        val records =
            store.all().filter {
                it.id.uid == uid &&
                    it.identityHash == identityHash &&
                    it.state != CandidateKeyState.DELETED
            }
        val listed = backend.list(identityHash)
        if (listed is CandidateResult.Failure) return CandidateRoute.Remote(listed)
        val handles = (listed as CandidateResult.Success).value.toSet()
        if (records.any { it.remoteHandle !in handles }) {
            return CandidateRoute.Remote(CandidateResult.Failure(CandidateError.QUARANTINED))
        }
        return CandidateRoute.Remote(CandidateResult.Success(records.sortedBy { it.id.alias }))
    }

    @Synchronized
    fun delete(uid: Int, id: CandidateKeyId): CandidateRoute<Unit> {
        val record = store.find(id) ?: return CandidateRoute.PassThrough
        ownershipError(uid, record)?.let {
            return CandidateRoute.Remote(CandidateResult.Failure(it))
        }
        val deleted = backend.delete(record.remoteHandle)
        if (deleted is CandidateResult.Success) {
            store.replace(record.withState(CandidateKeyState.DELETED))
        }
        return CandidateRoute.Remote(deleted)
    }

    @Synchronized
    fun grant(uid: Int, id: CandidateKeyId, granteeUid: Int): CandidateRoute<Unit> {
        val record = store.find(id) ?: return CandidateRoute.PassThrough
        ownershipError(uid, record)?.let {
            return CandidateRoute.Remote(CandidateResult.Failure(it))
        }
        return CandidateRoute.Remote(
            CandidateResult.Failure(CandidateError.CROSS_UID_GRANT_UNSUPPORTED)
        )
    }

    @Synchronized
    fun begin(uid: Int, id: CandidateKeyId): CandidateRoute<RemoteOperationHandle> {
        val record = store.find(id) ?: return CandidateRoute.PassThrough
        ownershipError(uid, record)?.let {
            return CandidateRoute.Remote(CandidateResult.Failure(it))
        }
        if (record.state != CandidateKeyState.ACTIVE || operations.values.any { it.keyId == id }) {
            return CandidateRoute.Remote(CandidateResult.Failure(CandidateError.CAPACITY))
        }
        val begun = backend.begin(record.remoteHandle)
        if (begun is CandidateResult.Success) {
            val handle = begun.value
            if (handle in operationStates) {
                return CandidateRoute.Remote(CandidateResult.Failure(CandidateError.QUARANTINED))
            }
            operations[handle] = LiveOperation(id, handle, CandidateOperationState.OPEN)
            operationStates[handle] = CandidateOperationState.OPEN
            store.replaceOperation(
                CandidateOperationRecord(handle, id, CandidateOperationState.OPEN)
            )
        }
        return CandidateRoute.Remote(begun)
    }

    @Synchronized
    fun updateAad(handle: RemoteOperationHandle, input: ByteArray) =
        withOperation(handle, input) { backend.updateAad(handle, input.copyOf()) }

    @Synchronized
    fun update(handle: RemoteOperationHandle, input: ByteArray) =
        withOperation(handle, input) { backend.update(handle, input.copyOf()) }

    @Synchronized
    fun finish(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<ByteArray> {
        val operation = openOperation(handle) ?: return lostOrStale(handle)
        if (!bounded(operation, input))
            return CandidateResult.Failure(CandidateError.INVALID_REQUEST)
        return when (val finished = backend.finish(handle, input.copyOf())) {
            is CandidateResult.Failure -> markFailure(operation, finished)
            is CandidateResult.Success -> {
                operation.state = CandidateOperationState.FINISHED
                operationStates[handle] = operation.state
                store.replaceOperation(
                    CandidateOperationRecord(handle, operation.keyId, operation.state)
                )
                operations.remove(handle)
                store.find(operation.keyId)?.let {
                    store.replace(it.withState(CandidateKeyState.CONSUMED))
                }
                CandidateResult.Success(finished.value.copyOf())
            }
        }
    }

    @Synchronized
    fun abort(handle: RemoteOperationHandle): CandidateResult<Unit> {
        val operation = openOperation(handle) ?: return lostOrStale(handle)
        return when (val aborted = backend.abort(handle)) {
            is CandidateResult.Failure -> markFailure(operation, aborted)
            is CandidateResult.Success -> {
                operation.state = CandidateOperationState.ABORTED
                operationStates[handle] = operation.state
                store.replaceOperation(
                    CandidateOperationRecord(handle, operation.keyId, operation.state)
                )
                operations.remove(handle)
                aborted
            }
        }
    }

    @Synchronized
    fun peerDied() {
        backend.peerDied()
        operations.values.forEach {
            it.state = CandidateOperationState.LOST
            operationStates[it.handle] = CandidateOperationState.LOST
            store.replaceOperation(
                CandidateOperationRecord(it.handle, it.keyId, CandidateOperationState.LOST)
            )
        }
        operations.clear()
    }

    private fun withOperation(
        handle: RemoteOperationHandle,
        input: ByteArray,
        action: () -> CandidateResult<Unit>,
    ): CandidateResult<Unit> {
        val operation = openOperation(handle) ?: return lostOrStale(handle)
        if (!bounded(operation, input))
            return CandidateResult.Failure(CandidateError.INVALID_REQUEST)
        val result = action()
        return if (result is CandidateResult.Failure) markFailure(operation, result) else result
    }

    private fun bounded(operation: LiveOperation, input: ByteArray): Boolean {
        if (input.size > 65_536 || operation.totalInput + input.size > 1_048_576) return false
        operation.totalInput += input.size
        return true
    }

    private fun openOperation(handle: RemoteOperationHandle) =
        operations[handle]?.takeIf { it.state == CandidateOperationState.OPEN }

    private fun <T> lostOrStale(handle: RemoteOperationHandle): CandidateResult<T> =
        CandidateResult.Failure(
            if (operationStates[handle] == CandidateOperationState.LOST)
                CandidateError.OPERATION_LOST
            else CandidateError.STALE_HANDLE
        )

    private fun <T> markFailure(
        operation: LiveOperation,
        failure: CandidateResult.Failure,
    ): CandidateResult<T> {
        if (
            failure.error == CandidateError.TRANSPORT ||
                failure.error == CandidateError.OPERATION_LOST
        ) {
            operation.state = CandidateOperationState.LOST
            operationStates[operation.handle] = operation.state
            store.replaceOperation(
                CandidateOperationRecord(operation.handle, operation.keyId, operation.state)
            )
            operations.remove(operation.handle)
        }
        return failure
    }

    private fun ownershipError(uid: Int, record: CandidateKeyRecord) =
        when {
            uid != record.id.uid -> CandidateError.POLICY_REJECTED
            record.state == CandidateKeyState.DELETED -> CandidateError.STALE_HANDLE
            else -> null
        }

    private fun shapeError(shape: CandidateKeyShape): CandidateError? =
        when {
            shape.algorithm != CandidateAlgorithm.EC -> CandidateError.UNSUPPORTED_ALGORITHM
            shape.curve != CandidateCurve.P256 -> CandidateError.UNSUPPORTED_EC_CURVE
            shape.purpose != CandidatePurpose.SIGN -> CandidateError.UNSUPPORTED_PURPOSE
            shape.digest != CandidateDigest.SHA256 -> CandidateError.UNSUPPORTED_DIGEST
            shape.securityLevel != CandidateSecurityLevel.TEE -> CandidateError.POLICY_REJECTED
            shape.challenge.isEmpty() || shape.challenge.size > 128 * 1024 ->
                CandidateError.INVALID_REQUEST
            else -> null
        }
}
