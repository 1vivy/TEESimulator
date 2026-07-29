package org.matrix.teesimulator.physicalharness

import java.util.UUID
import org.matrix.teesimulator.twophone.BackendDelete
import org.matrix.teesimulator.twophone.BackendGenerate
import org.matrix.teesimulator.twophone.BackendGeneratedKey
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireBackendFailure
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireDonorBackend
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec

class AndroidWireDonorBackend
internal constructor(
    sessionId: ByteArray,
    pair: PairIdentity,
    expectedCaller: WireCallerIdentity,
    private val repository: DonorLifecycleRepository,
    private val donor: AndroidKeystoreDonor,
    private val authenticator: HandleAuthenticator,
) : WireDonorBackend {
    private val sessionIdBytes = validateSessionId(sessionId)
    private val scope = HandleScope(pair, expectedCaller)
    private val lifecycleMonitor = Any()
    private val operations = mutableMapOf<UUID, SessionOperation>()
    private var closed = false

    override fun generate(command: BackendGenerate): BackendGeneratedKey = execute {
        requireCaller(command.caller)
        repository.generate(scope, command)
    }

    override fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata =
        execute {
            requireCaller(caller)
            repository.metadata(scope, handle)
        }

    override fun delete(command: BackendDelete) {
        execute {
            requireCaller(command.caller)
            repository.delete(scope, command)
        }
    }

    override fun begin(
        handle: WireKeyHandle,
        spec: WireOperationSpec,
        caller: WireCallerIdentity,
    ): WireOperationHandle = execute {
        requireCaller(caller)
        requireSupported(spec)
        val resolved = repository.resolveForBegin(scope, handle)
        val donorOperation = donor.begin(resolved.internalAlias, caller)
        try {
            val wireOperation =
                authenticator.createOperationHandle(
                    sessionIdBytes,
                    scope,
                    donorOperation.id,
                    resolved.keyId,
                )
            if (
                operations.putIfAbsent(donorOperation.id, SessionOperation(resolved.keyId)) != null
            ) {
                throw IllegalStateException("duplicate session operation")
            }
            wireOperation
        } catch (failure: RuntimeException) {
            abortAfterBeginFailure(donorOperation, caller, failure)
        }
    }

    override fun update(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray =
        execute(WireErrorCode.INVALID_OPERATION_HANDLE) {
            requireCaller(caller)
            requireOperation(operation)
            try {
                donor
                    .update(AndroidKeystoreOperationHandle(operation.id), caller, input.copyOf())
                    .copyOf()
            } catch (failure: RuntimeException) {
                operations.remove(operation.id)
                throw failure
            }
        }

    override fun finish(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray =
        execute(WireErrorCode.INVALID_OPERATION_HANDLE) {
            requireCaller(caller)
            requireOperation(operation)
            try {
                donor
                    .finish(AndroidKeystoreOperationHandle(operation.id), caller, input.copyOf())
                    .copyOf()
            } finally {
                operations.remove(operation.id)
            }
        }

    override fun abort(operation: WireOperationHandle, caller: WireCallerIdentity) {
        execute(WireErrorCode.INVALID_OPERATION_HANDLE) {
            requireCaller(caller)
            requireOperation(operation)
            try {
                donor.abort(AndroidKeystoreOperationHandle(operation.id), caller)
            } finally {
                operations.remove(operation.id)
            }
        }
    }

    override fun close() {
        synchronized(lifecycleMonitor) {
            if (closed) return
            closed = true
            val ownedOperations = operations.keys.toList()
            operations.clear()
            for (operationId in ownedOperations) {
                try {
                    donor.abort(AndroidKeystoreOperationHandle(operationId), scope.caller)
                } catch (_: RuntimeException) {
                    continue
                }
            }
        }
    }

    private fun requireOperation(operation: WireOperationHandle): SessionOperation {
        val valid =
            authenticator.verifyOperationHandle(
                sessionIdBytes,
                scope,
                operation.id,
                operation.keyId,
                operation,
            )
        if (!valid) invalidOperation()
        val record = operations[operation.id] ?: invalidOperation()
        if (record.keyId != operation.keyId) invalidOperation()
        return record
    }

    private fun requireCaller(caller: WireCallerIdentity) {
        if (scope.caller != caller) throw WireBackendFailure(WireErrorCode.WRONG_CALLER)
    }

    private fun requireSupported(spec: WireOperationSpec) {
        if (spec.purpose != WireKeyPurpose.SIGN || spec.digest != WireDigest.SHA256) {
            throw WireBackendFailure(WireErrorCode.INVALID_ARGUMENT)
        }
    }

    private fun abortAfterBeginFailure(
        operation: AndroidKeystoreOperationHandle,
        caller: WireCallerIdentity,
        failure: RuntimeException,
    ): Nothing {
        try {
            donor.abort(operation, caller)
        } catch (cleanupFailure: RuntimeException) {
            failure.addSuppressed(cleanupFailure)
        }
        throw failure
    }

    private fun <T> execute(
        authenticatorCode: WireErrorCode = WireErrorCode.DONOR_UNAVAILABLE,
        action: () -> T,
    ): T =
        synchronized(lifecycleMonitor) {
            try {
                if (closed) throw WireBackendFailure(WireErrorCode.DONOR_UNAVAILABLE)
                action()
            } catch (failure: RuntimeException) {
                throw mapWireBackendFailure(failure, authenticatorCode)
            }
        }

    private fun invalidOperation(): Nothing =
        throw WireBackendFailure(WireErrorCode.INVALID_OPERATION_HANDLE)

    private data class SessionOperation(val keyId: UUID)

    private companion object {
        const val SESSION_ID_BYTES = 32

        fun validateSessionId(sessionId: ByteArray): ByteArray {
            if (sessionId.size != SESSION_ID_BYTES) {
                val cause = HandleAuthenticatorException.InvalidSessionId()
                throw WireBackendFailure(WireErrorCode.DONOR_UNAVAILABLE, cause)
            }
            return sessionId.copyOf()
        }
    }
}
