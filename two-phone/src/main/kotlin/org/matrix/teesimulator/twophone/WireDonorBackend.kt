package org.matrix.teesimulator.twophone

import java.util.UUID

interface WireDonorBackend : AutoCloseable {
    fun generate(command: BackendGenerate): BackendGeneratedKey

    fun metadata(handle: WireKeyHandle, caller: WireCallerIdentity): WireKeyMetadata

    fun delete(command: BackendDelete)

    fun begin(
        handle: WireKeyHandle,
        spec: WireOperationSpec,
        caller: WireCallerIdentity,
    ): WireOperationHandle

    fun update(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray

    fun finish(
        operation: WireOperationHandle,
        input: ByteArray,
        caller: WireCallerIdentity,
    ): ByteArray

    fun abort(operation: WireOperationHandle, caller: WireCallerIdentity)

    override fun close()
}

class BackendGenerate(
    val generationId: UUID,
    payloadHash: ByteArray,
    logicalNameHash: ByteArray,
    challenge: ByteArray,
    val keySpec: WireKeySpec,
    val caller: WireCallerIdentity,
) {
    private val payloadHashBytes = payloadHash.copyOf()
    private val logicalNameHashBytes = logicalNameHash.copyOf()
    private val challengeBytes = challenge.copyOf()

    val payloadHash: ByteArray
        get() = payloadHashBytes.copyOf()

    val logicalNameHash: ByteArray
        get() = logicalNameHashBytes.copyOf()

    val challenge: ByteArray
        get() = challengeBytes.copyOf()
}

class BackendDelete(
    val deletionId: UUID,
    payloadHash: ByteArray,
    handle: WireKeyHandle,
    val caller: WireCallerIdentity,
) {
    private val payloadHashBytes = payloadHash.copyOf()
    private val storedHandle = handle.defensiveCopy()

    val payloadHash: ByteArray
        get() = payloadHashBytes.copyOf()

    val handle: WireKeyHandle
        get() = storedHandle.defensiveCopy()
}

class BackendGeneratedKey(handle: WireKeyHandle, metadata: WireKeyMetadata) {
    private val storedHandle = handle.defensiveCopy()
    private val storedMetadata = metadata.defensiveCopy()

    val handle: WireKeyHandle
        get() = storedHandle.defensiveCopy()

    val metadata: WireKeyMetadata
        get() = storedMetadata.defensiveCopy()
}

class WireBackendFailure(val code: WireErrorCode, cause: Throwable? = null) :
    RuntimeException(cause)
