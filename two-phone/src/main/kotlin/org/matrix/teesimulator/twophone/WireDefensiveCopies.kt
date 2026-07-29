package org.matrix.teesimulator.twophone

internal fun WireKeyHandle.defensiveCopy() = WireKeyHandle(id, binding)

internal fun WireOperationHandle.defensiveCopy() = WireOperationHandle(id, keyId, binding)

internal fun WireKeyMetadata.defensiveCopy() =
    WireKeyMetadata(state, attestationChallenge, publicKey, certificateChain, keySpec)

internal fun LifecycleResultPayload.defensiveCopy(): LifecycleResultPayload =
    when (this) {
        is GenerateResultPayload ->
            GenerateResultPayload(generationId, handle.defensiveCopy(), metadata.defensiveCopy())
        is GetMetadataResultPayload -> GetMetadataResultPayload(metadata.defensiveCopy())
        is DeleteResultPayload -> DeleteResultPayload(deletionId)
        is BeginResultPayload -> BeginResultPayload(operation.defensiveCopy(), step)
        is UpdateAadResultPayload -> UpdateAadResultPayload(step)
        is UpdateResultPayload -> UpdateResultPayload(step, output)
        is FinishResultPayload -> FinishResultPayload(step, output)
        is AbortResultPayload -> AbortResultPayload(step)
    }

internal fun WireOutcome.defensiveCopy(): WireOutcome =
    when (this) {
        is WireOutcome.Success -> WireOutcome.Success(payload.defensiveCopy())
        is WireOutcome.Error -> WireOutcome.Error(code)
    }

internal fun WireResponseEnvelope.defensiveCopy() =
    WireResponseEnvelope(version, sessionId, requestId, method, outcome.defensiveCopy())
