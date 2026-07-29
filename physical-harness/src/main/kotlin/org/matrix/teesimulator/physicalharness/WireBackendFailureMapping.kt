package org.matrix.teesimulator.physicalharness

import org.matrix.teesimulator.twophone.WireBackendFailure
import org.matrix.teesimulator.twophone.WireErrorCode

internal fun mapWireBackendFailure(
    failure: RuntimeException,
    authenticatorCode: WireErrorCode = WireErrorCode.DONOR_UNAVAILABLE,
): WireBackendFailure {
    if (failure is WireBackendFailure) return failure
    val code =
        when (failure) {
            is DonorLifecycleRepositoryException.ReplayConflict -> WireErrorCode.REPLAY_CONFLICT
            is DonorLifecycleRepositoryException.InvalidHandle -> WireErrorCode.INVALID_HANDLE
            is DonorLifecycleRepositoryException.InvalidState -> WireErrorCode.INVALID_STATE
            is DonorLifecycleRepositoryException.GlobalQuarantine,
            is DonorLifecycleRepositoryException.Unavailable,
            is DonorLifecycleRepositoryException.RevisionExhausted ->
                WireErrorCode.DONOR_UNAVAILABLE
            is AndroidKeystoreDonorException.WrongCaller -> WireErrorCode.WRONG_CALLER
            is AndroidKeystoreDonorException.InvalidAlias,
            is AndroidKeystoreDonorException.InvalidChallenge -> WireErrorCode.INVALID_ARGUMENT
            is AndroidKeystoreDonorException.OperationNotFound ->
                WireErrorCode.INVALID_OPERATION_HANDLE
            is AndroidKeystoreDonorException.KeyNotFound,
            is AndroidKeystoreDonorException.AliasAlreadyExists,
            is AndroidKeystoreDonorException.AttestationRejected,
            is AndroidKeystoreDonorException.BackendFailure -> WireErrorCode.DONOR_UNAVAILABLE
            is HandleAuthenticatorException -> authenticatorCode
            is IllegalArgumentException -> WireErrorCode.INVALID_ARGUMENT
            else -> WireErrorCode.INTERNAL_ERROR
        }
    return WireBackendFailure(code, failure)
}
