package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import org.matrix.teesimulator.twophone.WireErrorCode

class WireBackendFailureMappingTest {
    @Test
    fun repositoryFailuresHaveStableCodesAndPreserveCauses() {
        assertMapped(
            WireErrorCode.REPLAY_CONFLICT,
            DonorLifecycleRepositoryException.ReplayConflict(),
        )
        assertMapped(
            WireErrorCode.INVALID_HANDLE,
            DonorLifecycleRepositoryException.InvalidHandle(),
        )
        assertMapped(WireErrorCode.INVALID_STATE, DonorLifecycleRepositoryException.InvalidState())
        assertMapped(
            WireErrorCode.DONOR_UNAVAILABLE,
            DonorLifecycleRepositoryException.GlobalQuarantine(),
        )
        assertMapped(
            WireErrorCode.DONOR_UNAVAILABLE,
            DonorLifecycleRepositoryException.Unavailable(IllegalStateException()),
        )
        assertMapped(
            WireErrorCode.DONOR_UNAVAILABLE,
            DonorLifecycleRepositoryException.RevisionExhausted(),
        )
    }

    @Test
    fun donorAndUnexpectedFailuresHaveStableCodesAndPreserveCauses() {
        assertMapped(WireErrorCode.WRONG_CALLER, AndroidKeystoreDonorException.WrongCaller())
        assertMapped(WireErrorCode.INVALID_ARGUMENT, AndroidKeystoreDonorException.InvalidAlias())
        assertMapped(
            WireErrorCode.INVALID_ARGUMENT,
            AndroidKeystoreDonorException.InvalidChallenge(),
        )
        assertMapped(
            WireErrorCode.INVALID_OPERATION_HANDLE,
            AndroidKeystoreDonorException.OperationNotFound(),
        )
        listOf(
                AndroidKeystoreDonorException.KeyNotFound(),
                AndroidKeystoreDonorException.AliasAlreadyExists(),
                AndroidKeystoreDonorException.AttestationRejected("rejected"),
                AndroidKeystoreDonorException.BackendFailure(IllegalStateException()),
            )
            .forEach { assertMapped(WireErrorCode.DONOR_UNAVAILABLE, it) }
        assertMapped(WireErrorCode.INVALID_ARGUMENT, IllegalArgumentException())
        assertMapped(WireErrorCode.INTERNAL_ERROR, IllegalStateException())
    }

    @Test
    fun authenticatorFailureUsesBoundarySpecificCode() {
        val failure = HandleAuthenticatorException.InvalidMacOutput()
        assertMapped(WireErrorCode.DONOR_UNAVAILABLE, failure)
        assertMapped(
            WireErrorCode.INVALID_OPERATION_HANDLE,
            failure,
            WireErrorCode.INVALID_OPERATION_HANDLE,
        )
    }

    private fun assertMapped(
        expected: WireErrorCode,
        cause: RuntimeException,
        authenticatorCode: WireErrorCode = WireErrorCode.DONOR_UNAVAILABLE,
    ) {
        val mapped = mapWireBackendFailure(cause, authenticatorCode)
        assertEquals(expected, mapped.code)
        assertSame(cause, mapped.cause)
    }
}
