package org.matrix.TEESimulator.rka.broker

import org.junit.Assert.assertEquals
import org.junit.Test

class IrpcIdentityProbeTest {
    @Test
    fun resolvedIdentityMustAlsoFitJournalUtf8Boundary() {
        assertEquals("READY", IrpcIdentityProbe.classify(BrokerOutcome.Success(identity("donor"))))
        assertEquals(
            "IDENTITY_INVALID",
            IrpcIdentityProbe.classify(BrokerOutcome.Success(identity("é".repeat(128)))),
        )
    }

    @Test
    fun everyBrokerFailureMapsToOneRedactedStableCategory() {
        val cases =
            listOf(
                BrokerError.UnsupportedIrpcVersion(2) to "UNSUPPORTED_VERSION",
                BrokerError.InvalidBoundary(BrokerError.InvalidBoundary.Boundary.CAPABILITY) to
                    "INVALID_BOUNDARY",
                BrokerError.ServiceMissing(BrokerServiceKind.IRPC) to "SERVICE_MISSING",
                BrokerError.AccessDenied(BrokerServiceKind.IRPC) to "ACCESS_DENIED",
                BrokerError.ServiceDead(BrokerServiceKind.IRPC) to "SERVICE_DEAD",
                BrokerError.ServiceRejected(
                    BrokerServiceKind.IRPC,
                    BrokerServiceFailure.Oem(991),
                ) to "SERVICE_REJECTED",
                BrokerError.OemFailure(BrokerServiceKind.IRPC) to "OEM_FAILURE",
                BrokerError.Capacity(BrokerServiceKind.IRPC) to "CAPACITY",
                BrokerError.Cancelled to "CANCELLED",
                BrokerError.DeadlineExceeded to "DEADLINE_EXCEEDED",
            )

        cases.forEach { (error, expected) ->
            assertEquals(expected, IrpcIdentityProbe.classify(BrokerOutcome.Failure(error)))
        }
        assertEquals("SELF_CALL_BYPASS", IrpcIdentityProbe.classify(BrokerOutcome.SelfCallBypass))
    }

    private fun identity(componentName: String) =
        IrpcResolvedIdentity(
            descriptor = IrpcClient.IRPC_DESCRIPTOR,
            serviceName = IrpcClient.DEFAULT_TEE_SERVICE,
            componentName = componentName,
            uniqueId = "unique",
            version = IrpcClient.REQUIRED_VERSION,
        )
}
