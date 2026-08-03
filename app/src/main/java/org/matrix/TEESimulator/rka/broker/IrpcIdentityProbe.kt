package org.matrix.TEESimulator.rka.broker

import org.matrix.TEESimulator.rka.journal.RkpIrpcIdentity

/** Read-only production probe for the IRPC identity boundary used before donor key generation. */
object IrpcIdentityProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isNotEmpty()) {
            println("IRPC_IDENTITY=INPUT_INVALID")
            return
        }
        val outcome =
            runCatching {
                    IrpcClient.android()
                        .resolveIdentity(BrokerDeadline.at(5_000), BrokerCancellation.active())
                }
                .getOrElse {
                    println("IRPC_IDENTITY=UNEXPECTED_FAILURE")
                    return
                }
        println("IRPC_IDENTITY=${classify(outcome)}")
    }

    internal fun classify(outcome: BrokerOutcome<IrpcResolvedIdentity>): String =
        when (outcome) {
            is BrokerOutcome.Success ->
                try {
                    RkpIrpcIdentity.from(outcome.value)
                    "READY"
                } catch (_: IllegalArgumentException) {
                    "IDENTITY_INVALID"
                }
            BrokerOutcome.SelfCallBypass -> "SELF_CALL_BYPASS"
            is BrokerOutcome.Failure ->
                when (outcome.error) {
                    is BrokerError.UnsupportedIrpcVersion -> "UNSUPPORTED_VERSION"
                    is BrokerError.InvalidBoundary -> "INVALID_BOUNDARY"
                    is BrokerError.ServiceMissing -> "SERVICE_MISSING"
                    is BrokerError.AccessDenied -> "ACCESS_DENIED"
                    is BrokerError.ServiceDead -> "SERVICE_DEAD"
                    is BrokerError.ServiceRejected -> "SERVICE_REJECTED"
                    is BrokerError.OemFailure -> "OEM_FAILURE"
                    is BrokerError.Capacity -> "CAPACITY"
                    BrokerError.Cancelled -> "CANCELLED"
                    BrokerError.DeadlineExceeded -> "DEADLINE_EXCEEDED"
                }
        }
}
