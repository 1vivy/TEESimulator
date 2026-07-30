package org.matrix.TEESimulator.rka.bridge

import java.util.concurrent.atomic.AtomicReference

object BrokerBridgeFactory {
    /**
     * Runs bind, accept, authentication, I/O and dispatch through the production bounded bridge. A
     * successful response remains live and ownership transfers to the caller, which must close it.
     */
    fun acceptDonor(dispatch: (BridgeMessage) -> BridgeMessage): BridgeResult<BridgeMessage> {
        val server = AtomicReference<DonorBridgeServer?>()
        val transport = AtomicReference<BridgeTransport?>()
        val endpoint = AtomicReference<BrokerBridgeEndpoint?>()
        val authorization = AtomicReference<ProductionPeerAuthorization?>()
        return BoundedBridgeExecution().run(
            BridgeLimits.DEADLINE_MILLIS,
            {
                endpoint.get()?.peerDied()
                authorization.get()?.close()
                runCatching { transport.get()?.close() }
                runCatching { server.get()?.close() }
            },
        ) {
            val captured = captureProductionPeerAuthorization(BrokerSidecarRole.DONOR)
            if (captured is BridgeResult.Failure) return@run captured
            val peerAuthorization = (captured as BridgeResult.Success).value
            authorization.set(peerAuthorization)
            try {
                val bound = DonorBridgeServer.bind()
                if (bound is BridgeResult.Failure) return@run bound
                val value = (bound as BridgeResult.Success).value
                server.set(value)
                val connected = value.boundedTransport()
                transport.set(connected)
                val valueEndpoint =
                    createProductionBrokerEndpoint(
                        peerAuthorization,
                        value::socketMetadata,
                        connected,
                        InlineBridgeExecution,
                    )
                endpoint.set(valueEndpoint)
                try {
                    valueEndpoint.acceptAndDispatch(dispatch)
                } finally {
                    valueEndpoint.peerDied()
                    connected.close()
                    value.close()
                    transport.set(null)
                    server.set(null)
                    endpoint.set(null)
                }
            } finally {
                peerAuthorization.close()
                authorization.set(null)
            }
        }
    }

    /**
     * Runs connect, authentication and exchange through the production bounded bridge. A successful
     * response remains live and ownership transfers to the caller, which must close it.
     */
    fun exchangeCandidate(request: BridgeMessage): BridgeResult<BridgeMessage> {
        val transport = AtomicReference<BridgeTransport?>()
        val clientReference = AtomicReference<BrokerBridgeClient?>()
        val authorization = AtomicReference<ProductionPeerAuthorization?>()
        val result =
            BoundedBridgeExecution().run(
                BridgeLimits.DEADLINE_MILLIS,
                {
                    clientReference.get()?.peerDied()
                    authorization.get()?.close()
                    transport.get()?.close()
                },
            ) {
                val captured = captureProductionPeerAuthorization(BrokerSidecarRole.CANDIDATE)
                if (captured is BridgeResult.Failure) return@run captured
                val peerAuthorization = (captured as BridgeResult.Success).value
                authorization.set(peerAuthorization)
                try {
                    val connected = CandidateBridgeConnector.boundedTransport()
                    transport.set(connected)
                    val valueClient =
                        createProductionBrokerClient(
                            peerAuthorization,
                            { SocketMetadata.secureRootOwned() },
                            connected,
                            InlineBridgeExecution,
                        )
                    clientReference.set(valueClient)
                    try {
                        valueClient.exchange(request)
                    } finally {
                        valueClient.peerDied()
                        clientReference.set(null)
                        connected.close()
                        transport.set(null)
                    }
                } finally {
                    peerAuthorization.close()
                    authorization.set(null)
                }
            }
        if (result is BridgeResult.Failure) request.close()
        return result
    }
}
