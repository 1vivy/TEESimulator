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
        return BoundedBridgeExecution().run(
            BridgeLimits.DEADLINE_MILLIS,
            {
                endpoint.get()?.peerDied()
                runCatching { transport.get()?.close() }
                runCatching { server.get()?.close() }
            },
        ) {
            val bound = DonorBridgeServer.bind()
            if (bound is BridgeResult.Failure) return@run bound
            val value = (bound as BridgeResult.Success).value
            server.set(value)
            val connected = value.boundedTransport()
            transport.set(connected)
            try {
                val created =
                    createProductionBrokerEndpoint(
                        value::socketMetadata,
                        connected,
                        InlineBridgeExecution,
                    )
                if (created is BridgeResult.Failure) return@run created
                val valueEndpoint = (created as BridgeResult.Success).value
                endpoint.set(valueEndpoint)
                try {
                    valueEndpoint.acceptAndDispatch(dispatch)
                } finally {
                    valueEndpoint.peerDied()
                }
            } finally {
                connected.close()
                value.close()
                transport.set(null)
                server.set(null)
                endpoint.set(null)
            }
        }
    }

    /**
     * Runs connect, authentication and exchange through the production bounded bridge. A successful
     * response remains live and ownership transfers to the caller, which must close it.
     */
    fun exchangeCandidate(request: BridgeMessage): BridgeResult<BridgeMessage> {
        val transport = CandidateBridgeConnector.boundedTransport()
        val clientReference = AtomicReference<BrokerBridgeClient?>()
        val result =
            BoundedBridgeExecution().run(
                BridgeLimits.DEADLINE_MILLIS,
                {
                    clientReference.get()?.peerDied()
                    transport.close()
                },
            ) {
                val client =
                    createProductionBrokerClient(
                        { SocketMetadata.secureRootOwned() },
                        transport,
                        InlineBridgeExecution,
                    )
                if (client is BridgeResult.Failure) {
                    request.close()
                    transport.close()
                    return@run client
                }
                try {
                    val valueClient = (client as BridgeResult.Success).value
                    clientReference.set(valueClient)
                    try {
                        valueClient.exchange(request)
                    } finally {
                        valueClient.peerDied()
                    }
                } finally {
                    clientReference.set(null)
                    transport.close()
                }
            }
        if (result is BridgeResult.Failure) request.close()
        return result
    }
}
