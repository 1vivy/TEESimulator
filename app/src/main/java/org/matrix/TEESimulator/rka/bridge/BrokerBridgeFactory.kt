package org.matrix.TEESimulator.rka.bridge

import java.util.concurrent.atomic.AtomicReference

object BrokerBridgeFactory {
    private val donorLock = Any()
    private var donorServer: DonorBridgeServer? = null

    /**
     * Runs bind, accept, authentication, I/O and dispatch through the production bounded bridge. A
     * successful response remains live and ownership transfers to the caller, which must close it.
     */
    fun acceptDonor(dispatch: (BridgeMessage) -> BridgeMessage): BridgeResult<BridgeMessage> {
        return synchronized(donorLock) {
            val captured = captureProductionPeerAuthorization(BrokerSidecarRole.DONOR)
            if (captured is BridgeResult.Failure) return captured
            val peerAuthorization = (captured as BridgeResult.Success).value
            try {
                val value =
                    donorServer
                        ?: when (val bound = bindDonorServer()) {
                            is BridgeResult.Failure -> return bound
                            is BridgeResult.Success -> bound.value
                        }
                val accepted = value.nextTransport()
                if (accepted is BridgeResult.Failure) {
                    closeDonorServer(value)
                    return accepted
                }
                val connected = (accepted as BridgeResult.Success).value
                val valueEndpoint =
                    createProductionBrokerEndpoint(
                        peerAuthorization,
                        value::socketMetadata,
                        connected,
                    )
                try {
                    valueEndpoint.acceptAndDispatch(dispatch)
                } finally {
                    valueEndpoint.peerDied()
                    connected.close()
                }
            } finally {
                peerAuthorization.close()
            }
        }
    }

    private fun bindDonorServer(): BridgeResult<DonorBridgeServer> {
        val bound = DonorBridgeServer.bind()
        if (bound is BridgeResult.Success) donorServer = bound.value
        return bound
    }

    private fun closeDonorServer(server: DonorBridgeServer) {
        if (donorServer === server) donorServer = null
        server.close()
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
