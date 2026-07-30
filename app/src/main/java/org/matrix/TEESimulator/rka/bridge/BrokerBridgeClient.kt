package org.matrix.TEESimulator.rka.bridge

class BrokerBridgeClient(
    private val expected: () -> SupervisorSnapshot,
    private val processIdentity: ProcessIdentitySource,
    private val socketMetadata: () -> SocketMetadata,
    private val transport: BridgeTransport,
    @Suppress("UNUSED_PARAMETER") private val capacity: BridgeCapacity = BridgeCapacity(),
    @Suppress("UNUSED_PARAMETER") private val clock: () -> Long = System::nanoTime,
    private val execution: BridgeExecution = BoundedBridgeExecution(),
    private val timeoutMillis: Long = BridgeLimits.DEADLINE_MILLIS,
) {
    private val lock = Any()
    private var generation = -1L
    private var closed = false
    private val correlations = mutableMapOf<RequestId, BridgeCorrelation>()

    fun exchange(request: BridgeMessage): BridgeResult<BridgeMessage> =
        execution.run(timeoutMillis, ::closeTransport) { exchangeOne(request) }

    fun cancel(requestId: RequestId): BridgeResult<Unit> =
        take(requestId)?.let { correlation ->
            correlation.worker.interrupt()
            closeTransport()
            BridgeResult.Success(Unit)
        } ?: run { BridgeResult.Failure(BridgeError.UnknownCorrelation) }

    private fun authenticate(): BridgeResult<SupervisorSnapshot> {
        if (synchronized(lock) { closed }) {
            return BridgeResult.Failure(BridgeError.PeerDied)
        }
        val policy = SocketPolicy.validate(socketMetadata())
        if (policy is BridgeResult.Failure) return policy
        val credentials =
            try {
                transport.peerCredentials()
            } catch (error: BridgeTransportException) {
                return BridgeResult.Failure(error.error)
            } catch (_: SecurityException) {
                return BridgeResult.Failure(BridgeError.SelinuxDenied)
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.PeerDied)
            }
        val snapshot = expected()
        val observed =
            try {
                processIdentity.read(credentials.pid)
            } catch (_: SecurityException) {
                return BridgeResult.Failure(BridgeError.SelinuxDenied)
            } catch (_: Exception) {
                return BridgeResult.Failure(BridgeError.PeerDied)
            }
        return if (identityMatches(credentials, snapshot, observed)) {
            BridgeResult.Success(snapshot)
        } else {
            BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
        }
    }

    private fun exchangeOne(request: BridgeMessage): BridgeResult<BridgeMessage> {
        val authenticated = authenticate()
        if (authenticated is BridgeResult.Failure) return authenticated
        val snapshot = (authenticated as BridgeResult.Success).value
        val correlation =
            try {
                BridgeProtocol.correlationFor(request, snapshot.generation)
            } catch (_: IllegalArgumentException) {
                request.close()
                return closeWith(BridgeError.UnexpectedTag)
            }
        if (!add(correlation)) {
            request.close()
            return BridgeResult.Failure(BridgeError.DuplicateCorrelation)
        }
        try {
            val encoded = BridgeCodec.encode(request, BridgeExchangeRole.CANDIDATE_REQUEST)
            try {
                transport.output().write(encoded)
                transport.output().flush()
            } catch (_: SecurityException) {
                return closeWith(BridgeError.SelinuxDenied)
            } catch (_: Exception) {
                return closeWith(BridgeError.PeerDied)
            } finally {
                encoded.fill(0)
            }
            val response =
                try {
                    BridgeCodec.decode(transport.input(), BridgeExchangeRole.CANDIDATE_RESPONSE)
                } catch (_: SecurityException) {
                    return closeWith(BridgeError.SelinuxDenied)
                } catch (_: Exception) {
                    return closeWith(BridgeError.PeerDied)
                }
            if (response is BridgeResult.Failure) return closeWith(response.error)
            val message = (response as BridgeResult.Success).value
            if (!correlation.accepts(message)) {
                message.close()
                return closeWith(BridgeError.UnknownCorrelation)
            }
            val rechecked = authenticate()
            if (
                rechecked is BridgeResult.Failure ||
                    (rechecked as BridgeResult.Success).value != snapshot
            ) {
                message.close()
                return closeWith(BridgeError.PeerIdentityChanged)
            }
            return BridgeResult.Success(message)
        } finally {
            request.close()
            remove(request.requestId)
        }
    }

    private fun add(correlation: BridgeCorrelation): Boolean =
        synchronized(lock) {
            if (generation != -1L && generation != correlation.generation) correlations.clear()
            generation = correlation.generation
            correlations.size < BridgeLimits.MAX_IN_FLIGHT &&
                correlations.putIfAbsent(correlation.requestId, correlation) == null
        }

    private fun remove(id: RequestId): Boolean =
        synchronized(lock) { correlations.remove(id) != null }

    private fun take(id: RequestId): BridgeCorrelation? =
        synchronized(lock) { correlations.remove(id) }

    private fun closeWith(error: BridgeError): BridgeResult.Failure {
        synchronized(lock) { correlations.clear() }
        closeTransport()
        return BridgeResult.Failure(error)
    }

    private fun closeTransport() {
        var workers = emptyList<Thread>()
        val shouldClose =
            synchronized(lock) {
                if (closed) false
                else {
                    closed = true
                    workers = correlations.values.map(BridgeCorrelation::worker)
                    correlations.clear()
                    true
                }
            }
        if (!shouldClose) return
        workers.filter { it !== Thread.currentThread() }.forEach(Thread::interrupt)
        runCatching { transport.close() }
    }

    internal fun correlationCountForTest(): Int = synchronized(lock) { correlations.size }
}
