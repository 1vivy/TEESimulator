package org.matrix.TEESimulator.rka.bridge

internal interface TestBrokerBridgeEndpoint : BrokerBridgeEndpoint {
    fun stateLockHeldByCurrentThread(): Boolean

    fun correlationCountForTest(): Int
}

internal interface TestBrokerBridgeClient : BrokerBridgeClient {
    fun correlationCountForTest(): Int
}

internal fun testBrokerBridgeEndpoint(
    expected: () -> SupervisorSnapshot,
    processIdentity: ProcessIdentitySource,
    socketMetadata: () -> SocketMetadata,
    onDispatch: () -> Unit = {},
    transport: BridgeTransport,
    execution: BridgeExecution = BoundedBridgeExecution(),
    timeoutMillis: Long = BridgeLimits.DEADLINE_MILLIS,
): TestBrokerBridgeEndpoint =
    TestEndpoint(
        TestPeerAuthorization(expected, processIdentity),
        socketMetadata,
        onDispatch,
        transport,
        execution,
        timeoutMillis,
    )

internal fun testBrokerBridgeClient(
    expected: () -> SupervisorSnapshot,
    processIdentity: ProcessIdentitySource,
    socketMetadata: () -> SocketMetadata,
    transport: BridgeTransport,
    execution: BridgeExecution = BoundedBridgeExecution(),
    timeoutMillis: Long = BridgeLimits.DEADLINE_MILLIS,
): TestBrokerBridgeClient =
    TestClient(
        TestPeerAuthorization(expected, processIdentity),
        socketMetadata,
        transport,
        execution,
        timeoutMillis,
    )

private class TestPeerAuthorization(
    private val expected: () -> SupervisorSnapshot,
    private val processIdentity: ProcessIdentitySource,
) {
    private val captured = expected()
    private var validations = 0

    fun authenticate(credentials: PeerCredentials): BridgeResult<SupervisorSnapshot> {
        val snapshot = if (validations++ == 0) captured else expected()
        if (captured.generation != snapshot.generation) {
            return BridgeResult.Failure(BridgeError.TrustedStateChanged)
        }
        val observed =
            runCatching { processIdentity.read(snapshot.pid) }
                .getOrElse {
                    return BridgeResult.Failure(BridgeError.PeerDied)
                }
        return if (identityMatches(credentials, snapshot, observed)) {
            BridgeResult.Success(snapshot)
        } else {
            BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
        }
    }
}

private class TestEndpoint(
    private val authorization: TestPeerAuthorization,
    private val socketMetadata: () -> SocketMetadata,
    private val onDispatch: () -> Unit,
    private val transport: BridgeTransport,
    private val execution: BridgeExecution,
    private val timeoutMillis: Long,
) : TestBrokerBridgeEndpoint {
    private val stateLock = Any()
    private var closed = false
    private val correlations = mutableMapOf<RequestId, BridgeCorrelation>()

    override fun acceptAndDispatch(
        dispatch: (BridgeMessage) -> BridgeMessage
    ): BridgeResult<BridgeMessage> = execution.run(timeoutMillis, ::close) { dispatchOne(dispatch) }

    override fun cancel(requestId: RequestId): BridgeResult<Unit> =
        takeCorrelation(requestId)?.let { correlation ->
            correlation.worker.interrupt()
            close()
            BridgeResult.Success(Unit)
        } ?: BridgeResult.Failure(BridgeError.UnknownCorrelation)

    override fun peerDied() {
        close()
    }

    override fun stateLockHeldByCurrentThread(): Boolean = Thread.holdsLock(stateLock)

    override fun correlationCountForTest(): Int = synchronized(stateLock) { correlations.size }

    private fun dispatchOne(
        dispatch: (BridgeMessage) -> BridgeMessage
    ): BridgeResult<BridgeMessage> {
        val authentication = authenticate()
        if (authentication is BridgeResult.Failure) return failureAndClose(authentication.error)
        val initial = (authentication as BridgeResult.Success).value
        val input =
            try {
                transport.input()
            } catch (_: SecurityException) {
                return failureAndClose(BridgeError.SelinuxDenied)
            }
        val decoded = BridgeCodec.decode(input, BridgeExchangeRole.DONOR_REQUEST)
        if (decoded is BridgeResult.Failure) return failureAndClose(decoded.error)
        val request = (decoded as BridgeResult.Success).value
        val correlation =
            try {
                BridgeProtocol.correlationFor(request, initial.generation)
            } catch (_: IllegalArgumentException) {
                request.close()
                return failureAndClose(BridgeError.UnexpectedTag)
            }
        if (!addCorrelation(correlation)) {
            request.close()
            return failureAndClose(BridgeError.DuplicateCorrelation)
        }
        try {
            if (!reauthenticate(initial)) {
                return failureAndClose(BridgeError.PeerIdentityChanged)
            }
            onDispatch()
            val response = dispatch(request)
            var transferred = false
            try {
                if (!reauthenticate(initial)) {
                    return failureAndClose(BridgeError.PeerIdentityChanged)
                }
                if (!correlation.accepts(response)) {
                    return failureAndClose(BridgeError.UnknownCorrelation)
                }
                val encoded = BridgeCodec.encode(response, BridgeExchangeRole.DONOR_RESPONSE)
                try {
                    if (!reauthenticate(initial)) {
                        return failureAndClose(BridgeError.PeerIdentityChanged)
                    }
                    transport.output().write(encoded)
                    transport.output().flush()
                } catch (_: SecurityException) {
                    return failureAndClose(BridgeError.SelinuxDenied)
                } catch (_: Exception) {
                    return failureAndClose(BridgeError.PeerDied)
                } finally {
                    encoded.fill(0)
                }
                transferred = true
                return BridgeResult.Success(response)
            } finally {
                if (!transferred) response.close()
            }
        } finally {
            request.close()
            removeCorrelation(request.requestId)
        }
    }

    private fun authenticate(): BridgeResult<SupervisorSnapshot> {
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
        return authorization.authenticate(credentials)
    }

    private fun reauthenticate(initial: SupervisorSnapshot): Boolean {
        if (synchronized(stateLock) { closed }) return false
        val current = authenticate()
        return current is BridgeResult.Success && current.value == initial
    }

    private fun addCorrelation(correlation: BridgeCorrelation): Boolean =
        synchronized(stateLock) {
            if (closed || correlations.size >= BridgeLimits.MAX_IN_FLIGHT) false
            else correlations.putIfAbsent(correlation.requestId, correlation) == null
        }

    private fun removeCorrelation(id: RequestId): Boolean =
        synchronized(stateLock) { correlations.remove(id) != null }

    private fun takeCorrelation(id: RequestId): BridgeCorrelation? =
        synchronized(stateLock) { correlations.remove(id) }

    private fun failureAndClose(error: BridgeError): BridgeResult.Failure {
        close()
        return BridgeResult.Failure(error)
    }

    private fun close() {
        var workers = emptyList<Thread>()
        val shouldClose =
            synchronized(stateLock) {
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
}

private class TestClient(
    private val authorization: TestPeerAuthorization,
    private val socketMetadata: () -> SocketMetadata,
    private val transport: BridgeTransport,
    private val execution: BridgeExecution,
    private val timeoutMillis: Long,
) : TestBrokerBridgeClient {
    private val lock = Any()
    private var generation = -1L
    private var closed = false
    private val correlations = mutableMapOf<RequestId, BridgeCorrelation>()

    override fun exchange(request: BridgeMessage): BridgeResult<BridgeMessage> =
        execution.run(timeoutMillis, ::closeTransport) { exchangeOne(request) }

    override fun cancel(requestId: RequestId): BridgeResult<Unit> =
        take(requestId)?.let { correlation ->
            correlation.worker.interrupt()
            closeTransport()
            BridgeResult.Success(Unit)
        } ?: BridgeResult.Failure(BridgeError.UnknownCorrelation)

    override fun peerDied() {
        closeTransport()
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

    private fun authenticate(): BridgeResult<SupervisorSnapshot> {
        if (synchronized(lock) { closed }) return BridgeResult.Failure(BridgeError.PeerDied)
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
        return authorization.authenticate(credentials)
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

    override fun correlationCountForTest(): Int = synchronized(lock) { correlations.size }
}
