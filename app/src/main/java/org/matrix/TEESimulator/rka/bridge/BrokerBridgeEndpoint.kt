package org.matrix.TEESimulator.rka.bridge

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

interface BridgeTransport : Closeable {
    /** Must be backed by SO_PEERCRED on production Unix-domain transports. */
    fun peerCredentials(): PeerCredentials

    fun input(): InputStream

    fun output(): OutputStream

    /** Test hook proving an oversized frame is rejected before a body read/allocation. */
    fun noteBodyRead(size: Int) {}
}

/**
 * Role-neutral root endpoint: DONOR supplies an accepted transport; CANDIDATE supplies a connected
 * transport. Authentication and lifecycle are identical in both directions.
 */
interface BrokerBridgeEndpoint {
    fun acceptAndDispatch(dispatch: (BridgeMessage) -> BridgeMessage): BridgeResult<BridgeMessage>

    fun cancel(requestId: RequestId): BridgeResult<Unit>

    fun peerDied()
}

internal interface TestBrokerBridgeEndpoint : BrokerBridgeEndpoint {
    fun stateLockHeldByCurrentThread(): Boolean

    fun correlationCountForTest(): Int
}

private class DefaultBrokerBridgeEndpoint(
    private val trustedSource: TrustedSidecarIdentitySource,
    private val trustedIdentity: TrustedSidecarIdentity,
    private val socketMetadata: () -> SocketMetadata,
    private val onDispatch: () -> Unit = {},
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
        } ?: run { BridgeResult.Failure(BridgeError.UnknownCorrelation) }

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
        val revalidated = trustedSource.revalidate(trustedIdentity)
        if (revalidated is BridgeResult.Failure) return revalidated
        val snapshot = (revalidated as BridgeResult.Success).value
        return if (
            credentials.uid == snapshot.uid &&
                credentials.gid == snapshot.gid &&
                credentials.pid == snapshot.pid
        ) {
            BridgeResult.Success(snapshot)
        } else {
            BridgeResult.Failure(BridgeError.PeerIdentityMismatch)
        }
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

internal object BrokerBridgeEndpoints {
    @JvmSynthetic
    fun forTest(
        expected: () -> SupervisorSnapshot,
        processIdentity: ProcessIdentitySource,
        socketMetadata: () -> SocketMetadata,
        onDispatch: () -> Unit = {},
        transport: BridgeTransport,
        execution: BridgeExecution = BoundedBridgeExecution(),
        timeoutMillis: Long = BridgeLimits.DEADLINE_MILLIS,
    ): TestBrokerBridgeEndpoint {
        val source = testTrustedSidecarIdentitySource(expected, processIdentity)
        val captured = source.capture() as BridgeResult.Success
        return DefaultBrokerBridgeEndpoint(
            source,
            captured.value,
            socketMetadata,
            onDispatch,
            transport,
            execution,
            timeoutMillis,
        )
    }

    @JvmSynthetic
    fun production(
        trustedSource: TrustedSidecarIdentitySource,
        socketMetadata: () -> SocketMetadata,
        transport: BridgeTransport,
        execution: BridgeExecution = BoundedBridgeExecution(),
    ): BridgeResult<BrokerBridgeEndpoint> =
        when (val captured = trustedSource.capture()) {
            is BridgeResult.Failure -> captured
            is BridgeResult.Success ->
                BridgeResult.Success(
                    DefaultBrokerBridgeEndpoint(
                        trustedSource,
                        captured.value,
                        socketMetadata,
                        transport = transport,
                        execution = execution,
                        timeoutMillis = BridgeLimits.DEADLINE_MILLIS,
                    )
                )
        }
}
