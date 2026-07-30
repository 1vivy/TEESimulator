package org.matrix.TEESimulator.rka.bridge

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

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
class BrokerBridgeEndpoint(
    private val expected: () -> SupervisorSnapshot,
    private val processIdentity: ProcessIdentitySource,
    private val socketMetadata: () -> SocketMetadata,
    private val capacity: BridgeCapacity = BridgeCapacity(),
    private val clock: () -> Long = System::nanoTime,
    private val onDispatch: () -> Unit = {},
    private val transport: BridgeTransport,
) {
    private val stateLock = Any()
    private var closed = false
    private val correlations = mutableSetOf<RequestId>()

    fun acceptAndDispatch(dispatch: (BridgeMessage) -> BridgeMessage): BridgeResult<BridgeMessage> {
        val deadline = absoluteDeadline()
        val lease = capacity.acquire()
        if (lease is BridgeResult.Failure) return lease
        (lease as BridgeResult.Success).value.use {
            val authentication = authenticate()
            if (authentication is BridgeResult.Failure) return failureAndClose(authentication.error)
            val initial = (authentication as BridgeResult.Success).value
            if (expired(deadline)) return failureAndClose(BridgeError.DeadlineExceeded)
            val input =
                try {
                    transport.input()
                } catch (_: SecurityException) {
                    return failureAndClose(BridgeError.SelinuxDenied)
                }
            val decoded = BridgeCodec.decode(input, BridgeDirection.SIDECAR_TO_BROKER)
            if (decoded is BridgeResult.Failure) return failureAndClose(decoded.error)
            val request = (decoded as BridgeResult.Success).value
            if (!addCorrelation(request.requestId)) {
                return failureAndClose(BridgeError.DuplicateCorrelation)
            }
            try {
                if (expired(deadline)) return failureAndClose(BridgeError.DeadlineExceeded)
                val current = expected()
                val observed =
                    try {
                        processIdentity.read(initial.pid)
                    } catch (_: SecurityException) {
                        return failureAndClose(BridgeError.SelinuxDenied)
                    } catch (_: Exception) {
                        return failureAndClose(BridgeError.PeerDied)
                    }
                if (
                    current != initial ||
                        !identityMatches(
                            PeerCredentials(initial.uid, initial.gid, initial.pid),
                            current,
                            observed,
                        )
                ) {
                    return failureAndClose(BridgeError.PeerIdentityChanged)
                }
                onDispatch()
                val response = dispatch(request)
                if (response.requestId != request.requestId) {
                    return failureAndClose(BridgeError.UnknownCorrelation)
                }
                if (expired(deadline)) return failureAndClose(BridgeError.DeadlineExceeded)
                val encoded = BridgeCodec.encode(response, BridgeDirection.BROKER_TO_SIDECAR)
                try {
                    transport.output().write(encoded)
                    transport.output().flush()
                } catch (_: SecurityException) {
                    return failureAndClose(BridgeError.SelinuxDenied)
                } catch (_: Exception) {
                    return failureAndClose(BridgeError.PeerDied)
                } finally {
                    encoded.fill(0)
                }
                if (expired(deadline)) return failureAndClose(BridgeError.DeadlineExceeded)
                return BridgeResult.Success(response)
            } finally {
                removeCorrelation(request.requestId)
            }
        }
    }

    fun cancel(requestId: RequestId): BridgeResult<Unit> =
        if (removeCorrelation(requestId)) {
            close()
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.UnknownCorrelation)
        }

    fun peerDied() {
        close()
    }

    internal fun stateLockHeldByCurrentThread(): Boolean = Thread.holdsLock(stateLock)

    private fun authenticate(): BridgeResult<SupervisorSnapshot> {
        val policy = SocketPolicy.validate(socketMetadata())
        if (policy is BridgeResult.Failure) return policy
        val credentials =
            try {
                transport.peerCredentials()
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

    private fun addCorrelation(id: RequestId): Boolean =
        synchronized(stateLock) {
            if (closed || correlations.size >= BridgeLimits.MAX_IN_FLIGHT) false
            else correlations.add(id)
        }

    private fun removeCorrelation(id: RequestId): Boolean =
        synchronized(stateLock) { correlations.remove(id) }

    private fun failureAndClose(error: BridgeError): BridgeResult.Failure {
        close()
        return BridgeResult.Failure(error)
    }

    private fun close() {
        val shouldClose =
            synchronized(stateLock) {
                if (closed) false
                else {
                    closed = true
                    correlations.clear()
                    true
                }
            }
        if (shouldClose) runCatching { transport.close() }
    }

    private fun absoluteDeadline(): Long {
        val now = clock()
        val budget = TimeUnit.MILLISECONDS.toNanos(BridgeLimits.DEADLINE_MILLIS)
        return now + budget
    }

    private fun expired(deadline: Long): Boolean {
        val remaining = deadline - clock()
        return remaining <= 0 ||
            remaining > TimeUnit.MILLISECONDS.toNanos(BridgeLimits.DEADLINE_MILLIS)
    }
}
