package org.matrix.TEESimulator.rka.bridge

import java.util.concurrent.TimeUnit

class BrokerBridgeClient(
    private val expected: () -> SupervisorSnapshot,
    private val processIdentity: ProcessIdentitySource,
    private val socketMetadata: () -> SocketMetadata,
    private val transport: BridgeTransport,
    private val capacity: BridgeCapacity = BridgeCapacity(),
    private val clock: () -> Long = System::nanoTime,
) {
    private val lock = Any()
    private var generation = -1L
    private val correlations = mutableSetOf<RequestId>()

    fun exchange(request: BridgeMessage): BridgeResult<BridgeMessage> {
        val lease = capacity.acquire()
        if (lease is BridgeResult.Failure) return lease
        (lease as BridgeResult.Success).value.use {
            val deadline = clock() + TimeUnit.MILLISECONDS.toNanos(BridgeLimits.DEADLINE_MILLIS)
            val authenticated = authenticate()
            if (authenticated is BridgeResult.Failure) return authenticated
            val snapshot = (authenticated as BridgeResult.Success).value
            if (!add(request.requestId, snapshot.generation)) {
                return BridgeResult.Failure(BridgeError.DuplicateCorrelation)
            }
            try {
                if (expired(deadline)) return BridgeResult.Failure(BridgeError.DeadlineExceeded)
                val encoded = BridgeCodec.encode(request, BridgeDirection.BROKER_TO_SIDECAR)
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
                if (expired(deadline)) return closeWith(BridgeError.DeadlineExceeded)
                val response =
                    try {
                        BridgeCodec.decode(transport.input(), BridgeDirection.SIDECAR_TO_BROKER)
                    } catch (_: SecurityException) {
                        return closeWith(BridgeError.SelinuxDenied)
                    } catch (_: Exception) {
                        return closeWith(BridgeError.PeerDied)
                    }
                if (response is BridgeResult.Failure) return closeWith(response.error)
                val message = (response as BridgeResult.Success).value
                if (message.requestId != request.requestId) {
                    return closeWith(BridgeError.UnknownCorrelation)
                }
                val rechecked = authenticate()
                if (
                    rechecked is BridgeResult.Failure ||
                        (rechecked as BridgeResult.Success).value != snapshot
                ) {
                    return closeWith(BridgeError.PeerIdentityChanged)
                }
                if (expired(deadline)) return closeWith(BridgeError.DeadlineExceeded)
                return BridgeResult.Success(message)
            } finally {
                remove(request.requestId)
            }
        }
    }

    fun cancel(requestId: RequestId): BridgeResult<Unit> =
        if (remove(requestId)) {
            runCatching { transport.close() }
            BridgeResult.Success(Unit)
        } else {
            BridgeResult.Failure(BridgeError.UnknownCorrelation)
        }

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

    private fun add(id: RequestId, newGeneration: Long): Boolean =
        synchronized(lock) {
            if (generation != -1L && generation != newGeneration) correlations.clear()
            generation = newGeneration
            correlations.size < BridgeLimits.MAX_IN_FLIGHT && correlations.add(id)
        }

    private fun remove(id: RequestId): Boolean = synchronized(lock) { correlations.remove(id) }

    private fun expired(deadline: Long): Boolean {
        val remaining = deadline - clock()
        return remaining <= 0L ||
            remaining > TimeUnit.MILLISECONDS.toNanos(BridgeLimits.DEADLINE_MILLIS)
    }

    private fun closeWith(error: BridgeError): BridgeResult.Failure {
        synchronized(lock) { correlations.clear() }
        runCatching { transport.close() }
        return BridgeResult.Failure(error)
    }
}
