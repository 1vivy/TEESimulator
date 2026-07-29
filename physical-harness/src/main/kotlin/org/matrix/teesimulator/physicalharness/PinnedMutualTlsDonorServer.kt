package org.matrix.teesimulator.physicalharness

import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import org.matrix.teesimulator.twophone.BoundedWireFrameIo
import org.matrix.teesimulator.twophone.DonorServerHello
import org.matrix.teesimulator.twophone.DonorTransportHelloCodec
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDonorDispatcher

class PinnedMutualTlsDonorServer(
    private val sslContext: SSLContext,
    private val bindAddress: InetAddress,
    private val requestedPort: Int,
    private val expectedTargetPin: SpkiPin,
    private val expectedDonorPin: SpkiPin,
    private val expectedCaller: WireCallerIdentity,
    private val dispatcherFactory: DonorSessionDispatcherFactory,
    private val nonceSource: SecureRandom,
    private val now: () -> Instant,
) : DonorServer {
    private val stateMonitor = Any()
    private val closeLock = ReentrantLock()
    private val stopping = AtomicBoolean(false)
    private val registeredSockets = ConcurrentHashMap.newKeySet<SSLSocket>()
    private val deadlines = SocketDeadlineScheduler()
    private val workers =
        ThreadPoolExecutor(
            MAX_SESSIONS,
            MAX_SESSIONS,
            0,
            TimeUnit.MILLISECONDS,
            SynchronousQueue(),
            { task -> Thread(task, "donor-transport-session").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
    @Volatile private var listener: SSLServerSocket? = null
    @Volatile private var acceptor: Thread? = null
    @Volatile private var started = false
    @Volatile
    internal var resourcesClosed = false
        private set

    val boundPort: Int
        get() = listener?.localPort ?: 0

    val isRunning: Boolean
        get() = started && !stopping.get()

    val activeSessionCount: Int
        get() = registeredSockets.size

    internal val workersTerminated: Boolean
        get() = workers.isTerminated

    internal val acceptorTerminated: Boolean
        get() = acceptor?.isAlive != true

    internal val deadlineSchedulerClosed: Boolean
        get() = deadlines.isShutdown

    internal val deadlineSchedulerTerminated: Boolean
        get() = deadlines.isTerminated

    override fun start() {
        synchronized(stateMonitor) {
            check(!started && !stopping.get())
            val server =
                sslContext.serverSocketFactory.createServerSocket(
                    requestedPort,
                    ACCEPT_BACKLOG,
                    bindAddress,
                ) as SSLServerSocket
            server.enabledProtocols = arrayOf(TLS_1_3)
            server.needClientAuth = true
            server.soTimeout = ACCEPT_TIMEOUT_MILLIS
            listener = server
            started = true
            acceptor =
                Thread({ acceptLoop(server) }, "donor-transport-acceptor").apply {
                    isDaemon = true
                    start()
                }
        }
    }

    private fun acceptLoop(server: SSLServerSocket) {
        while (!stopping.get()) {
            val socket =
                try {
                    server.accept() as SSLSocket
                } catch (_: java.net.SocketTimeoutException) {
                    continue
                } catch (_: SocketException) {
                    return
                } catch (_: java.io.IOException) {
                    if (stopping.get()) return else continue
                }
            val registered =
                synchronized(stateMonitor) {
                    if (stopping.get()) false else registeredSockets.add(socket)
                }
            if (!registered) {
                closeSocket(socket)
                continue
            }
            try {
                workers.execute { runSession(socket) }
            } catch (_: RejectedExecutionException) {
                registeredSockets.remove(socket)
                closeSocket(socket)
            }
        }
    }

    private fun runSession(socket: SSLSocket) {
        var dispatcher: WireDonorDispatcher? = null
        try {
            authenticate(socket)
            socket.soTimeout = HELLO_TIMEOUT_MILLIS
            val clientHello =
                deadlines.run(socket, HELLO_TIMEOUT_MILLIS.toLong()) {
                    DonorTransportHelloCodec.readClient(socket.inputStream)
                } ?: return
            val serverNonce = ByteArray(NONCE_BYTES).also(nonceSource::nextBytes)
            val pair = PairIdentity(expectedTargetPin.toString(), expectedDonorPin.toString())
            dispatcher =
                dispatcherFactory.create(pair, clientHello.nonce, serverNonce, expectedCaller)
            deadlines.run(socket, HELLO_TIMEOUT_MILLIS.toLong()) {
                DonorTransportHelloCodec.writeServer(
                    socket.outputStream,
                    DonorServerHello(clientHello.nonce, serverNonce),
                )
            }
            processFrames(socket, dispatcher)
        } catch (_: Exception) {
            return
        } finally {
            dispatcher?.close()
            registeredSockets.remove(socket)
            closeSocket(socket)
        }
    }

    private fun authenticate(socket: SSLSocket) {
        socket.useClientMode = false
        socket.needClientAuth = true
        socket.enabledProtocols = arrayOf(TLS_1_3)
        socket.soTimeout = HANDSHAKE_TIMEOUT_MILLIS
        deadlines.run(socket, HANDSHAKE_TIMEOUT_MILLIS.toLong(), socket::startHandshake)
        if (socket.session.protocol != TLS_1_3) throw SSLProtocolFailure()
        val peer =
            socket.session.peerCertificates.firstOrNull() as? X509Certificate
                ?: throw SSLProtocolFailure()
        peer.checkValidity()
        if (!expectedTargetPin.matches(peer)) throw SSLProtocolFailure()
    }

    private fun processFrames(socket: SSLSocket, dispatcher: WireDonorDispatcher) {
        var requests = 0
        var responseBytes = 0L
        while (!stopping.get()) {
            socket.soTimeout = FRAME_TIMEOUT_MILLIS
            val frame =
                deadlines.run(socket, FRAME_TIMEOUT_MILLIS.toLong()) {
                    BoundedWireFrameIo.read(socket.inputStream)
                } ?: return
            val request = NormalizedWireCodec.decodeRequest(frame)
            val response = NormalizedWireCodec.encodeResponse(dispatcher.dispatch(request))
            deadlines.run(socket, WRITE_TIMEOUT_MILLIS) {
                BoundedWireFrameIo.write(socket.outputStream, response)
            }
            requests += 1
            responseBytes += response.size
            if (requests >= MAX_REQUESTS || responseBytes >= MAX_RESPONSE_BYTES) return
        }
    }

    override fun closeUntil(deadlineNanos: Long): DonorServerCloseOutcome {
        val lockResult = closeLock.tryLockUntil(deadlineNanos)
        var interrupted = lockResult.interrupted
        if (!lockResult.acquired) {
            if (interrupted) Thread.currentThread().interrupt()
            return DonorServerCloseOutcome.Incomplete()
        }
        return try {
            if (resourcesClosed) {
                DonorServerCloseOutcome.Closed
            } else {
                stopping.set(true)
                synchronized(stateMonitor) {
                    listener?.let(::closeListener)
                    closeSockets(registeredSockets)
                }
                acceptor?.interrupt()
                workers.shutdownNow()
                deadlines.shutdownNow()

                val acceptorResult = awaitThreadUntil(acceptor, deadlineNanos)
                interrupted = interrupted || acceptorResult.interrupted
                val workerResult = awaitExecutorUntil(workers, deadlineNanos)
                interrupted = interrupted || workerResult.interrupted
                val deadlineResult = deadlines.closeUntil(deadlineNanos)
                interrupted = interrupted || deadlineResult.interrupted

                val terminated =
                    acceptorTerminated && workersTerminated && deadlineSchedulerTerminated
                if (terminated) resourcesClosed = true
                if (terminated) {
                    DonorServerCloseOutcome.Closed
                } else {
                    DonorServerCloseOutcome.Incomplete()
                }
            }
        } catch (failure: RuntimeException) {
            DonorServerCloseOutcome.Incomplete(failure)
        } finally {
            closeLock.unlock()
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private class SSLProtocolFailure : RuntimeException()

    private companion object {
        const val TLS_1_3 = "TLSv1.3"
        const val NONCE_BYTES = 32
        const val ACCEPT_BACKLOG = 8
        const val MAX_SESSIONS = 4
        const val MAX_REQUESTS = 64
        const val MAX_RESPONSE_BYTES = 8L * 1024 * 1024
        const val ACCEPT_TIMEOUT_MILLIS = 1_000
        const val HANDSHAKE_TIMEOUT_MILLIS = 10_000
        const val HELLO_TIMEOUT_MILLIS = 5_000
        const val FRAME_TIMEOUT_MILLIS = 30_000
        const val WRITE_TIMEOUT_MILLIS = 10_000L
    }
}

internal fun closeSockets(sockets: Collection<Socket>) {
    sockets.forEach(::closeSocket)
}

private fun closeListener(listener: SSLServerSocket) {
    try {
        listener.close()
    } catch (_: java.io.IOException) {
        return
    } catch (_: RuntimeException) {
        return
    }
}
