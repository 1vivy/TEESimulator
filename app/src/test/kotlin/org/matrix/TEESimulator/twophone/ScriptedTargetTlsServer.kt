package org.matrix.TEESimulator.twophone

import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import org.matrix.teesimulator.twophone.BoundedWireFrameIo
import org.matrix.teesimulator.twophone.DonorServerHello
import org.matrix.teesimulator.twophone.DonorTransportHelloCodec
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.WireErrorCode
import org.matrix.teesimulator.twophone.WireOutcome
import org.matrix.teesimulator.twophone.WireRequestEnvelope
import org.matrix.teesimulator.twophone.WireResponseEnvelope

internal enum class TargetServerScript {
    VALID_TWO,
    WRONG_SESSION,
    WRONG_REQUEST_ID,
    REPLAY_RESPONSE,
    OVERSIZED_FRAME,
    STALL_AFTER_REQUEST,
}

internal class ScriptedTargetTlsServer(
    private val rig: TargetLoopbackTestRig,
    private val script: TargetServerScript,
) : AutoCloseable {
    val backendInvocations = AtomicInteger()
    val requests = CopyOnWriteArrayList<WireRequestEnvelope>()
    val requestReceived = CountDownLatch(1)
    private val listener =
        rig.donorServerContext()
            .serverSocketFactory
            .createServerSocket(rig.endpointPort, 1, rig.endpointAddress) as SSLServerSocket
    private val thread = Thread(::run, "scripted-target-tls-server").apply { isDaemon = true }
    @Volatile private var socket: SSLSocket? = null
    @Volatile private var failure: Throwable? = null

    fun start() {
        listener.enabledProtocols = arrayOf("TLSv1.3")
        listener.needClientAuth = true
        thread.start()
    }

    fun awaitRequest() {
        check(requestReceived.await(5, TimeUnit.SECONDS))
    }

    fun assertHealthy() {
        failure?.let { throw AssertionError("scripted TLS server failed", it) }
    }

    private fun run() {
        try {
            val accepted = listener.accept() as SSLSocket
            socket = accepted
            accepted.use { connection ->
                connection.enabledProtocols = arrayOf("TLSv1.3")
                connection.needClientAuth = true
                connection.startHandshake()
                val hello =
                    checkNotNull(DonorTransportHelloCodec.readClient(connection.inputStream))
                val serverNonce = ByteArray(32) { (it + 17).toByte() }
                DonorTransportHelloCodec.writeServer(
                    connection.outputStream,
                    DonorServerHello(hello.nonce, serverNonce),
                )
                when (script) {
                    TargetServerScript.VALID_TWO -> repeat(2) { respondValid(connection) }
                    TargetServerScript.REPLAY_RESPONSE -> replay(connection)
                    TargetServerScript.WRONG_SESSION -> respondWrongSession(connection)
                    TargetServerScript.WRONG_REQUEST_ID -> respondWrongId(connection)
                    TargetServerScript.OVERSIZED_FRAME -> respondOversized(connection)
                    TargetServerScript.STALL_AFTER_REQUEST -> stall(connection)
                }
            }
        } catch (caught: Throwable) {
            if (script != TargetServerScript.STALL_AFTER_REQUEST) failure = caught
        }
    }

    private fun request(connection: SSLSocket): WireRequestEnvelope {
        val decoded =
            NormalizedWireCodec.decodeRequest(
                checkNotNull(BoundedWireFrameIo.read(connection.inputStream))
            )
        requests += decoded
        requestReceived.countDown()
        return decoded
    }

    private fun respondValid(connection: SSLSocket): WireResponseEnvelope {
        val incoming = request(connection)
        return response(incoming, incoming.sessionId, incoming.requestId).also { outgoing ->
            BoundedWireFrameIo.write(
                connection.outputStream,
                NormalizedWireCodec.encodeResponse(outgoing),
            )
        }
    }

    private fun replay(connection: SSLSocket) {
        val first = respondValid(connection)
        request(connection)
        BoundedWireFrameIo.write(connection.outputStream, NormalizedWireCodec.encodeResponse(first))
    }

    private fun respondWrongSession(connection: SSLSocket) {
        val incoming = request(connection)
        write(connection, response(incoming, ByteArray(32) { 0x55 }, incoming.requestId))
    }

    private fun respondWrongId(connection: SSLSocket) {
        val incoming = request(connection)
        write(connection, response(incoming, incoming.sessionId, UUID.randomUUID()))
    }

    private fun respondOversized(connection: SSLSocket) {
        request(connection)
        connection.outputStream.write(
            ByteBuffer.allocate(Int.SIZE_BYTES).putInt(NormalizedWireCodec.MAX_FRAME_BYTES).array()
        )
        connection.outputStream.flush()
    }

    private fun stall(connection: SSLSocket) {
        request(connection)
        connection.inputStream.read()
    }

    private fun write(connection: SSLSocket, response: WireResponseEnvelope) {
        BoundedWireFrameIo.write(
            connection.outputStream,
            NormalizedWireCodec.encodeResponse(response),
        )
    }

    private fun response(request: WireRequestEnvelope, session: ByteArray, id: UUID) =
        WireResponseEnvelope(
            request.version,
            session,
            id,
            request.method,
            WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD),
        )

    override fun close() {
        runCatching { socket?.close() }
        runCatching { listener.close() }
        thread.join(5_000)
    }
}
