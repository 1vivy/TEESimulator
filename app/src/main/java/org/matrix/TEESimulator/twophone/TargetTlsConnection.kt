package org.matrix.TEESimulator.twophone

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import org.matrix.teesimulator.twophone.BoundedWireFrameIo
import org.matrix.teesimulator.twophone.DonorClientHello
import org.matrix.teesimulator.twophone.DonorTransportHelloCodec
import org.matrix.teesimulator.twophone.LifecycleRequestPayload
import org.matrix.teesimulator.twophone.NormalizedWireCodec
import org.matrix.teesimulator.twophone.ProtocolVersion
import org.matrix.teesimulator.twophone.ResponseCorrelationException
import org.matrix.teesimulator.twophone.SpkiPin
import org.matrix.teesimulator.twophone.TargetPublicProfile
import org.matrix.teesimulator.twophone.TargetResponseCorrelator
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireCodecException
import org.matrix.teesimulator.twophone.WireOutcome
import org.matrix.teesimulator.twophone.WireRequestEnvelope
import org.matrix.teesimulator.twophone.WireTransportFramingException

internal interface TargetConnection {
    val protocol: String

    fun exchange(
        sequence: ULong,
        payload: LifecycleRequestPayload,
        caller: WireCallerIdentity,
        deadline: Instant,
        cancellation: TargetCallCancellation,
    ): WireOutcome

    fun close()
}

internal fun interface TargetConnectionFactory {
    fun connect(deadline: Instant, cancellation: TargetCallCancellation): TargetConnection
}

internal class JsseTargetConnectionFactory(
    private val profile: TargetPublicProfile,
    private val sslContext: SSLContext,
    private val random: SecureRandom,
    private val now: () -> Instant,
) : TargetConnectionFactory {
    override fun connect(
        deadline: Instant,
        cancellation: TargetCallCancellation,
    ): TargetTlsConnection {
        checkCancellation(cancellation, deadline, now)
        val address = InetAddress.getByAddress(profile.donorEndpoint.address)
        val raw = Socket()
        var tls: SSLSocket? = null
        val cancellationRegistration =
            cancellation.onCancel {
                runCatching { tls?.close() }
                runCatching { raw.close() }
            }
        try {
            raw.connect(
                InetSocketAddress(address, profile.donorEndpoint.port),
                remainingMillis(deadline, now),
            )
            val peerIdentity = address.hostAddress
            tls =
                sslContext.socketFactory.createSocket(
                    raw,
                    peerIdentity,
                    profile.donorEndpoint.port,
                    true,
                ) as SSLSocket
            tls.enabledProtocols = arrayOf(TLS_1_3)
            tls.sslParameters =
                tls.sslParameters.apply {
                    protocols = arrayOf(TLS_1_3)
                    endpointIdentificationAlgorithm = ENDPOINT_IDENTIFICATION
                }
            tls.soTimeout = remainingMillis(deadline, now)
            tls.startHandshake()
            authenticatePeer(tls, profile)

            val clientNonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            DonorTransportHelloCodec.writeClient(tls.outputStream, DonorClientHello(clientNonce))
            tls.soTimeout = remainingMillis(deadline, now)
            val hello =
                DonorTransportHelloCodec.readServer(tls.inputStream)
                    ?: throw TargetSessionException.PeerAuthentication()
            if (!java.security.MessageDigest.isEqual(clientNonce, hello.clientNonce)) {
                throw TargetSessionException.NonceMismatch()
            }
            return TargetTlsConnection(tls, profile, clientNonce, hello.serverNonce, now)
        } catch (failure: SSLHandshakeException) {
            closeRejected(tls, raw)
            if (failure.hasCause<PinnedDonorCertificateException>()) {
                throw TargetSessionException.DonorPinMismatch(failure)
            }
            throw TargetSessionException.PeerAuthentication(failure)
        } catch (failure: TargetSessionException) {
            closeRejected(tls, raw)
            throw failure
        } catch (failure: Exception) {
            closeRejected(tls, raw)
            if (cancellation.isCancelled) throw TargetSessionException.Cancelled()
            throw TargetSessionException.TransportFailure(failure)
        } finally {
            cancellationRegistration.close()
        }
    }

    private fun authenticatePeer(socket: SSLSocket, profile: TargetPublicProfile) {
        if (socket.session.protocol != TLS_1_3) throw TargetSessionException.TlsProtocol()
        val leaf =
            socket.session.peerCertificates.firstOrNull() as? X509Certificate
                ?: throw TargetSessionException.PeerAuthentication()
        val expected = SpkiPin.parse(profile.donorPin.toString())
        if (!expected.matches(leaf)) throw TargetSessionException.DonorPinMismatch()
    }

    private fun closeRejected(tls: SSLSocket?, raw: Socket) {
        runCatching { tls?.close() }
        runCatching { raw.close() }
    }
}

internal class TargetTlsConnection(
    private val socket: SSLSocket,
    profile: TargetPublicProfile,
    clientNonce: ByteArray,
    serverNonce: ByteArray,
    private val now: () -> Instant,
) : TargetConnection {
    private val stableClientNonce = clientNonce.copyOf()
    private val stableServerNonce = serverNonce.copyOf()
    private val correlator =
        TargetResponseCorrelator(profile.pairIdentity, stableClientNonce, stableServerNonce)
    private val requestIdPrefix = java.nio.ByteBuffer.wrap(correlator.sessionId).long

    override val protocol: String
        get() = socket.session.protocol

    override fun exchange(
        sequence: ULong,
        payload: LifecycleRequestPayload,
        caller: WireCallerIdentity,
        deadline: Instant,
        cancellation: TargetCallCancellation,
    ): WireOutcome {
        checkCancellation(cancellation, deadline, now)
        val requestId = UUID(requestIdPrefix, sequence.toLong())
        val request =
            WireRequestEnvelope(
                ProtocolVersion.V1,
                correlator.sessionId,
                stableClientNonce,
                stableServerNonce,
                sequence,
                requestId,
                NormalizedWireCodec.payloadHash(payload),
                payload.method,
                deadline,
                caller,
                payload,
            )
        correlator.register(request)
        val cancellationRegistration = cancellation.onCancel { runCatching { socket.close() } }
        try {
            socket.soTimeout = remainingMillis(deadline, now)
            BoundedWireFrameIo.write(
                socket.outputStream,
                NormalizedWireCodec.encodeRequest(request),
            )
            socket.soTimeout = remainingMillis(deadline, now)
            val responseFrame =
                BoundedWireFrameIo.read(socket.inputStream)
                    ?: throw IOException("donor closed before response")
            val response = NormalizedWireCodec.decodeResponse(responseFrame)
            return correlator.accept(requestId, response)
        } catch (failure: ResponseCorrelationException.DuplicateResponse) {
            throw TargetSessionException.ReplayRejected(failure)
        } catch (failure: ResponseCorrelationException.WrongSession) {
            throw TargetSessionException.WrongSession(failure)
        } catch (failure: ResponseCorrelationException.WrongRequestId) {
            throw TargetSessionException.WrongRequestId(failure)
        } catch (failure: ResponseCorrelationException) {
            throw TargetSessionException.CorrelationFailure(failure)
        } catch (failure: WireTransportFramingException) {
            throw TargetSessionException.FramingFailure(failure)
        } catch (failure: WireCodecException) {
            throw TargetSessionException.FramingFailure(failure)
        } catch (failure: IOException) {
            if (cancellation.isCancelled) throw TargetSessionException.Cancelled()
            if (now().isAfter(deadline)) throw TargetSessionException.DeadlineExceeded()
            throw TargetSessionException.TransportFailure(failure)
        } finally {
            cancellationRegistration.close()
        }
    }

    override fun close() = socket.close()
}

private fun checkCancellation(
    cancellation: TargetCallCancellation,
    deadline: Instant,
    now: () -> Instant,
) {
    if (cancellation.isCancelled) throw TargetSessionException.Cancelled()
    if (!now().isBefore(deadline)) throw TargetSessionException.DeadlineExceeded()
}

private fun remainingMillis(deadline: Instant, now: () -> Instant): Int {
    val remaining = Duration.between(now(), deadline).toMillis()
    if (remaining <= 0) throw TargetSessionException.DeadlineExceeded()
    return remaining.coerceAtMost(Int.MAX_VALUE.toLong()).toInt().coerceAtLeast(1)
}

private inline fun <reified T : Throwable> Throwable.hasCause(): Boolean {
    var current: Throwable? = this
    while (current != null) {
        if (current is T) return true
        current = current.cause
    }
    return false
}

private const val TLS_1_3 = "TLSv1.3"
private const val ENDPOINT_IDENTIFICATION = "HTTPS"
private const val NONCE_BYTES = 32
