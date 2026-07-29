package org.matrix.teesimulator.twophone

import java.security.MessageDigest
import java.util.UUID

sealed class ResponseCorrelationException(message: String) : RuntimeException(message) {
    class WrongVersion : ResponseCorrelationException("response protocol version mismatch")

    class WrongSession : ResponseCorrelationException("response session mismatch")

    class WrongRequestId : ResponseCorrelationException("response request id mismatch")

    class WrongMethod : ResponseCorrelationException("response method mismatch")

    class UnsolicitedResponse : ResponseCorrelationException("response was not requested")

    class DuplicateResponse : ResponseCorrelationException("response was already accepted")

    class UntrustedRequest : ResponseCorrelationException("outgoing request context is untrusted")

    class DuplicateRegistration : ResponseCorrelationException("request id was already registered")
}

class TargetResponseCorrelator(
    private val pair: PairIdentity,
    clientNonce: ByteArray,
    serverNonce: ByteArray,
) {
    private val trustedClientNonce = clientNonce.copyOf()
    private val trustedServerNonce = serverNonce.copyOf()
    private val trustedSessionId = deriveSessionId(pair, trustedClientNonce, trustedServerNonce)
    private val pending = mutableMapOf<UUID, PendingResponse>()
    private val completed = mutableSetOf<UUID>()

    val sessionId: ByteArray
        get() = trustedSessionId.copyOf()

    @Synchronized
    fun register(request: WireRequestEnvelope) {
        if (
            request.version != ProtocolVersion.V1 ||
                !MessageDigest.isEqual(request.sessionId, trustedSessionId) ||
                !MessageDigest.isEqual(request.clientNonce, trustedClientNonce) ||
                !MessageDigest.isEqual(request.serverNonce, trustedServerNonce)
        ) {
            throw ResponseCorrelationException.UntrustedRequest()
        }
        if (request.requestId in pending || request.requestId in completed) {
            throw ResponseCorrelationException.DuplicateRegistration()
        }
        pending[request.requestId] = PendingResponse(request.method)
    }

    @Synchronized
    fun accept(expectedRequestId: UUID, response: WireResponseEnvelope): WireOutcome {
        if (response.version != ProtocolVersion.V1) {
            throw ResponseCorrelationException.WrongVersion()
        }
        if (!MessageDigest.isEqual(response.sessionId, trustedSessionId)) {
            throw ResponseCorrelationException.WrongSession()
        }
        if (expectedRequestId in completed || response.requestId in completed) {
            throw ResponseCorrelationException.DuplicateResponse()
        }
        val expected =
            pending[expectedRequestId] ?: throw ResponseCorrelationException.UnsolicitedResponse()
        if (response.requestId != expectedRequestId) {
            throw ResponseCorrelationException.WrongRequestId()
        }
        if (response.method != expected.method) {
            throw ResponseCorrelationException.WrongMethod()
        }

        pending.remove(expectedRequestId)
        completed += expectedRequestId
        return response.outcome.defensiveCopy()
    }

    private data class PendingResponse(val method: Method)
}
