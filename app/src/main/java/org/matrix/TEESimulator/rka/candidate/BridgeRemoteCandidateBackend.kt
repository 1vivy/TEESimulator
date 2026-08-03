package org.matrix.TEESimulator.rka.candidate

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.util.concurrent.atomic.AtomicLong
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.rka.bridge.BridgeError
import org.matrix.TEESimulator.rka.bridge.BridgeErrorCode
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.BridgeResult
import org.matrix.TEESimulator.rka.bridge.BrokerBridgeFactory
import org.matrix.TEESimulator.rka.bridge.CandidateBridgeOperation
import org.matrix.TEESimulator.rka.bridge.PublicBytes
import org.matrix.TEESimulator.rka.bridge.RequestId

internal class BridgeRemoteCandidateBackend(
    private val exchange: (BridgeMessage) -> BridgeResult<BridgeMessage> =
        BrokerBridgeFactory::exchangeCandidate
) : RemoteCandidateBackend {
    private val requestIds = AtomicLong()

    override fun generate(command: RemoteGenerateCommand): CandidateResult<RemoteKeyMaterial> =
        exchange(
            CandidateBridgeOperation.GENERATE,
            CandidateBridgePayloadCodec.generateCommand(command),
        ) {
            CandidateBridgePayloadCodec.decodeGenerate(it)
        }

    override fun get(handle: RemoteKeyHandle): CandidateResult<Unit> =
        unit(CandidateBridgeOperation.GET, CandidateBridgePayloadCodec.handleCommand(handle))

    override fun list(identityHash: IdentityHash): CandidateResult<List<RemoteKeyHandle>> =
        exchange(
            CandidateBridgeOperation.LIST,
            CandidateBridgePayloadCodec.identityCommand(identityHash),
        ) {
            CandidateBridgePayloadCodec.decodeHandles(it)
        }

    override fun delete(handle: RemoteKeyHandle): CandidateResult<Unit> =
        unit(CandidateBridgeOperation.DELETE, CandidateBridgePayloadCodec.handleCommand(handle))

    override fun begin(handle: RemoteKeyHandle): CandidateResult<RemoteOperationHandle> =
        exchange(
            CandidateBridgeOperation.BEGIN,
            CandidateBridgePayloadCodec.handleCommand(handle),
        ) {
            RemoteOperationHandle.of(CandidateBridgePayloadCodec.decodeFixed(it, 16))
        }

    override fun updateAad(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<Unit> =
        unit(
            CandidateBridgeOperation.UPDATE_AAD,
            CandidateBridgePayloadCodec.operationCommand(handle, input),
        )

    override fun update(handle: RemoteOperationHandle, input: ByteArray): CandidateResult<Unit> =
        unit(
            CandidateBridgeOperation.UPDATE,
            CandidateBridgePayloadCodec.operationCommand(handle, input),
        )

    override fun finish(
        handle: RemoteOperationHandle,
        input: ByteArray,
    ): CandidateResult<ByteArray> =
        exchange(
            CandidateBridgeOperation.FINISH,
            CandidateBridgePayloadCodec.operationCommand(handle, input),
        ) {
            CandidateBridgePayloadCodec.decodeOutput(it)
        }

    override fun abort(handle: RemoteOperationHandle): CandidateResult<Unit> =
        unit(
            CandidateBridgeOperation.ABORT,
            CandidateBridgePayloadCodec.operationCommand(handle, ByteArray(0)),
        )

    override fun peerDied() = Unit

    private fun unit(
        operation: CandidateBridgeOperation,
        payload: ByteArray,
    ): CandidateResult<Unit> = exchange(operation, payload) { bytes -> require(bytes.isEmpty()) }

    private fun <T> exchange(
        operation: CandidateBridgeOperation,
        payload: ByteArray,
        decode: (ByteArray) -> T,
    ): CandidateResult<T> {
        val requestId = RequestId(requestIds.incrementAndGet())
        val request =
            BridgeMessage.CandidateCommand(
                requestId,
                operation,
                PublicBytes.of(payload, BridgeLimits.MAX_FRAME_BYTES - 5),
            )
        payload.fill(0)
        return when (val result = exchange(request)) {
            is BridgeResult.Failure -> {
                SystemLogger.warning(
                    "RKA candidate bridge unavailable: category=${category(result.error)}"
                )
                CandidateResult.Failure(map(result.error))
            }
            is BridgeResult.Success -> {
                val response = result.value
                try {
                    when (response) {
                        is BridgeMessage.Error -> CandidateResult.Failure(map(response.code))
                        is BridgeMessage.CandidateReply -> {
                            if (
                                response.requestId != requestId || response.operation != operation
                            ) {
                                CandidateResult.Failure(CandidateError.TRANSPORT)
                            } else {
                                val bytes = response.payload.copyBytes()
                                try {
                                    CandidateResult.Success(decode(bytes))
                                } catch (_: IllegalArgumentException) {
                                    CandidateResult.Failure(CandidateError.QUARANTINED)
                                } catch (_: EOFException) {
                                    CandidateResult.Failure(CandidateError.QUARANTINED)
                                } finally {
                                    bytes.fill(0)
                                }
                            }
                        }
                        else -> CandidateResult.Failure(CandidateError.TRANSPORT)
                    }
                } finally {
                    response.close()
                }
            }
        }
    }

    private fun map(error: BridgeError): CandidateError =
        when (error) {
            BridgeError.Capacity,
            BridgeError.QueueSaturated -> CandidateError.CAPACITY
            BridgeError.TrustedStateMissing,
            BridgeError.TrustedStateInvalid,
            BridgeError.TrustedStateChanged,
            BridgeError.PeerIdentityMismatch,
            BridgeError.PeerIdentityChanged,
            BridgeError.SocketPolicy,
            BridgeError.SelinuxDenied -> CandidateError.POLICY_REJECTED
            else -> CandidateError.TRANSPORT
        }

    private fun map(error: BridgeErrorCode): CandidateError =
        when (error) {
            BridgeErrorCode.INVALID_REQUEST -> CandidateError.INVALID_REQUEST
            BridgeErrorCode.POLICY_REJECTED -> CandidateError.POLICY_REJECTED
            BridgeErrorCode.CAPACITY -> CandidateError.CAPACITY
            else -> CandidateError.TRANSPORT
        }

    private fun category(error: BridgeError): String =
        when (error) {
            BridgeError.DeadlineExceeded -> "DEADLINE"
            BridgeError.PeerDied -> "PEER_DIED"
            BridgeError.PeerIdentityMismatch -> "PEER_IDENTITY"
            BridgeError.PeerIdentityChanged -> "PEER_IDENTITY_CHANGED"
            BridgeError.TrustedStateMissing -> "TRUSTED_STATE_MISSING"
            BridgeError.TrustedStateInvalid -> "TRUSTED_STATE_INVALID"
            BridgeError.TrustedStateChanged -> "TRUSTED_STATE_CHANGED"
            BridgeError.SocketPolicy -> "SOCKET_POLICY"
            BridgeError.SocketCreateDenied -> "SOCKET_CREATE"
            BridgeError.SocketChownDenied -> "SOCKET_CHOWN"
            BridgeError.SocketChmodDenied -> "SOCKET_CHMOD"
            BridgeError.SocketLabelDenied -> "SOCKET_LABEL"
            BridgeError.SocketBindDenied -> "SOCKET_CONNECT"
            BridgeError.SocketPathChanged -> "SOCKET_PATH_CHANGED"
            BridgeError.SelinuxDenied -> "SELINUX"
            BridgeError.Io -> "IO"
            else -> "PROTOCOL"
        }
}

internal object CandidateBridgePayloadCodec {
    fun generateCommand(command: RemoteGenerateCommand): ByteArray = output {
        write(command.aliasHandle.copyBytes())
        write(command.identityHash.copyBytes())
        writeBounded(command.challenge, 1, 128 * 1024)
        writeBounded(command.aaidDer, 1, 128 * 1024)
    }

    fun handleCommand(handle: RemoteKeyHandle): ByteArray = handle.copyBytes()

    fun identityCommand(identityHash: IdentityHash): ByteArray = identityHash.copyBytes()

    fun operationCommand(handle: RemoteOperationHandle, input: ByteArray): ByteArray = output {
        write(handle.copyBytes())
        writeBounded(input, 0, BridgeLimits.MAX_UPDATE_BYTES)
    }

    fun generateReply(material: RemoteKeyMaterial): ByteArray = output {
        write(material.handle.copyBytes())
        writeLong(material.donorEpoch)
        writeLong(material.profileEpoch)
        writeByte(material.characteristics.algorithm.ordinal)
        writeByte(material.characteristics.curve.ordinal)
        writeByte(material.characteristics.purposes.single().ordinal)
        writeByte(material.characteristics.digests.single().ordinal)
        writeByte(material.characteristics.securityLevel.ordinal)
        val chain = material.certificateChain
        require(chain.size in 2..BridgeLimits.MAX_CHAIN_CERTIFICATES)
        require(chain.sumOf(ByteArray::size) <= BridgeLimits.MAX_CHAIN_BYTES)
        writeByte(chain.size)
        chain.forEach {
            require(it.size in 1..BridgeLimits.MAX_CERTIFICATE_BYTES)
            writeBounded(it, 1, BridgeLimits.MAX_CERTIFICATE_BYTES)
        }
    }

    fun handlesReply(handles: List<RemoteKeyHandle>): ByteArray = output {
        require(handles.size <= BridgeLimits.MAX_PUBLIC_KEYS)
        writeByte(handles.size)
        handles.forEach { write(it.copyBytes()) }
    }

    fun operationReply(handle: RemoteOperationHandle): ByteArray = handle.copyBytes()

    fun outputReply(output: ByteArray): ByteArray = output {
        writeBounded(output, 0, BridgeLimits.MAX_FRAME_BYTES - 4)
    }

    fun decodeGenerate(bytes: ByteArray): RemoteKeyMaterial =
        input(bytes) {
            val handle = RemoteKeyHandle.of(readFixed(16))
            val donorEpoch = readLong()
            val profileEpoch = readLong()
            require(donorEpoch >= 0 && profileEpoch >= 0)
            val characteristics =
                CandidateCharacteristics(
                    enumValue<CandidateAlgorithm>(),
                    enumValue<CandidateCurve>(),
                    setOf(enumValue<CandidatePurpose>()),
                    setOf(enumValue<CandidateDigest>()),
                    enumValue<CandidateSecurityLevel>(),
                )
            val count = readUnsignedByte()
            require(count in 2..BridgeLimits.MAX_CHAIN_CERTIFICATES)
            var total = 0
            val chain =
                List(count) {
                    val certificate = readBounded(1, BridgeLimits.MAX_CERTIFICATE_BYTES)
                    total = Math.addExact(total, certificate.size)
                    require(total <= BridgeLimits.MAX_CHAIN_BYTES)
                    certificate
                }
            RemoteKeyMaterial(handle, donorEpoch, profileEpoch, chain, characteristics)
        }

    fun decodeHandles(bytes: ByteArray): List<RemoteKeyHandle> =
        input(bytes) {
            val count = readUnsignedByte()
            require(count <= BridgeLimits.MAX_PUBLIC_KEYS)
            List(count) { RemoteKeyHandle.of(readFixed(16)) }
        }

    fun decodeFixed(bytes: ByteArray, size: Int): ByteArray = input(bytes) { readFixed(size) }

    fun decodeOutput(bytes: ByteArray): ByteArray =
        input(bytes) { readBounded(0, BridgeLimits.MAX_FRAME_BYTES - 4) }

    private inline fun output(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use(block)
            bytes.toByteArray()
        }

    private inline fun <T> input(bytes: ByteArray, block: DataInputStream.() -> T): T =
        DataInputStream(ByteArrayInputStream(bytes)).use {
            val value = it.block()
            require(it.available() == 0)
            value
        }

    private fun DataOutputStream.writeBounded(bytes: ByteArray, minimum: Int, maximum: Int) {
        require(bytes.size in minimum..maximum)
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataInputStream.readBounded(minimum: Int, maximum: Int): ByteArray {
        val length = readInt()
        require(length in minimum..maximum)
        return readFixed(length)
    }

    private fun DataInputStream.readFixed(size: Int): ByteArray = ByteArray(size).also(::readFully)

    private inline fun <reified T : Enum<T>> DataInputStream.enumValue(): T {
        val value = readUnsignedByte()
        return enumValues<T>().getOrNull(value) ?: throw IllegalArgumentException()
    }
}
