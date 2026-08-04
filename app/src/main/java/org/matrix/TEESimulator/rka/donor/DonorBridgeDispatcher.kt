package org.matrix.TEESimulator.rka.donor

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import org.matrix.TEESimulator.rka.bridge.BridgeErrorCode
import org.matrix.TEESimulator.rka.bridge.BridgeLimits
import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.bridge.CandidateBridgeOperation
import org.matrix.TEESimulator.rka.bridge.Hash32
import org.matrix.TEESimulator.rka.bridge.PublicBytes
import org.matrix.TEESimulator.rka.journal.RkpOpaqueHandle

internal object DonorBridgeDispatcher {
    fun dispatch(
        command: BridgeMessage.CandidateCommand,
        backend: DonorKeyMintBackend,
    ): BridgeMessage {
        val candidate = command.candidateId
        val payload = command.payload.copyBytes()
        return try {
            val result =
                when (command.operation) {
                    CandidateBridgeOperation.GENERATE ->
                        backend.generate(candidate, DonorBridgeCodec.decodeGenerate(payload)).map {
                            DonorBridgeCodec.keyReply(it)
                        }
                    CandidateBridgeOperation.GET ->
                        backend.get(candidate, DonorBridgeCodec.decodeKeyHandle(payload)).map {
                            DonorBridgeCodec.keyReply(it)
                        }
                    CandidateBridgeOperation.LIST -> {
                        if (payload.isNotEmpty()) failure(DonorError.INVALID_REQUEST)
                        else success(DonorBridgeCodec.listReply(backend.list(candidate)))
                    }
                    CandidateBridgeOperation.DELETE ->
                        backend.delete(candidate, DonorBridgeCodec.decodeKeyHandle(payload)).map {
                            ByteArray(0)
                        }
                    CandidateBridgeOperation.BEGIN ->
                        backend.begin(candidate, DonorBridgeCodec.decodeKeyHandle(payload)).map {
                            it.handle.copyBytes()
                        }
                    CandidateBridgeOperation.UPDATE_AAD -> {
                        val (handle, input) = DonorBridgeCodec.decodeOperation(payload)
                        backend.updateAad(candidate, handle, input).map {
                            DonorBridgeCodec.updateReply(it)
                        }
                    }
                    CandidateBridgeOperation.UPDATE -> {
                        val (handle, input) = DonorBridgeCodec.decodeOperation(payload)
                        backend.update(candidate, handle, input).map {
                            DonorBridgeCodec.updateReply(it)
                        }
                    }
                    CandidateBridgeOperation.FINISH -> {
                        val (handle, input) = DonorBridgeCodec.decodeOperation(payload)
                        backend.finish(candidate, handle, input).map {
                            DonorBridgeCodec.bounded(it.signature.copyBytes())
                        }
                    }
                    CandidateBridgeOperation.ABORT -> {
                        val (handle, input) = DonorBridgeCodec.decodeOperation(payload)
                        if (input.isNotEmpty()) failure(DonorError.INVALID_REQUEST)
                        else backend.abort(candidate, handle).map { ByteArray(0) }
                    }
                }
            when (result) {
                is DonorResult.Success ->
                    BridgeMessage.CandidateReply(
                        command.requestId,
                        command.operation,
                        PublicBytes.of(result.value, BridgeLimits.MAX_FRAME_BYTES - 5),
                    )
                is DonorResult.Failure ->
                    BridgeMessage.Error(
                        command.requestId,
                        result.code.bridgeCode(),
                        Hash32.of(detailHash(result.code)),
                    )
            }
        } catch (_: Exception) {
            BridgeMessage.Error(
                command.requestId,
                BridgeErrorCode.INVALID_REQUEST,
                Hash32.of(detailHash(DonorError.INVALID_REQUEST)),
            )
        } finally {
            payload.fill(0)
        }
    }

    private fun DonorError.bridgeCode(): BridgeErrorCode =
        when (this) {
            DonorError.INVALID_REQUEST,
            DonorError.STALE_HANDLE -> BridgeErrorCode.INVALID_REQUEST
            DonorError.CAPACITY -> BridgeErrorCode.CAPACITY
            DonorError.QUARANTINED,
            DonorError.OPERATION_LOST -> BridgeErrorCode.POLICY_REJECTED
        }

    private fun detailHash(error: DonorError): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest("RKA-DONOR-KEYMINT-v1\u0000${error.name}".toByteArray())

    private fun success(bytes: ByteArray): DonorResult<ByteArray> = DonorResult.Success(bytes)

    private fun failure(error: DonorError): DonorResult<ByteArray> = DonorResult.Failure(error)

    private fun <T> DonorResult<T>.map(transform: (T) -> ByteArray): DonorResult<ByteArray> =
        when (this) {
            is DonorResult.Success -> DonorResult.Success(transform(value))
            is DonorResult.Failure -> this
        }
}

internal object DonorBridgeCodec {
    fun decodeGenerate(payload: ByteArray): DonorGenerateRequest =
        input(payload) {
            val alias = DonorKeyHandle.of(readFixed(16))
            val rkpHandle = RkpOpaqueHandle.from(readFixed(32))
            val challenge = readBounded(16, 64)
            val aaid = readBounded(1, 131_072)
            val transcript = readBounded(1, BridgeLimits.MAX_TOTAL_INPUT_BYTES)
            val count = readUnsignedByte()
            require(count in 2..BridgeLimits.MAX_CHAIN_CERTIFICATES)
            var total = 0
            val chain =
                List(count) {
                    readBounded(1, BridgeLimits.MAX_CERTIFICATE_BYTES).also {
                        total = Math.addExact(total, it.size)
                        require(total <= BridgeLimits.MAX_CHAIN_BYTES)
                    }
                }
            DonorGenerateRequest(alias, rkpHandle, chain, challenge, aaid, transcript)
        }

    fun generateCommand(request: DonorGenerateRequest): ByteArray = output {
        write(request.aliasHandle.copyBytes())
        write(request.rkpHandle.copyBytes())
        writeBounded(request.challenge)
        writeBounded(request.aaid)
        writeBounded(request.transcript)
        writeByte(request.rkpChain.size)
        request.rkpChain.forEach { writeBounded(it) }
    }

    fun decodeKeyHandle(payload: ByteArray): DonorKeyHandle =
        input(payload) { DonorKeyHandle.of(readFixed(16)) }

    fun keyCommand(handle: DonorKeyHandle): ByteArray = handle.copyBytes()

    fun decodeOperation(payload: ByteArray): Pair<DonorOperationHandle, ByteArray> =
        input(payload) {
            DonorOperationHandle.of(readFixed(16)) to readBounded(0, BridgeLimits.MAX_UPDATE_BYTES)
        }

    fun operationCommand(handle: DonorOperationHandle, input: ByteArray): ByteArray = output {
        write(handle.copyBytes())
        writeBounded(input)
    }

    fun keyReply(key: DonorPublicKey): ByteArray = output {
        write(key.handle.copyBytes())
        writeBounded(key.publicSpki.copyBytes())
        writeByte(key.certificateChain.size)
        key.certificateChain.forEach { writeBounded(it.copyBytes()) }
        writeBounded(key.transcriptSignature.copyBytes())
    }

    fun listReply(handles: List<DonorKeyHandle>): ByteArray = output {
        require(handles.size <= BridgeLimits.MAX_PUBLIC_KEYS)
        writeByte(handles.size)
        handles.forEach { write(it.copyBytes()) }
    }

    fun updateReply(update: DonorUpdateResult): ByteArray = output {
        writeInt(update.consumed)
        writeBounded(update.output.copyBytes())
    }

    fun bounded(value: ByteArray): ByteArray = output { writeBounded(value) }

    private inline fun <T> input(payload: ByteArray, block: DataInputStream.() -> T): T =
        DataInputStream(ByteArrayInputStream(payload)).use {
            val result = it.block()
            require(it.available() == 0)
            result
        }

    private inline fun output(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use(block)
            bytes.toByteArray()
        }

    private fun DataInputStream.readBounded(minimum: Int, maximum: Int): ByteArray {
        val length = readInt().toLong() and 0xffff_ffffL
        require(length in minimum.toLong()..maximum.toLong())
        return readFixed(length.toInt())
    }

    private fun DataInputStream.readFixed(size: Int): ByteArray = ByteArray(size).also(::readFully)

    private fun DataOutputStream.writeBounded(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }
}
