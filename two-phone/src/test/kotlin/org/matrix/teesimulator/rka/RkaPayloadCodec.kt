package org.matrix.teesimulator.rka

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

object RkaPayloadCodec {
    fun decode(frame: RkaFrame): RkaPayload? {
        if (frame.error != ErrorCode.OK) {
            require(frame.kind == MessageKind.RESPONSE)
            require(frame.payload.isEmpty())
            return null
        }
        return PayloadReader(frame.payload).use { input ->
            val payload =
                when (frame.kind) {
                    MessageKind.REQUEST -> input.readRequest(frame.method)
                    MessageKind.RESPONSE -> input.readResponse(frame.method)
                }
            require(input.available() == 0)
            payload
        }
    }

    private fun PayloadReader.readRequest(method: Method): RkaPayload =
        when (method) {
            Method.GENERATE ->
                GenerateRequest(
                    logicalName = readUtf8(RkaLimits.LOGICAL_NAME_BYTES),
                    attestationChallenge = readSized16(1, RkaLimits.CHALLENGE_BYTES),
                    mutationId = readFixed(16),
                    purpose = readRequiredTag(1),
                    digest = readRequiredTag(1),
                    curve = readRequiredTag(1),
                )
            Method.GET_METADATA -> GetMetadataRequest(readFixed(32))
            Method.DELETE -> DeleteRequest(readFixed(32), readFixed(16))
            Method.BEGIN ->
                BeginRequest(
                    keyHandle = readFixed(32),
                    operationId = readFixed(16),
                    purpose = readRequiredTag(1),
                    digest = readRequiredTag(1),
                )
            Method.UPDATE ->
                UpdateRequest(
                    operationHandle = readFixed(32),
                    chunkIndex = readInt().toUInt(),
                    input = readSized32(RkaLimits.REQUEST_CHUNK_BYTES),
                )
            Method.FINISH ->
                FinishRequest(
                    operationHandle = readFixed(32),
                    input = readSized32(RkaLimits.REQUEST_CHUNK_BYTES),
                    signature = readSized32(0),
                )
            Method.ABORT -> AbortRequest(readFixed(32))
        }

    private fun PayloadReader.readResponse(method: Method): RkaPayload =
        when (method) {
            Method.GENERATE -> readGenerateResponse()
            Method.GET_METADATA -> {
                val metadata = readGenerateResponse()
                GetMetadataResponse(
                    metadata.keyHandle,
                    metadata.publicKeySpki,
                    metadata.certificateChain,
                    readLong().toULong(),
                )
            }
            Method.DELETE -> DeleteResponse(readLong().toULong())
            Method.BEGIN -> BeginResponse(readFixed(32))
            Method.UPDATE -> UpdateResponse(readSized32(RkaLimits.REQUEST_CHUNK_BYTES))
            Method.FINISH ->
                FinishResponse(
                    readSized32(
                        RkaReferenceCodec.MAX_FRAME_SIZE - RkaReferenceCodec.HEADER_SIZE - 4
                    )
                )
            Method.ABORT -> AbortResponse(readRequiredTag(1))
        }

    private fun PayloadReader.readGenerateResponse(): GenerateResponse {
        val keyHandle = readFixed(32)
        val publicKey = readSized16(1, 2_048)
        val count = readUnsignedByte()
        require(count in 1..RkaLimits.CERTIFICATE_COUNT)
        val certificates = List(count) { readSized32(RkaLimits.CERTIFICATE_BYTES, 1) }
        require(certificates.sumOf(ByteArray::size) <= RkaLimits.CERTIFICATE_AGGREGATE_BYTES)
        require(certificates.map(ByteArray::toHexString).toSet().size == certificates.size)
        return GenerateResponse(keyHandle, publicKey, certificates)
    }

    private class PayloadReader(payload: ByteArray) :
        DataInputStream(ByteArrayInputStream(payload)) {
        fun readFixed(size: Int): ByteArray = readNBytes(size).also { require(it.size == size) }

        fun readRequiredTag(required: Int): UByte =
            readUnsignedByte().also { require(it == required) }.toUByte()

        fun readSized16(minimum: Int, maximum: Int): ByteArray {
            val size = readUnsignedShort()
            require(size in minimum..maximum)
            return readFixed(size)
        }

        fun readSized32(maximum: Int, minimum: Int = 0): ByteArray {
            val size = readInt().toLong() and 0xffff_ffffL
            require(size in minimum.toLong()..maximum.toLong())
            return readFixed(size.toInt())
        }

        fun readUtf8(maximum: Int): String {
            val bytes = readSized16(1, maximum)
            val decoder =
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
            return decoder.decode(ByteBuffer.wrap(bytes)).toString().also {
                require('\u0000' !in it)
            }
        }
    }
}
