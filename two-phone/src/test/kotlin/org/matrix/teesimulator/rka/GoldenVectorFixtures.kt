package org.matrix.teesimulator.rka

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

object GoldenVectorFixtures {
    val methods = Method.entries

    fun lifecycleFrames(transport: TransportKind): List<Pair<String, RkaFrame>> =
        methods.flatMapIndexed { index, method ->
            val request =
                frame(
                    transport = transport,
                    method = method,
                    kind = MessageKind.REQUEST,
                    sequence = (index * 2 + 1).toULong(),
                    payload = requestPayload(method),
                    requestSeed = 0x20 + index,
                )
            val response =
                frame(
                    transport = transport,
                    method = method,
                    kind = MessageKind.RESPONSE,
                    sequence = (index * 2 + 2).toULong(),
                    payload = responsePayload(method),
                    requestSeed = 0x20 + index,
                )
            listOf(
                "${method.name.lowercase()}-request" to request,
                "${method.name.lowercase()}-response" to response,
            )
        }

    fun changedReplayFrame(): RkaFrame {
        val original = frame()
        return original.copy(
            payload = original.payload.copyOf().also { it[55] = (it[55].toInt() xor 1).toByte() }
        )
    }

    fun frame(
        transport: TransportKind = TransportKind.DIRECT_PINNED_TLS,
        method: Method = Method.GENERATE,
        kind: MessageKind = MessageKind.REQUEST,
        error: ErrorCode = ErrorCode.OK,
        sequence: ULong = 1u,
        profileEpoch: ULong = 7u,
        payload: ByteArray = requestPayload(method),
        sessionSeed: Int = 0x10,
        requestSeed: Int = 0x20,
    ): RkaFrame =
        RkaFrame(
            kind = kind,
            transport = transport,
            method = method,
            error = error,
            profileEpoch = profileEpoch,
            sequence = sequence,
            deadlineUnixMillis = 1_800_000_120_000u,
            sessionId = bytes(32, sessionSeed),
            requestId = bytes(16, requestSeed),
            clientNonce = bytes(32, 0x30),
            serverNonce = bytes(32, 0x50),
            candidateTlsPin = bytes(32, 0x70),
            peerTlsPin =
                bytes(32, if (transport == TransportKind.DIRECT_PINNED_TLS) 0x90 else 0xb0),
            donorFingerprint = bytes(32, 0xd0),
            callerUid = 10_123u,
            callerIdentityHash = bytes(32, 0x01),
            payload = payload,
        )

    fun requestPayload(method: Method): ByteArray = bytes {
        when (method) {
            Method.GENERATE -> {
                writeUtf8("fixture-signing-key")
                writeSized(bytes(32, 0x41))
                write(bytes(16, 0x61))
                writeByte(1)
                writeByte(1)
                writeByte(1)
            }
            Method.GET_METADATA -> write(bytes(32, 0x81))
            Method.DELETE -> {
                write(bytes(32, 0x81))
                write(bytes(16, 0x61))
            }
            Method.BEGIN -> {
                write(bytes(32, 0x81))
                write(bytes(16, 0xa1))
                writeByte(1)
                writeByte(1)
            }
            Method.UPDATE -> {
                write(bytes(32, 0xc1))
                writeInt(0)
                writeLarge("update".encodeToByteArray())
            }
            Method.FINISH -> {
                write(bytes(32, 0xc1))
                writeLarge("finish".encodeToByteArray())
                writeLarge(byteArrayOf())
            }
            Method.ABORT -> write(bytes(32, 0xc1))
        }
    }

    fun responsePayload(method: Method): ByteArray = bytes {
        when (method) {
            Method.GENERATE -> writePublicMetadata()
            Method.GET_METADATA -> {
                writePublicMetadata()
                writeLong(3)
            }
            Method.DELETE -> writeLong(4)
            Method.BEGIN -> write(bytes(32, 0xc1))
            Method.UPDATE -> writeLarge("updated".encodeToByteArray())
            Method.FINISH -> writeLarge(bytes(64, 0xe1))
            Method.ABORT -> writeByte(1)
        }
    }

    private fun DataOutputStream.writePublicMetadata() {
        write(bytes(32, 0x81))
        writeSized(byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03))
        writeByte(1)
        writeInt(5)
        write(byteArrayOf(0x30, 0x03, 0x04, 0x05, 0x06))
    }

    private fun bytes(block: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use(block)
            bytes.toByteArray()
        }

    private fun DataOutputStream.writeUtf8(value: String) = writeSized(value.encodeToByteArray())

    private fun DataOutputStream.writeSized(value: ByteArray) {
        writeShort(value.size)
        write(value)
    }

    private fun DataOutputStream.writeLarge(value: ByteArray) {
        writeInt(value.size)
        write(value)
    }

    private fun bytes(size: Int, seed: Int): ByteArray =
        ByteArray(size) { index -> (seed + index).toByte() }
}
