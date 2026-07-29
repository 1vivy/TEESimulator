package org.matrix.teesimulator.twophone

import java.nio.ByteBuffer
import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs

class NormalizedWireCodecTest {
    private val sessionId = bytes(32, 1)
    private val clientNonce = bytes(32, 2)
    private val serverNonce = bytes(32, 3)
    private val requestId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val generationId = UUID.fromString("10000000-0000-0000-0000-000000000001")
    private val deletionId = UUID.fromString("20000000-0000-0000-0000-000000000002")
    private val operationId = UUID.fromString("30000000-0000-0000-0000-000000000003")
    private val keyId = UUID.fromString("40000000-0000-0000-0000-000000000004")
    private val caller = WireCallerIdentity("signer-sha256", "attestation-application-id")
    private val deadline = Instant.parse("2026-07-25T12:00:30.123456789Z")
    private val keyHandle = WireKeyHandle(keyId, bytes(32, 5))
    private val operationHandle = WireOperationHandle(operationId, keyId, bytes(32, 6))
    private val logicalNameHash = bytes(32, 7)
    private val keySpec =
        WireKeySpec(WireKeyAlgorithm.EC, WireEcCurve.P256, WireDigest.SHA256, WireKeyPurpose.SIGN)
    private val operationSpec = WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256)
    private val metadata =
        WireKeyMetadata(
            KeyState.ACTIVE,
            bytes(32, 9),
            bytes(65, 10),
            listOf(bytes(96, 11), bytes(97, 12)),
            keySpec,
        )

    @Test
    fun everyLifecycleRequestRoundTripsDeterministically() {
        val payloads =
            listOf(
                GenerateRequestPayload(generationId, logicalNameHash, bytes(32, 8), keySpec),
                ImportRequestPayload,
                GetMetadataRequestPayload(keyHandle),
                DeleteRequestPayload(deletionId, keyHandle),
                BeginRequestPayload(operationId, 0uL, keyHandle, operationSpec),
                UpdateAadRequestPayload(operationHandle, 1uL, "aad".encodeToByteArray()),
                UpdateRequestPayload(operationHandle, 2uL, "input".encodeToByteArray()),
                FinishRequestPayload(operationHandle, ULong.MAX_VALUE, bytes(3, 8)),
                AbortRequestPayload(operationHandle, 3uL),
            )

        payloads.forEachIndexed { index, payload ->
            val expected = request(payload, index.toULong())
            val encoded = NormalizedWireCodec.encodeRequest(expected)
            val actual = NormalizedWireCodec.decodeRequest(encoded)

            assertRequestEnvelope(expected, actual)
            assertContentEquals(encoded, NormalizedWireCodec.encodeRequest(actual))
        }
    }

    @Test
    fun everySupportedSuccessAndEveryStableErrorRoundTripsDeterministically() {
        val successes =
            listOf(
                GenerateResultPayload(generationId, keyHandle, metadata),
                GetMetadataResultPayload(metadata),
                DeleteResultPayload(deletionId),
                BeginResultPayload(operationHandle, 0uL),
                UpdateAadResultPayload(1uL),
                UpdateResultPayload(2uL, bytes(16, 14)),
                FinishResultPayload(3uL, bytes(64, 15)),
                AbortResultPayload(4uL),
            )

        successes.forEach { payload ->
            val expected = response(payload.method, WireOutcome.Success(payload))
            val encoded = NormalizedWireCodec.encodeResponse(expected)
            val actual = NormalizedWireCodec.decodeResponse(encoded)

            assertResponseEnvelope(expected, actual)
            assertContentEquals(encoded, NormalizedWireCodec.encodeResponse(actual))
        }

        WireErrorCode.entries.forEach { code ->
            val expected = response(Method.IMPORT, WireOutcome.Error(code))
            val encoded = NormalizedWireCodec.encodeResponse(expected)
            val actual = NormalizedWireCodec.decodeResponse(encoded)

            assertResponseEnvelope(expected, actual)
            assertContentEquals(encoded, NormalizedWireCodec.encodeResponse(actual))
        }
    }

    @Test
    fun importHasNoPrivatePayloadAndReturnsTypedUnsupportedError() {
        val decodedRequest =
            NormalizedWireCodec.decodeRequest(
                NormalizedWireCodec.encodeRequest(request(ImportRequestPayload))
            )
        assertIs<ImportRequestPayload>(decodedRequest.payload)

        val expected = response(Method.IMPORT, WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD))
        val decodedResponse =
            NormalizedWireCodec.decodeResponse(NormalizedWireCodec.encodeResponse(expected))
        val error = assertIs<WireOutcome.Error>(decodedResponse.outcome)
        assertEquals(WireErrorCode.UNSUPPORTED_METHOD, error.code)
    }

    @Test
    fun replayAndOperationHandleErrorsUseAppendedStableTags() {
        val replay =
            NormalizedWireCodec.encodeResponse(
                response(Method.UPDATE, WireOutcome.Error(WireErrorCode.REPLAY_CONFLICT))
            )
        val operationHandle =
            NormalizedWireCodec.encodeResponse(
                response(Method.UPDATE, WireOutcome.Error(WireErrorCode.INVALID_OPERATION_HANDLE))
            )

        assertEquals(0x300e, ByteBuffer.wrap(replay).getShort(62).toInt() and 0xffff)
        assertEquals(0x300f, ByteBuffer.wrap(operationHandle).getShort(62).toInt() and 0xffff)
        assertEquals(
            WireErrorCode.REPLAY_CONFLICT,
            assertIs<WireOutcome.Error>(NormalizedWireCodec.decodeResponse(replay).outcome).code,
        )
        assertEquals(
            WireErrorCode.INVALID_OPERATION_HANDLE,
            assertIs<WireOutcome.Error>(NormalizedWireCodec.decodeResponse(operationHandle).outcome)
                .code,
        )
        assertFailsWith<WireCodecException.UnknownErrorCode> {
            NormalizedWireCodec.decodeResponse(replay.mutatingShort(62, 0x3010))
        }
    }

    @Test
    fun frameHeaderUsesBoundedBigEndianFixedWidthValues() {
        val payload = FinishRequestPayload(operationHandle, ULong.MAX_VALUE, bytes(3, 8))
        val encoded = NormalizedWireCodec.encodeRequest(request(payload, ULong.MAX_VALUE))
        val buffer = ByteBuffer.wrap(encoded)

        assertEquals(encoded.size - Int.SIZE_BYTES, buffer.int)
        assertEquals(0x54504b31, buffer.int)
        assertEquals(1, buffer.short.toInt())
        assertEquals(1, buffer.get().toInt())
        assertEquals(8, buffer.short.toInt())
        assertEquals(0x1008, buffer.short.toInt())
        assertContentEquals(sessionId, ByteArray(32).also(buffer::get))
        assertContentEquals(clientNonce, ByteArray(32).also(buffer::get))
        assertContentEquals(serverNonce, ByteArray(32).also(buffer::get))
        assertEquals(-1L, buffer.long)
        assertEquals(requestId, UUID(buffer.long, buffer.long))
        assertContentEquals(
            NormalizedWireCodec.payloadHash(payload),
            ByteArray(32).also(buffer::get),
        )
        assertEquals(deadline.epochSecond, buffer.long)
        assertEquals(deadline.nano, buffer.int)
    }

    @Test
    fun canonicalPayloadHashRejectsChangedPayloadAndDeclaredHash() {
        val original = GenerateRequestPayload(generationId, logicalNameHash, bytes(32, 20), keySpec)
        val changed = GenerateRequestPayload(generationId, logicalNameHash, bytes(32, 21), keySpec)
        val originalHash = NormalizedWireCodec.payloadHash(original)

        assertContentEquals(originalHash, NormalizedWireCodec.payloadHash(original))
        assertFalse(originalHash.contentEquals(NormalizedWireCodec.payloadHash(changed)))
        assertFailsWith<WireCodecException.PayloadHashMismatch> {
            NormalizedWireCodec.encodeRequest(request(changed, payloadHash = originalHash))
        }
        assertFailsWith<WireCodecException.PayloadHashMismatch> {
            NormalizedWireCodec.encodeRequest(
                request(original, payloadHash = originalHash.copyOf().also { it[0]++ })
            )
        }

        val encoded = NormalizedWireCodec.encodeRequest(request(original))
        assertFailsWith<WireCodecException.PayloadHashMismatch> {
            NormalizedWireCodec.decodeRequest(encoded.copyOf().also { it[135]++ })
        }
        assertFailsWith<WireCodecException.PayloadHashMismatch> {
            NormalizedWireCodec.decodeRequest(
                encoded.copyOf().also { it[requestPayloadOffset() + 16]++ }
            )
        }
    }

    @Test
    fun normalizedSigningSpecsUseExplicitTagsAndRejectUnknownTags() {
        val generate =
            NormalizedWireCodec.encodeRequest(
                request(
                    GenerateRequestPayload(generationId, logicalNameHash, bytes(32, 8), keySpec)
                )
            )
        val keySpecOffset = requestPayloadOffset() + 16 + 32
        val keySpecTags = ByteBuffer.wrap(generate, keySpecOffset, 8)
        assertEquals(1, keySpecTags.short.toInt())
        assertEquals(1, keySpecTags.short.toInt())
        assertEquals(1, keySpecTags.short.toInt())
        assertEquals(1, keySpecTags.short.toInt())
        assertFailsWith<WireCodecException.UnknownSpecTag> {
            NormalizedWireCodec.decodeRequest(generate.mutatingShort(keySpecOffset, 0x7fff))
        }

        val begin =
            NormalizedWireCodec.encodeRequest(
                request(BeginRequestPayload(operationId, 0uL, keyHandle, operationSpec))
            )
        val operationSpecOffset = requestPayloadOffset() + 16 + 8 + 16 + 4 + keyHandle.binding.size
        val operationSpecTags = ByteBuffer.wrap(begin, operationSpecOffset, 4)
        assertEquals(1, operationSpecTags.short.toInt())
        assertEquals(1, operationSpecTags.short.toInt())
        assertFailsWith<WireCodecException.UnknownSpecTag> {
            NormalizedWireCodec.decodeRequest(begin.mutatingShort(operationSpecOffset + 2, 0x7fff))
        }
    }

    @Test
    fun callerWireIdentityExcludesTargetLocalUid() {
        val first =
            WireCallerIdentity.from(
                CallerIdentity(10123, "signer-sha256", "attestation-application-id")
            )
        val movedUid =
            WireCallerIdentity.from(
                CallerIdentity(20234, "signer-sha256", "attestation-application-id")
            )
        assertEquals(first, movedUid)

        val firstBytes =
            NormalizedWireCodec.encodeRequest(request(ImportRequestPayload, caller = first))
        val movedBytes =
            NormalizedWireCodec.encodeRequest(request(ImportRequestPayload, caller = movedUid))
        assertContentEquals(firstBytes, movedBytes)
    }

    @Test
    fun byteBackedModelsAndDecodedFramesAreDefensiveCopies() {
        val challenge = bytes(32, 17)
        val sourceLogicalNameHash = logicalNameHash.copyOf()
        val binding = bytes(32, 18)
        val sourceSession = sessionId.copyOf()
        val payload =
            GenerateRequestPayload(generationId, sourceLogicalNameHash, challenge, keySpec)
        val envelope = request(payload, sessionId = sourceSession)
        val handle = WireKeyHandle(keyId, binding)
        val expected = NormalizedWireCodec.encodeRequest(envelope)

        challenge.fill(0)
        sourceLogicalNameHash.fill(0)
        binding.fill(0)
        sourceSession.fill(0)
        envelope.sessionId.fill(0)
        envelope.payloadHash.fill(0)
        payload.logicalNameHash.fill(0)
        payload.challenge.fill(0)
        handle.binding.fill(0)

        assertContentEquals(expected, NormalizedWireCodec.encodeRequest(envelope))
        assertContentEquals(bytes(32, 18), handle.binding)

        val decoded = NormalizedWireCodec.decodeRequest(expected)
        val decodedBytes = NormalizedWireCodec.encodeRequest(decoded)
        decoded.sessionId.fill(0)
        assertIs<GenerateRequestPayload>(decoded.payload).run {
            logicalNameHash.fill(0)
            challenge.fill(0)
        }
        assertContentEquals(decodedBytes, NormalizedWireCodec.encodeRequest(decoded))
    }

    @Test
    fun restartMetadataDefensivelyCopiesEveryPublicByteField() {
        val challenge = bytes(32, 30)
        val publicKey = bytes(65, 31)
        val certificate = bytes(96, 32)
        val source =
            WireKeyMetadata(KeyState.SUPERSEDED, challenge, publicKey, listOf(certificate), keySpec)
        val generate = GenerateResultPayload(generationId, keyHandle, source)
        val metadataResult = GetMetadataResultPayload(source)
        val generateBytes =
            NormalizedWireCodec.encodeResponse(
                response(Method.GENERATE, WireOutcome.Success(generate))
            )
        val metadataBytes =
            NormalizedWireCodec.encodeResponse(
                response(Method.GET_METADATA, WireOutcome.Success(metadataResult))
            )

        challenge.fill(0)
        publicKey.fill(0)
        certificate.fill(0)
        source.attestationChallenge.fill(0)
        source.publicKey.fill(0)
        source.certificateChain.single().fill(0)

        assertContentEquals(
            generateBytes,
            NormalizedWireCodec.encodeResponse(
                response(Method.GENERATE, WireOutcome.Success(generate))
            ),
        )
        assertContentEquals(
            metadataBytes,
            NormalizedWireCodec.encodeResponse(
                response(Method.GET_METADATA, WireOutcome.Success(metadataResult))
            ),
        )
    }

    @Test
    fun malformedTruncatedTrailingAndUnknownHeadersAreTypedErrors() {
        val valid = NormalizedWireCodec.encodeRequest(request(ImportRequestPayload))

        assertFailsWith<WireCodecException.MalformedFrame> {
            NormalizedWireCodec.decodeRequest(valid.mutatingInt(4, 0x01020304))
        }
        assertFailsWith<WireCodecException.TruncatedFrame> {
            NormalizedWireCodec.decodeRequest(valid.copyOf(valid.size - 1))
        }
        assertFailsWith<WireCodecException.TrailingData> {
            NormalizedWireCodec.decodeRequest(valid + byteArrayOf(0))
        }
        assertFailsWith<WireCodecException.UnknownVersion> {
            NormalizedWireCodec.decodeRequest(valid.mutatingShort(8, 2))
        }
        assertFailsWith<WireCodecException.UnknownFrameType> {
            NormalizedWireCodec.decodeRequest(valid.copyOf().also { it[10] = 99 })
        }
        assertFailsWith<WireCodecException.UnknownMethod> {
            NormalizedWireCodec.decodeRequest(valid.mutatingShort(11, 0x7fff))
        }
        assertFailsWith<WireCodecException.UnknownPayloadType> {
            NormalizedWireCodec.decodeRequest(valid.mutatingShort(13, 0x7fff))
        }
    }

    @Test
    fun invalidLengthsInvalidUtf8AndOversizedFramesAreTypedErrors() {
        val valid = NormalizedWireCodec.encodeRequest(request(ImportRequestPayload))

        assertFailsWith<WireCodecException.InvalidLength> {
            NormalizedWireCodec.decodeRequest(valid.mutatingInt(179, -1))
        }
        assertFailsWith<WireCodecException.InvalidUtf8> {
            NormalizedWireCodec.decodeRequest(
                valid.mutatingInt(179, 1).copyOf().also { it[183] = 0xc3.toByte() }
            )
        }
        assertFailsWith<WireCodecException.OversizedFrame> {
            NormalizedWireCodec.decodeRequest(ByteArray(NormalizedWireCodec.MAX_FRAME_BYTES + 1))
        }
        assertFailsWith<WireCodecException.InvalidLength> {
            NormalizedWireCodec.encodeRequest(
                request(
                    GenerateRequestPayload(generationId, logicalNameHash, ByteArray(129), keySpec)
                )
            )
        }
        assertFailsWith<WireCodecException.InvalidLength> {
            NormalizedWireCodec.encodeRequest(
                request(GenerateRequestPayload(generationId, ByteArray(31), bytes(32, 1), keySpec))
            )
        }
        assertFailsWith<WireCodecException.InvalidLength> {
            NormalizedWireCodec.encodeResponse(
                response(
                    Method.GENERATE,
                    WireOutcome.Success(
                        GenerateResultPayload(
                            generationId,
                            keyHandle,
                            WireKeyMetadata(
                                KeyState.ACTIVE,
                                bytes(32, 1),
                                bytes(65, 2),
                                List(17) { bytes(8, it) },
                                keySpec,
                            ),
                        )
                    ),
                )
            )
        }
    }

    @Test
    fun methodPayloadAndResponseKindMismatchesAreTypedErrors() {
        val generate =
            request(GenerateRequestPayload(generationId, logicalNameHash, bytes(32, 7), keySpec))
        assertFailsWith<WireCodecException.MethodPayloadMismatch> {
            NormalizedWireCodec.encodeRequest(generate.copy(method = Method.DELETE))
        }

        val encodedRequest = NormalizedWireCodec.encodeRequest(generate)
        assertFailsWith<WireCodecException.MethodPayloadMismatch> {
            NormalizedWireCodec.decodeRequest(encodedRequest.mutatingShort(11, 4))
        }

        val success =
            response(Method.UPDATE, WireOutcome.Success(UpdateResultPayload(2uL, bytes(16, 14))))
        val encodedSuccess = NormalizedWireCodec.encodeResponse(success)
        assertFailsWith<WireCodecException.MethodPayloadMismatch> {
            NormalizedWireCodec.decodeResponse(encodedSuccess.mutatingShort(11, 8))
        }

        val error =
            NormalizedWireCodec.encodeResponse(
                response(Method.IMPORT, WireOutcome.Error(WireErrorCode.UNSUPPORTED_METHOD))
            )
        assertFailsWith<WireCodecException.UnknownErrorCode> {
            NormalizedWireCodec.decodeResponse(error.mutatingShort(62, 0x7fff))
        }
        assertFailsWith<WireCodecException.UnknownFrameType> {
            NormalizedWireCodec.decodeResponse(encodedSuccess.copyOf().also { it[10] = 1 })
        }
    }

    private fun request(
        payload: LifecycleRequestPayload,
        sequence: ULong = 7uL,
        caller: WireCallerIdentity = this.caller,
        sessionId: ByteArray = this.sessionId,
        payloadHash: ByteArray = NormalizedWireCodec.payloadHash(payload),
    ) =
        WireRequestEnvelope(
            ProtocolVersion.V1,
            sessionId,
            clientNonce,
            serverNonce,
            sequence,
            requestId,
            payloadHash,
            payload.method,
            deadline,
            caller,
            payload,
        )

    private fun response(method: Method, outcome: WireOutcome) =
        WireResponseEnvelope(ProtocolVersion.V1, sessionId, requestId, method, outcome)

    private fun assertRequestEnvelope(expected: WireRequestEnvelope, actual: WireRequestEnvelope) {
        assertEquals(expected.version, actual.version)
        assertContentEquals(expected.sessionId, actual.sessionId)
        assertContentEquals(expected.clientNonce, actual.clientNonce)
        assertContentEquals(expected.serverNonce, actual.serverNonce)
        assertEquals(expected.sequence, actual.sequence)
        assertEquals(expected.requestId, actual.requestId)
        assertContentEquals(expected.payloadHash, actual.payloadHash)
        assertEquals(expected.method, actual.method)
        assertEquals(expected.deadline, actual.deadline)
        assertEquals(expected.caller, actual.caller)
        assertPayload(expected.payload, actual.payload)
    }

    private fun assertResponseEnvelope(
        expected: WireResponseEnvelope,
        actual: WireResponseEnvelope,
    ) {
        assertEquals(expected.version, actual.version)
        assertContentEquals(expected.sessionId, actual.sessionId)
        assertEquals(expected.requestId, actual.requestId)
        assertEquals(expected.method, actual.method)
        when (val expectedOutcome = expected.outcome) {
            is WireOutcome.Error ->
                assertEquals(expectedOutcome.code, assertIs<WireOutcome.Error>(actual.outcome).code)
            is WireOutcome.Success ->
                assertResult(
                    expectedOutcome.payload,
                    assertIs<WireOutcome.Success>(actual.outcome).payload,
                )
        }
    }

    private fun assertPayload(expected: LifecycleRequestPayload, actual: LifecycleRequestPayload) {
        assertEquals(expected::class, actual::class)
        when (expected) {
            is GenerateRequestPayload -> {
                actual as GenerateRequestPayload
                assertEquals(expected.generationId, actual.generationId)
                assertContentEquals(expected.logicalNameHash, actual.logicalNameHash)
                assertContentEquals(expected.challenge, actual.challenge)
                assertEquals(expected.keySpec, actual.keySpec)
            }
            ImportRequestPayload -> Unit
            is GetMetadataRequestPayload ->
                assertKeyHandle(expected.handle, (actual as GetMetadataRequestPayload).handle)
            is DeleteRequestPayload -> {
                actual as DeleteRequestPayload
                assertEquals(expected.deletionId, actual.deletionId)
                assertKeyHandle(expected.handle, actual.handle)
            }
            is BeginRequestPayload -> {
                actual as BeginRequestPayload
                assertEquals(expected.operationId, actual.operationId)
                assertEquals(expected.step, actual.step)
                assertKeyHandle(expected.handle, actual.handle)
                assertEquals(expected.operationSpec, actual.operationSpec)
            }
            is UpdateAadRequestPayload -> {
                actual as UpdateAadRequestPayload
                assertOperation(expected.operation, actual.operation)
                assertEquals(expected.step, actual.step)
                assertContentEquals(expected.input, actual.input)
            }
            is UpdateRequestPayload -> {
                actual as UpdateRequestPayload
                assertOperation(expected.operation, actual.operation)
                assertEquals(expected.step, actual.step)
                assertContentEquals(expected.input, actual.input)
            }
            is FinishRequestPayload -> {
                actual as FinishRequestPayload
                assertOperation(expected.operation, actual.operation)
                assertEquals(expected.step, actual.step)
                assertContentEquals(expected.input, actual.input)
            }
            is AbortRequestPayload -> {
                actual as AbortRequestPayload
                assertOperation(expected.operation, actual.operation)
                assertEquals(expected.step, actual.step)
            }
        }
    }

    private fun assertResult(expected: LifecycleResultPayload, actual: LifecycleResultPayload) {
        assertEquals(expected::class, actual::class)
        when (expected) {
            is GenerateResultPayload -> {
                actual as GenerateResultPayload
                assertEquals(expected.generationId, actual.generationId)
                assertKeyHandle(expected.handle, actual.handle)
                assertMetadata(expected.metadata, actual.metadata)
            }
            is GetMetadataResultPayload ->
                assertMetadata(expected.metadata, (actual as GetMetadataResultPayload).metadata)
            is DeleteResultPayload ->
                assertEquals(expected.deletionId, (actual as DeleteResultPayload).deletionId)
            is BeginResultPayload -> {
                actual as BeginResultPayload
                assertOperation(expected.operation, actual.operation)
                assertEquals(expected.step, actual.step)
            }
            is UpdateAadResultPayload ->
                assertEquals(expected.step, (actual as UpdateAadResultPayload).step)
            is UpdateResultPayload -> {
                actual as UpdateResultPayload
                assertEquals(expected.step, actual.step)
                assertContentEquals(expected.output, actual.output)
            }
            is FinishResultPayload -> {
                actual as FinishResultPayload
                assertEquals(expected.step, actual.step)
                assertContentEquals(expected.output, actual.output)
            }
            is AbortResultPayload ->
                assertEquals(expected.step, (actual as AbortResultPayload).step)
        }
    }

    private fun assertKeyHandle(expected: WireKeyHandle, actual: WireKeyHandle) {
        assertEquals(expected.id, actual.id)
        assertContentEquals(expected.binding, actual.binding)
    }

    private fun assertOperation(expected: WireOperationHandle, actual: WireOperationHandle) {
        assertEquals(expected.id, actual.id)
        assertEquals(expected.keyId, actual.keyId)
        assertContentEquals(expected.binding, actual.binding)
    }

    private fun assertMetadata(expected: WireKeyMetadata, actual: WireKeyMetadata) {
        assertEquals(expected.state, actual.state)
        assertContentEquals(expected.attestationChallenge, actual.attestationChallenge)
        assertContentEquals(expected.publicKey, actual.publicKey)
        assertEquals(expected.certificateChain.size, actual.certificateChain.size)
        expected.certificateChain.zip(actual.certificateChain).forEach { (left, right) ->
            assertContentEquals(left, right)
        }
        assertEquals(expected.keySpec, actual.keySpec)
    }

    private fun requestPayloadOffset(): Int =
        179 +
            Int.SIZE_BYTES +
            caller.signingCertificateDigest.encodeToByteArray().size +
            Int.SIZE_BYTES +
            caller.attestationApplicationIdDigest.encodeToByteArray().size

    private fun ByteArray.mutatingInt(offset: Int, value: Int): ByteArray =
        copyOf().also { ByteBuffer.wrap(it).putInt(offset, value) }

    private fun ByteArray.mutatingShort(offset: Int, value: Int): ByteArray =
        copyOf().also { ByteBuffer.wrap(it).putShort(offset, value.toShort()) }

    private fun bytes(size: Int, seed: Int) = ByteArray(size) { (it + seed).toByte() }
}
