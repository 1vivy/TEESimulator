package org.matrix.teesimulator.rka

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolPayloadContractTest {
    @Test
    fun allMethodPayloadSchemasDecodeToTypedModels() {
        // Given: canonical request and response payloads for every method.
        val frames =
            TransportKind.entries
                .flatMap(GoldenVectorFixtures::lifecycleFrames)
                .map(Pair<String, RkaFrame>::second)

        // When: the fixed payload schemas are decoded.
        val decoded = frames.map(RkaPayloadCodec::decode)

        // Then: all seven request and response model variants are represented per transport.
        assertEquals(TransportKind.entries.size * Method.entries.size * 2, decoded.size)
        assertEquals(
            setOf(
                GenerateRequest::class,
                GenerateResponse::class,
                GetMetadataRequest::class,
                GetMetadataResponse::class,
                DeleteRequest::class,
                DeleteResponse::class,
                BeginRequest::class,
                BeginResponse::class,
                UpdateRequest::class,
                UpdateResponse::class,
                FinishRequest::class,
                FinishResponse::class,
                AbortRequest::class,
                AbortResponse::class,
            ),
            decoded.filterNotNull().map { it::class }.toSet(),
        )
    }

    @Test
    fun fieldBoundsRejectValuesOutsideTheContract() {
        // Given: one invalid payload for every variable-width or fixed-tag boundary.
        val invalidFrames =
            listOf(
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(logicalName = byteArrayOf()),
                ),
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(logicalName = ByteArray(129)),
                ),
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(challenge = byteArrayOf()),
                ),
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(challenge = ByteArray(129)),
                ),
                request(Method.GENERATE, PayloadBoundaryFixtures.generateRequest(purpose = 2)),
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(logicalName = byteArrayOf(0)),
                ),
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(
                        logicalName = byteArrayOf(0xc3.toByte())
                    ),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(publicKey = byteArrayOf()),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(publicKey = ByteArray(2_049)),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(certificates = emptyList()),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(
                        certificates = List(9) { byteArrayOf(it.toByte()) }
                    ),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(
                        certificates = listOf(byteArrayOf())
                    ),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(
                        certificates = listOf(ByteArray(RkaLimits.CERTIFICATE_BYTES + 1))
                    ),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(
                        certificates = listOf(byteArrayOf(1), byteArrayOf(1))
                    ),
                ),
                request(
                    Method.UPDATE,
                    PayloadBoundaryFixtures.updateRequest(
                        ByteArray(RkaLimits.REQUEST_CHUNK_BYTES + 1)
                    ),
                ),
                request(
                    Method.FINISH,
                    PayloadBoundaryFixtures.finishRequest(
                        ByteArray(RkaLimits.REQUEST_CHUNK_BYTES + 1)
                    ),
                ),
                request(
                    Method.FINISH,
                    PayloadBoundaryFixtures.finishRequest(byteArrayOf(), byteArrayOf(1)),
                ),
                response(Method.ABORT, byteArrayOf(2)),
            )

        // When: each invalid payload crosses the codec boundary.
        val rejected =
            invalidFrames.count { frame ->
                runCatching { RkaReferenceCodec.encode(frame) }.isFailure
            }

        // Then: every out-of-contract value is rejected before dispatch.
        assertEquals(invalidFrames.size, rejected)
    }

    @Test
    fun everyMethodRejectsTruncationAndTrailingBytes() {
        // Given: every canonical request and response payload.
        val frames =
            Method.entries.flatMap { method ->
                listOf(
                    request(method, GoldenVectorFixtures.requestPayload(method)),
                    response(method, GoldenVectorFixtures.responsePayload(method)),
                )
            }

        // When: fixed-schema payloads are truncated or extended.
        val rejected =
            frames
                .flatMap { frame ->
                    listOf(
                        frame.copy(payload = frame.payload.dropLast(1).toByteArray()),
                        frame.copy(payload = frame.payload + 0),
                    )
                }
                .count { frame -> runCatching { RkaReferenceCodec.encode(frame) }.isFailure }

        // Then: no schema accepts missing or unknown fields.
        assertEquals(frames.size * 2, rejected)
        assertTrue(frames.isNotEmpty())
    }

    @Test
    fun variablePayloadBoundsAcceptTheirExactMaximums() {
        // Given: method payloads at each approved variable-width maximum.
        val certificates =
            List(RkaLimits.CERTIFICATE_COUNT) { index ->
                ByteArray(RkaLimits.CERTIFICATE_BYTES).also { it[0] = index.toByte() }
            }
        val frames =
            listOf(
                request(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.generateRequest(
                        logicalName = ByteArray(RkaLimits.LOGICAL_NAME_BYTES) { 'a'.code.toByte() },
                        challenge = ByteArray(RkaLimits.CHALLENGE_BYTES),
                    ),
                ),
                response(
                    Method.GENERATE,
                    PayloadBoundaryFixtures.publicMetadataResponse(
                        publicKey = ByteArray(2_048),
                        certificates = certificates,
                    ),
                ),
                request(
                    Method.UPDATE,
                    PayloadBoundaryFixtures.updateRequest(ByteArray(RkaLimits.REQUEST_CHUNK_BYTES)),
                ),
                request(
                    Method.FINISH,
                    PayloadBoundaryFixtures.finishRequest(ByteArray(RkaLimits.REQUEST_CHUNK_BYTES)),
                ),
            )

        // When: the payloads cross the codec boundary.
        val decoded = frames.map(RkaReferenceCodec::encode).map(RkaReferenceCodec::decode)

        // Then: each exact maximum remains valid and typed.
        assertEquals(frames.size, decoded.size)
    }

    private fun request(method: Method, payload: ByteArray): RkaFrame =
        GoldenVectorFixtures.frame(method = method, payload = payload)

    private fun response(method: Method, payload: ByteArray): RkaFrame =
        GoldenVectorFixtures.frame(
            method = method,
            kind = MessageKind.RESPONSE,
            sequence = 2u,
            payload = payload,
        )
}
