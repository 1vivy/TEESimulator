package org.matrix.teesimulator.twophone

import java.security.MessageDigest

object NormalizedWireCodec {
    const val MAX_FRAME_BYTES = 2 * 1024 * 1024

    private const val MAGIC = 0x54504b31
    private const val VERSION_V1 = 1
    private const val REQUEST_FRAME = 1
    private const val RESPONSE_FRAME = 2
    private const val SUCCESS_OUTCOME = 1
    private const val ERROR_OUTCOME = 2

    private const val SESSION_ID_BYTES = 32
    private const val NONCE_BYTES = 32
    private const val PAYLOAD_HASH_BYTES = 32
    private const val MAX_IDENTITY_BYTES = 1024
    private const val MAX_CHALLENGE_BYTES = 128
    private const val MAX_HANDLE_BINDING_BYTES = 1024
    private const val MAX_INPUT_BYTES = 1024 * 1024
    private const val MAX_PUBLIC_KEY_BYTES = 64 * 1024
    private const val MAX_CERTIFICATE_BYTES = 256 * 1024
    private const val MAX_CERTIFICATES = 16

    fun payloadHash(payload: LifecycleRequestPayload): ByteArray {
        val writer = WireWriter()
        writer.writeUnsignedShort(requestPayloadTag(payload))
        writeRequestPayload(writer, payload)
        return MessageDigest.getInstance("SHA-256").digest(writer.toByteArray())
    }

    fun encodeRequest(request: WireRequestEnvelope): ByteArray {
        if (request.method != request.payload.method) {
            throw WireCodecException.MethodPayloadMismatch()
        }
        val declaredPayloadHash = request.payloadHash
        if (declaredPayloadHash.size != PAYLOAD_HASH_BYTES) {
            throw WireCodecException.InvalidLength("payload hash")
        }
        if (!MessageDigest.isEqual(declaredPayloadHash, payloadHash(request.payload))) {
            throw WireCodecException.PayloadHashMismatch()
        }
        val writer = WireWriter()
        writeHeader(
            writer,
            request.version,
            REQUEST_FRAME,
            request.method,
            requestPayloadTag(request.payload),
        )
        writer.writeFixed("session id", request.sessionId, SESSION_ID_BYTES)
        writer.writeFixed("client nonce", request.clientNonce, NONCE_BYTES)
        writer.writeFixed("server nonce", request.serverNonce, NONCE_BYTES)
        writer.writeULong(request.sequence)
        writer.writeUuid(request.requestId)
        writer.writeFixed("payload hash", declaredPayloadHash, PAYLOAD_HASH_BYTES)
        writer.writeInstant(request.deadline)
        writer.writeString(
            "signing certificate digest",
            request.caller.signingCertificateDigest,
            MAX_IDENTITY_BYTES,
        )
        writer.writeString(
            "attestation application id digest",
            request.caller.attestationApplicationIdDigest,
            MAX_IDENTITY_BYTES,
        )
        writeRequestPayload(writer, request.payload)
        return writer.toFrame()
    }

    fun decodeRequest(frame: ByteArray): WireRequestEnvelope {
        val reader = frameReader(frame)
        val version = readHeaderVersion(reader)
        requireFrameType(reader, REQUEST_FRAME)
        val method = methodForTag(reader.readUnsignedShort())
        val payloadTag = reader.readUnsignedShort()
        val sessionId = reader.readFixed(SESSION_ID_BYTES)
        val clientNonce = reader.readFixed(NONCE_BYTES)
        val serverNonce = reader.readFixed(NONCE_BYTES)
        val sequence = reader.readULong()
        val requestId = reader.readUuid()
        val declaredPayloadHash = reader.readFixed(PAYLOAD_HASH_BYTES)
        val deadline = reader.readInstant()
        val caller =
            WireCallerIdentity(
                reader.readString("signing certificate digest", MAX_IDENTITY_BYTES),
                reader.readString("attestation application id digest", MAX_IDENTITY_BYTES),
            )
        val payload = readRequestPayload(payloadTag, reader)
        if (method != payload.method) throw WireCodecException.MethodPayloadMismatch()
        reader.requireFinished()
        if (!MessageDigest.isEqual(declaredPayloadHash, payloadHash(payload))) {
            throw WireCodecException.PayloadHashMismatch()
        }
        return WireRequestEnvelope(
            version,
            sessionId,
            clientNonce,
            serverNonce,
            sequence,
            requestId,
            declaredPayloadHash,
            method,
            deadline,
            caller,
            payload,
        )
    }

    fun encodeResponse(response: WireResponseEnvelope): ByteArray {
        val writer = WireWriter()
        val payloadTag =
            when (val outcome = response.outcome) {
                is WireOutcome.Success -> {
                    if (response.method != outcome.payload.method) {
                        throw WireCodecException.MethodPayloadMismatch()
                    }
                    resultPayloadTag(outcome.payload)
                }
                is WireOutcome.Error -> null
            }
        writeHeader(writer, response.version, RESPONSE_FRAME, response.method, null)
        writer.writeFixed("session id", response.sessionId, SESSION_ID_BYTES)
        writer.writeUuid(response.requestId)
        when (val outcome = response.outcome) {
            is WireOutcome.Success -> {
                writer.writeByte(SUCCESS_OUTCOME)
                writer.writeUnsignedShort(payloadTag!!)
                writeResultPayload(writer, outcome.payload)
            }
            is WireOutcome.Error -> {
                writer.writeByte(ERROR_OUTCOME)
                writer.writeUnsignedShort(errorCodeTag(outcome.code))
            }
        }
        return writer.toFrame()
    }

    fun decodeResponse(frame: ByteArray): WireResponseEnvelope {
        val reader = frameReader(frame)
        val version = readHeaderVersion(reader)
        requireFrameType(reader, RESPONSE_FRAME)
        val method = methodForTag(reader.readUnsignedShort())
        val sessionId = reader.readFixed(SESSION_ID_BYTES)
        val requestId = reader.readUuid()
        val outcome =
            when (val tag = reader.readUnsignedByte()) {
                SUCCESS_OUTCOME -> {
                    val payload = readResultPayload(reader.readUnsignedShort(), reader)
                    if (method != payload.method) {
                        throw WireCodecException.MethodPayloadMismatch()
                    }
                    WireOutcome.Success(payload)
                }
                ERROR_OUTCOME -> WireOutcome.Error(errorCodeForTag(reader.readUnsignedShort()))
                else -> throw WireCodecException.UnknownOutcomeType(tag)
            }
        reader.requireFinished()
        return WireResponseEnvelope(version, sessionId, requestId, method, outcome)
    }

    private fun writeHeader(
        writer: WireWriter,
        version: ProtocolVersion,
        frameType: Int,
        method: Method,
        payloadTag: Int?,
    ) {
        writer.writeInt(MAGIC)
        writer.writeUnsignedShort(versionTag(version))
        writer.writeByte(frameType)
        writer.writeUnsignedShort(methodTag(method))
        payloadTag?.let(writer::writeUnsignedShort)
    }

    private fun readHeaderVersion(reader: WireReader): ProtocolVersion {
        if (reader.readInt() != MAGIC) throw WireCodecException.MalformedFrame()
        return versionForTag(reader.readUnsignedShort())
    }

    private fun requireFrameType(reader: WireReader, expected: Int) {
        val actual = reader.readUnsignedByte()
        if (actual != expected) throw WireCodecException.UnknownFrameType(actual)
    }

    private fun writeRequestPayload(writer: WireWriter, payload: LifecycleRequestPayload) {
        when (payload) {
            is GenerateRequestPayload -> {
                writer.writeUuid(payload.generationId)
                writer.writeFixed("logical name hash", payload.logicalNameHash, 32)
                writer.writeKeySpec(payload.keySpec)
                writer.writeBytes(
                    "attestation challenge",
                    payload.challenge,
                    1,
                    MAX_CHALLENGE_BYTES,
                )
            }
            ImportRequestPayload -> Unit
            is GetMetadataRequestPayload -> writer.writeKeyHandle(payload.handle)
            is DeleteRequestPayload -> {
                writer.writeUuid(payload.deletionId)
                writer.writeKeyHandle(payload.handle)
            }
            is BeginRequestPayload -> {
                writer.writeUuid(payload.operationId)
                writer.writeULong(payload.step)
                writer.writeKeyHandle(payload.handle)
                writer.writeOperationSpec(payload.operationSpec)
            }
            is UpdateAadRequestPayload -> {
                writer.writeOperationHandle(payload.operation)
                writer.writeULong(payload.step)
                writer.writeBytes("aad input", payload.input, 0, MAX_INPUT_BYTES)
            }
            is UpdateRequestPayload -> {
                writer.writeOperationHandle(payload.operation)
                writer.writeULong(payload.step)
                writer.writeBytes("update input", payload.input, 0, MAX_INPUT_BYTES)
            }
            is FinishRequestPayload -> {
                writer.writeOperationHandle(payload.operation)
                writer.writeULong(payload.step)
                writer.writeBytes("finish input", payload.input, 0, MAX_INPUT_BYTES)
            }
            is AbortRequestPayload -> {
                writer.writeOperationHandle(payload.operation)
                writer.writeULong(payload.step)
            }
        }
    }

    private fun readRequestPayload(tag: Int, reader: WireReader): LifecycleRequestPayload =
        when (tag) {
            0x1001 -> {
                val generationId = reader.readUuid()
                val logicalNameHash = reader.readFixed(32)
                val keySpec = reader.readKeySpec()
                val challenge = reader.readBytes("attestation challenge", 1, MAX_CHALLENGE_BYTES)
                GenerateRequestPayload(generationId, logicalNameHash, challenge, keySpec)
            }
            0x1002 -> ImportRequestPayload
            0x1003 -> GetMetadataRequestPayload(reader.readKeyHandle())
            0x1004 -> DeleteRequestPayload(reader.readUuid(), reader.readKeyHandle())
            0x1005 ->
                BeginRequestPayload(
                    reader.readUuid(),
                    reader.readULong(),
                    reader.readKeyHandle(),
                    reader.readOperationSpec(),
                )
            0x1006 ->
                UpdateAadRequestPayload(
                    reader.readOperationHandle(),
                    reader.readULong(),
                    reader.readBytes("aad input", 0, MAX_INPUT_BYTES),
                )
            0x1007 ->
                UpdateRequestPayload(
                    reader.readOperationHandle(),
                    reader.readULong(),
                    reader.readBytes("update input", 0, MAX_INPUT_BYTES),
                )
            0x1008 ->
                FinishRequestPayload(
                    reader.readOperationHandle(),
                    reader.readULong(),
                    reader.readBytes("finish input", 0, MAX_INPUT_BYTES),
                )
            0x1009 -> AbortRequestPayload(reader.readOperationHandle(), reader.readULong())
            else -> throw WireCodecException.UnknownPayloadType(tag)
        }

    private fun writeResultPayload(writer: WireWriter, payload: LifecycleResultPayload) {
        when (payload) {
            is GenerateResultPayload -> {
                writer.writeUuid(payload.generationId)
                writer.writeKeyHandle(payload.handle)
                writer.writeKeyMetadata(payload.metadata)
            }
            is GetMetadataResultPayload -> writer.writeKeyMetadata(payload.metadata)
            is DeleteResultPayload -> writer.writeUuid(payload.deletionId)
            is BeginResultPayload -> {
                writer.writeOperationHandle(payload.operation)
                writer.writeULong(payload.step)
            }
            is UpdateAadResultPayload -> writer.writeULong(payload.step)
            is UpdateResultPayload -> {
                writer.writeULong(payload.step)
                writer.writeBytes("update output", payload.output, 0, MAX_INPUT_BYTES)
            }
            is FinishResultPayload -> {
                writer.writeULong(payload.step)
                writer.writeBytes("finish output", payload.output, 0, MAX_INPUT_BYTES)
            }
            is AbortResultPayload -> writer.writeULong(payload.step)
        }
    }

    private fun readResultPayload(tag: Int, reader: WireReader): LifecycleResultPayload =
        when (tag) {
            0x2001 -> {
                val generationId = reader.readUuid()
                val handle = reader.readKeyHandle()
                GenerateResultPayload(generationId, handle, reader.readKeyMetadata())
            }
            0x2003 -> GetMetadataResultPayload(reader.readKeyMetadata())
            0x2004 -> DeleteResultPayload(reader.readUuid())
            0x2005 -> BeginResultPayload(reader.readOperationHandle(), reader.readULong())
            0x2006 -> UpdateAadResultPayload(reader.readULong())
            0x2007 ->
                UpdateResultPayload(
                    reader.readULong(),
                    reader.readBytes("update output", 0, MAX_INPUT_BYTES),
                )
            0x2008 ->
                FinishResultPayload(
                    reader.readULong(),
                    reader.readBytes("finish output", 0, MAX_INPUT_BYTES),
                )
            0x2009 -> AbortResultPayload(reader.readULong())
            else -> throw WireCodecException.UnknownPayloadType(tag)
        }

    private fun requestPayloadTag(payload: LifecycleRequestPayload): Int =
        when (payload) {
            is GenerateRequestPayload -> 0x1001
            ImportRequestPayload -> 0x1002
            is GetMetadataRequestPayload -> 0x1003
            is DeleteRequestPayload -> 0x1004
            is BeginRequestPayload -> 0x1005
            is UpdateAadRequestPayload -> 0x1006
            is UpdateRequestPayload -> 0x1007
            is FinishRequestPayload -> 0x1008
            is AbortRequestPayload -> 0x1009
        }

    private fun resultPayloadTag(payload: LifecycleResultPayload): Int =
        when (payload) {
            is GenerateResultPayload -> 0x2001
            is GetMetadataResultPayload -> 0x2003
            is DeleteResultPayload -> 0x2004
            is BeginResultPayload -> 0x2005
            is UpdateAadResultPayload -> 0x2006
            is UpdateResultPayload -> 0x2007
            is FinishResultPayload -> 0x2008
            is AbortResultPayload -> 0x2009
        }

    private fun WireWriter.writeKeySpec(spec: WireKeySpec) {
        writeUnsignedShort(keyAlgorithmTag(spec.algorithm))
        writeUnsignedShort(ecCurveTag(spec.curve))
        writeUnsignedShort(digestTag(spec.digest))
        writeUnsignedShort(keyPurposeTag(spec.purpose))
    }

    private fun WireReader.readKeySpec() =
        WireKeySpec(
            keyAlgorithmForTag(readUnsignedShort()),
            ecCurveForTag(readUnsignedShort()),
            digestForTag(readUnsignedShort()),
            keyPurposeForTag(readUnsignedShort()),
        )

    private fun WireWriter.writeOperationSpec(spec: WireOperationSpec) {
        writeUnsignedShort(keyPurposeTag(spec.purpose))
        writeUnsignedShort(digestTag(spec.digest))
    }

    private fun WireReader.readOperationSpec() =
        WireOperationSpec(keyPurposeForTag(readUnsignedShort()), digestForTag(readUnsignedShort()))

    private fun WireWriter.writeKeyMetadata(metadata: WireKeyMetadata) {
        writeUnsignedShort(keyStateTag(metadata.state))
        writeBytes("attestation challenge", metadata.attestationChallenge, 1, MAX_CHALLENGE_BYTES)
        writeBytes("public key", metadata.publicKey, 1, MAX_PUBLIC_KEY_BYTES)
        val certificates = metadata.certificateChain
        writeCollectionSize("certificate chain", certificates.size, MAX_CERTIFICATES)
        certificates.forEach { writeBytes("certificate", it, 1, MAX_CERTIFICATE_BYTES) }
        writeKeySpec(metadata.keySpec)
    }

    private fun WireReader.readKeyMetadata(): WireKeyMetadata {
        val state = keyStateForTag(readUnsignedShort())
        val challenge = readBytes("attestation challenge", 1, MAX_CHALLENGE_BYTES)
        val publicKey = readBytes("public key", 1, MAX_PUBLIC_KEY_BYTES)
        val certificateCount = readCollectionSize("certificate chain", MAX_CERTIFICATES)
        val certificates =
            List(certificateCount) { readBytes("certificate", 1, MAX_CERTIFICATE_BYTES) }
        return WireKeyMetadata(state, challenge, publicKey, certificates, readKeySpec())
    }

    private fun keyAlgorithmTag(algorithm: WireKeyAlgorithm): Int =
        when (algorithm) {
            WireKeyAlgorithm.EC -> 1
        }

    private fun keyAlgorithmForTag(tag: Int): WireKeyAlgorithm =
        when (tag) {
            1 -> WireKeyAlgorithm.EC
            else -> throw WireCodecException.UnknownSpecTag("key algorithm", tag)
        }

    private fun ecCurveTag(curve: WireEcCurve): Int =
        when (curve) {
            WireEcCurve.P256 -> 1
        }

    private fun ecCurveForTag(tag: Int): WireEcCurve =
        when (tag) {
            1 -> WireEcCurve.P256
            else -> throw WireCodecException.UnknownSpecTag("EC curve", tag)
        }

    private fun digestTag(digest: WireDigest): Int =
        when (digest) {
            WireDigest.SHA256 -> 1
        }

    private fun digestForTag(tag: Int): WireDigest =
        when (tag) {
            1 -> WireDigest.SHA256
            else -> throw WireCodecException.UnknownSpecTag("digest", tag)
        }

    private fun keyPurposeTag(purpose: WireKeyPurpose): Int =
        when (purpose) {
            WireKeyPurpose.SIGN -> 1
        }

    private fun keyPurposeForTag(tag: Int): WireKeyPurpose =
        when (tag) {
            1 -> WireKeyPurpose.SIGN
            else -> throw WireCodecException.UnknownSpecTag("key purpose", tag)
        }

    private fun versionTag(version: ProtocolVersion): Int =
        when (version) {
            ProtocolVersion.V1 -> VERSION_V1
        }

    private fun versionForTag(tag: Int): ProtocolVersion =
        when (tag) {
            VERSION_V1 -> ProtocolVersion.V1
            else -> throw WireCodecException.UnknownVersion(tag)
        }

    private fun methodTag(method: Method): Int =
        when (method) {
            Method.GENERATE -> 1
            Method.IMPORT -> 2
            Method.GET_METADATA -> 3
            Method.DELETE -> 4
            Method.BEGIN -> 5
            Method.UPDATE_AAD -> 6
            Method.UPDATE -> 7
            Method.FINISH -> 8
            Method.ABORT -> 9
        }

    private fun methodForTag(tag: Int): Method =
        when (tag) {
            1 -> Method.GENERATE
            2 -> Method.IMPORT
            3 -> Method.GET_METADATA
            4 -> Method.DELETE
            5 -> Method.BEGIN
            6 -> Method.UPDATE_AAD
            7 -> Method.UPDATE
            8 -> Method.FINISH
            9 -> Method.ABORT
            else -> throw WireCodecException.UnknownMethod(tag)
        }

    private fun keyStateTag(state: KeyState): Int =
        when (state) {
            KeyState.ABSENT -> 1
            KeyState.CREATING -> 2
            KeyState.ACTIVE -> 3
            KeyState.SUPERSEDED -> 4
            KeyState.DELETE_PENDING -> 5
            KeyState.DELETED -> 6
            KeyState.QUARANTINED -> 7
        }

    private fun keyStateForTag(tag: Int): KeyState =
        when (tag) {
            1 -> KeyState.ABSENT
            2 -> KeyState.CREATING
            3 -> KeyState.ACTIVE
            4 -> KeyState.SUPERSEDED
            5 -> KeyState.DELETE_PENDING
            6 -> KeyState.DELETED
            7 -> KeyState.QUARANTINED
            else -> throw WireCodecException.UnknownKeyState(tag)
        }

    private fun errorCodeTag(code: WireErrorCode): Int =
        when (code) {
            WireErrorCode.UNSUPPORTED_METHOD -> 0x3001
            WireErrorCode.MALFORMED_REQUEST -> 0x3002
            WireErrorCode.INVALID_ARGUMENT -> 0x3003
            WireErrorCode.DEADLINE_EXCEEDED -> 0x3004
            WireErrorCode.WRONG_SESSION -> 0x3005
            WireErrorCode.WRONG_CALLER -> 0x3006
            WireErrorCode.WRONG_PAIR -> 0x3007
            WireErrorCode.SEQUENCE_ERROR -> 0x3008
            WireErrorCode.REQUEST_ID_REUSE -> 0x3009
            WireErrorCode.INVALID_HANDLE -> 0x300a
            WireErrorCode.INVALID_STATE -> 0x300b
            WireErrorCode.DONOR_UNAVAILABLE -> 0x300c
            WireErrorCode.INTERNAL_ERROR -> 0x300d
            WireErrorCode.REPLAY_CONFLICT -> 0x300e
            WireErrorCode.INVALID_OPERATION_HANDLE -> 0x300f
        }

    private fun errorCodeForTag(tag: Int): WireErrorCode =
        when (tag) {
            0x3001 -> WireErrorCode.UNSUPPORTED_METHOD
            0x3002 -> WireErrorCode.MALFORMED_REQUEST
            0x3003 -> WireErrorCode.INVALID_ARGUMENT
            0x3004 -> WireErrorCode.DEADLINE_EXCEEDED
            0x3005 -> WireErrorCode.WRONG_SESSION
            0x3006 -> WireErrorCode.WRONG_CALLER
            0x3007 -> WireErrorCode.WRONG_PAIR
            0x3008 -> WireErrorCode.SEQUENCE_ERROR
            0x3009 -> WireErrorCode.REQUEST_ID_REUSE
            0x300a -> WireErrorCode.INVALID_HANDLE
            0x300b -> WireErrorCode.INVALID_STATE
            0x300c -> WireErrorCode.DONOR_UNAVAILABLE
            0x300d -> WireErrorCode.INTERNAL_ERROR
            0x300e -> WireErrorCode.REPLAY_CONFLICT
            0x300f -> WireErrorCode.INVALID_OPERATION_HANDLE
            else -> throw WireCodecException.UnknownErrorCode(tag)
        }

    private fun WireWriter.writeKeyHandle(handle: WireKeyHandle) {
        writeUuid(handle.id)
        writeBytes("key handle binding", handle.binding, 1, MAX_HANDLE_BINDING_BYTES)
    }

    private fun WireWriter.writeOperationHandle(handle: WireOperationHandle) {
        writeUuid(handle.id)
        writeUuid(handle.keyId)
        writeBytes("operation handle binding", handle.binding, 1, MAX_HANDLE_BINDING_BYTES)
    }

    private fun WireReader.readKeyHandle() =
        WireKeyHandle(readUuid(), readBytes("key handle binding", 1, MAX_HANDLE_BINDING_BYTES))

    private fun WireReader.readOperationHandle() =
        WireOperationHandle(
            readUuid(),
            readUuid(),
            readBytes("operation handle binding", 1, MAX_HANDLE_BINDING_BYTES),
        )
}
