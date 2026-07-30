package org.matrix.teesimulator.rka

internal fun v2ResultGenerate(
    triggeringKind: Long,
    previous: ByteArray,
): V2Value =
    v2Result(
        triggeringKind,
        v2Map(
            0L to v2Bytes(0x55, 16),
            1L to
                v2Array(
                    v2Bytes(byteArrayOf(0x30, 0x01)),
                    v2Bytes(byteArrayOf(0x30, 0x02)),
                ),
            2L to v2Bytes(0x12, 32),
            3L to v2Envelope(),
            4L to v2LeafProof(previous),
        ),
    )

internal fun v2ResultList(): V2Value =
    v2Result(
        12,
        v2Map(
            0L to
                v2Array(
                    v2Array(
                        v2Bytes(0x55, 16),
                        v2Bytes(0x33, 32),
                        v2UInt(1),
                    ),
                ),
        ),
    )

internal fun v2ResultDelete(): V2Value =
    v2Result(13, v2Map(0L to v2Boolean(true)))

internal fun v2ResultBegin(): V2Value =
    v2Result(
        20,
        v2Map(
            0L to v2Bytes(0x77, 16),
            1L to v2UInt(65_536),
        ),
    )

internal fun v2ResultUpdate(triggeringKind: Long): V2Value =
    v2Result(
        triggeringKind,
        v2Map(
            0L to v2UInt(5),
            1L to v2Bytes("out".encodeToByteArray()),
        ),
    )

internal fun v2ResultFinish(): V2Value =
    v2Result(
        23,
        v2Map(
            0L to v2Bytes(byteArrayOf(0x30, 0x44)),
            1L to v2Bytes(0x88, 32),
        ),
    )

internal fun v2ResultAbort(): V2Value =
    v2Result(24, v2Map(0L to v2Boolean(true)))

internal fun v2Error(): V2Value =
    v2Map(
        0L to v2UInt(10),
        1L to v2UInt(1),
        2L to v2Boolean(false),
        3L to v2Boolean(false),
        4L to v2Bytes(0x90, 32),
    )

private fun v2Result(
    triggeringKind: Long,
    body: V2Value,
): V2Value =
    v2Map(
        0L to v2UInt(triggeringKind),
        1L to body,
    )

private fun v2LeafProof(previous: ByteArray): V2Value =
    v2Map(
        0L to v2Bytes(0x21, 32),
        1L to v2Bytes(0x22, 32),
        2L to v2Bytes(0x23, 32),
        3L to v2Bytes(0x24, 32),
        4L to v2Bytes(0x25, 32),
        5L to v2Bytes(v2LeafSignature(previous)),
    )

private fun v2LeafSignature(previous: ByteArray): ByteArray {
    val envelopeHash =
        v2Sha256(
            "TEESIM-RKA-V2/ENVELOPE\u0000".encodeToByteArray() +
                ProtocolV2Cbor.encode(v2Envelope()),
        )
    val digest =
        v2Sha256(
            "TEESIM-RKA-V2/LEAF-PROOF\u0000".encodeToByteArray() +
                envelopeHash +
                previous +
                ByteArray(32) { 0x21 } +
                ByteArray(32) { 0x22 },
        )
    val first = v2DerInteger(digest.copyOfRange(0, 16))
    val second = v2DerInteger(digest.copyOfRange(16, 32))
    return byteArrayOf(0x30, (first.size + second.size).toByte()) + first + second
}

private fun v2DerInteger(value: ByteArray): ByteArray {
    val magnitude = if (value.first().toInt() and 0x80 != 0) byteArrayOf(0) + value else value
    return byteArrayOf(0x02, magnitude.size.toByte()) + magnitude
}
