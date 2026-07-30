package org.matrix.teesimulator.rka

import java.security.MessageDigest

internal typealias V2Value = ProtocolV2Value

internal fun v2UInt(value: Long): V2Value = ProtocolV2Value.UIntValue(value)

internal fun v2Bytes(value: ByteArray): V2Value = ProtocolV2Value.BytesValue(value)

internal fun v2Bytes(
    byte: Int,
    size: Int,
): V2Value = v2Bytes(ByteArray(size) { byte.toByte() })

internal fun v2Text(value: String): V2Value = ProtocolV2Value.TextValue(value)

internal fun v2Array(vararg values: V2Value): V2Value =
    ProtocolV2Value.ArrayValue(values.toList())

internal fun v2Map(vararg entries: Pair<Long, V2Value>): V2Value =
    ProtocolV2Value.MapValue(entries.toList())

internal fun v2Boolean(value: Boolean): V2Value = ProtocolV2Value.BooleanValue(value)

internal fun v2Sha256(bytes: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(bytes)

internal fun v2Hello(): V2Value =
    v2Map(
        0L to v2UInt(1),
        1L to v2UInt(1),
        2L to v2Bytes(0x33, 32),
        3L to v2Bytes(0x44, 32),
        4L to v2UInt(15),
    )

internal fun v2HelloAck(): V2Value =
    v2Map(
        0L to v2Boolean(true),
        1L to v2Bytes(0x41, 32),
        2L to v2Bytes(0x42, 32),
        3L to v2Bytes(0x43, 32),
    )

internal fun v2Generate(): V2Value {
    val identityHash = v2IdentityHash()
    return v2Map(
        0L to v2Identity(identityHash),
        1L to v2ForegroundRequest(),
        2L to v2Envelope(identityHash),
    )
}

internal fun v2Alias(): V2Value = v2Map(0L to v2Bytes(0x55, 16))

internal fun v2IdentityHandle(): V2Value = v2Map(0L to v2Bytes(0x33, 32))

internal fun v2Operation(): V2Value = v2Map(0L to v2Bytes(0x77, 16))

internal fun v2Begin(): V2Value =
    v2Map(
        0L to v2Bytes(0x55, 16),
        1L to v2UInt(2),
        2L to v2UInt(4),
        3L to v2UInt(0),
    )

internal fun v2Chunk(): V2Value =
    v2Map(
        0L to v2Bytes(0x77, 16),
        1L to v2Bytes("chunk".encodeToByteArray()),
    )

internal fun v2Finish(): V2Value =
    v2Map(
        0L to v2Bytes(0x77, 16),
        1L to v2Bytes("final".encodeToByteArray()),
    )

internal fun v2IdentityHash(): ByteArray {
    val withoutHash =
        v2Map(
            0L to v2UInt(0),
            1L to v2UInt(10_123),
            2L to v2Packages(),
            3L to v2Bytes(byteArrayOf(0x30, 0x00)),
            5L to v2Bytes(0x99, 32),
        )
    return v2Sha256(
        "TEESIM-RKA-V2/IDENTITY\u0000".encodeToByteArray() +
            ProtocolV2Cbor.encode(withoutHash),
    )
}

internal fun v2Identity(identityHash: ByteArray): V2Value =
    v2Map(
        0L to v2UInt(0),
        1L to v2UInt(10_123),
        2L to v2Packages(),
        3L to v2Bytes(byteArrayOf(0x30, 0x00)),
        4L to v2Bytes(identityHash),
        5L to v2Bytes(0x99, 32),
    )

private fun v2Packages(): V2Value =
    v2Array(
        v2Array(
            v2Text("org.example.app"),
            v2UInt(1),
            v2Array(v2Bytes(byteArrayOf(0x30, 0x01))),
        ),
    )

private fun v2ForegroundRequest(): V2Value =
    v2Map(
        0L to v2UInt(1),
        1L to v2UInt(3),
        2L to v2UInt(1),
        3L to v2UInt(2),
        4L to v2UInt(4),
        5L to v2Bytes(0x66, 16),
        6L to v2Bytes(0x55, 16),
    )

internal fun v2Envelope(identityHash: ByteArray = v2IdentityHash()): V2Value =
    v2Map(
        0L to v2UInt(1),
        1L to v2Bytes(identityHash),
        2L to v2Bytes(0xaa, 32),
        3L to v2UInt(7),
        4L to v2Bytes(0xcc, 32),
        5L to v2Bytes(0xdd, 32),
        6L to v2Bytes(0xee, 32),
        13L to v2UInt(1_000),
        14L to v2UInt(120),
        15L to v2UInt(1),
        16L to v2UInt(0),
    )
