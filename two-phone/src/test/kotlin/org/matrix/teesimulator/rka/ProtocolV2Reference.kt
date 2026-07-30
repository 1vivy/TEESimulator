package org.matrix.teesimulator.rka

internal data class ProtocolV2NamedVector(
    val name: String,
    val bytes: ByteArray,
)

internal data class ProtocolV2Verification(
    val names: List<String>,
    val kinds: List<Long>,
    val sequences: List<Long>,
    val transcripts: List<ByteArray>,
)

internal object ProtocolV2Reference {
    private data class Specification(
        val name: String,
        val kind: Long,
        val body: (ByteArray) -> V2Value,
    )

    private val specifications =
        listOf(
            Specification("hello", 1) { v2Hello() },
            Specification("hello_ack", 2) { v2HelloAck() },
            Specification("generate", 10) { v2Generate() },
            Specification("get", 11) { v2Alias() },
            Specification("list", 12) { v2IdentityHandle() },
            Specification("delete", 13) { v2Alias() },
            Specification("begin", 20) { v2Begin() },
            Specification("update_aad", 21) { v2Chunk() },
            Specification("update", 22) { v2Chunk() },
            Specification("finish", 23) { v2Finish() },
            Specification("abort", 24) { v2Operation() },
            Specification("result_generate", 30) { previous -> v2ResultGenerate(10, previous) },
            Specification("result_get", 30) { previous -> v2ResultGenerate(11, previous) },
            Specification("result_list", 30) { v2ResultList() },
            Specification("result_delete", 30) { v2ResultDelete() },
            Specification("result_begin", 30) { v2ResultBegin() },
            Specification("result_update_aad", 30) { v2ResultUpdate(21) },
            Specification("result_update", 30) { v2ResultUpdate(22) },
            Specification("result_finish", 30) { v2ResultFinish() },
            Specification("result_abort", 30) { v2ResultAbort() },
            Specification("error", 31) { v2Error() },
        )

    fun verify(vectors: List<ProtocolV2NamedVector>): ProtocolV2Verification {
        require(vectors.size == specifications.size) { "expected 21 schema vectors" }
        var previous = ByteArray(32)
        val transcripts = mutableListOf<ByteArray>()
        val sequences = mutableListOf<Long>()
        vectors.zip(specifications).forEachIndexed { index, (actual, specification) ->
            require(actual.name == specification.name) { "unexpected vector name at $index" }
            val body = specification.body(previous)
            val withoutTranscript = frame(specification.kind, index.toLong(), body, null)
            val current =
                v2Sha256(
                    "TEESIM-RKA-V2/FRAME\u0000".encodeToByteArray() +
                        previous +
                        ProtocolV2Cbor.encode(withoutTranscript),
                )
            val expected = frame(specification.kind, index.toLong(), body, current)
            val parsed = ProtocolV2Cbor.parse(actual.bytes)
            require(parsed == expected) { "${actual.name} has an unexpected nested schema or value" }
            require(ProtocolV2Cbor.encode(parsed).contentEquals(actual.bytes)) {
                "${actual.name} is not byte-canonical"
            }
            require(current.any { byte -> byte != 0.toByte() }) {
                "${actual.name} has a zero transcript hash"
            }
            transcripts += current
            sequences += index.toLong()
            previous = current
        }
        return ProtocolV2Verification(
            names = specifications.map(Specification::name),
            kinds = specifications.map(Specification::kind),
            sequences = sequences,
            transcripts = transcripts,
        )
    }

    private fun frame(
        kind: Long,
        sequence: Long,
        body: V2Value,
        transcript: ByteArray?,
    ): V2Value {
        val entries =
            mutableListOf(
                0L to v2UInt(2),
                1L to v2UInt(kind),
                2L to v2Bytes(0x22, 16),
                3L to v2Bytes(0x11, 32),
                4L to v2UInt(7),
                5L to v2UInt(sequence),
                6L to body,
            )
        transcript?.let { entries += 7L to v2Bytes(it) }
        return ProtocolV2Value.MapValue(entries)
    }
}
