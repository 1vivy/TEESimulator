package org.matrix.TEESimulator.rka.bridge

internal fun testKeyMetadata(hash: Hash32): List<BrokerKeyMetadata> {
    val bytes = hash.copyBytes()
    hash.close()
    return listOf(
        BrokerKeyMetadata(
            0,
            Hash32.of(bytes),
            Hash32.of(bytes),
            Hash32.of(bytes),
        )
    )
}

internal fun testBatchId(): BrokerBatchId = BrokerBatchId.of(ByteArray(16) { 7 })
