package org.matrix.teesimulator.physicalharness

internal interface AuthenticatedDonorStateStore {
    fun load(): DonorStateSnapshot?

    fun save(snapshot: DonorStateSnapshot)
}

internal class CodecAuthenticatedDonorStateStore(
    private val blobStore: DonorStateBlobStore,
    private val codec: DonorStateCodec,
) : AuthenticatedDonorStateStore {
    override fun load(): DonorStateSnapshot? = blobStore.read()?.let(codec::decode)

    override fun save(snapshot: DonorStateSnapshot) {
        blobStore.write(codec.encode(snapshot))
    }
}
