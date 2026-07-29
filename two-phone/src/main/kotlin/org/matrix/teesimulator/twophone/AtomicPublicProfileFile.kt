package org.matrix.teesimulator.twophone

import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream

sealed class PublicProfileStoreException(message: String) : RuntimeException(message) {
    class OversizedBlob : PublicProfileStoreException("public profile blob exceeds the size limit")

    class UnexpectedLength : PublicProfileStoreException("public profile blob length changed")

    class RootOwnershipRequired :
        PublicProfileStoreException("target public profile store requires UID 0")

    class InvalidOwner : PublicProfileStoreException("target public profile is not root-owned")

    class InvalidMode : PublicProfileStoreException("target public profile mode is not 0600")
}

class AtomicPublicProfileFile(private val facade: PublicProfileAtomicFileFacade) {
    private val monitor = Any()

    fun read(): ByteArray? =
        synchronized(monitor) {
            val presentBeforeOpen = facade.isPresent()
            val stream =
                try {
                    facade.openRead()
                } catch (failure: FileNotFoundException) {
                    if (!presentBeforeOpen && !facade.isPresent()) return@synchronized null
                    throw failure
                }
            stream.use(::readExactly)
        }

    fun write(blob: ByteArray) {
        if (blob.size > PublicProfileCodec.MAX_PROFILE_BYTES) {
            throw PublicProfileStoreException.OversizedBlob()
        }
        synchronized(monitor) {
            val stableBlob = blob.copyOf()
            val stream = facade.startWrite()
            try {
                facade.prepareWrite(stream)
                stream.write(stableBlob)
                facade.finishWrite(stream)
            } catch (failure: Throwable) {
                try {
                    facade.failWrite(stream)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                throw failure
            }
        }
    }

    private fun readExactly(stream: FileInputStream): ByteArray {
        val size = stream.channel.size()
        if (size > PublicProfileCodec.MAX_PROFILE_BYTES) {
            throw PublicProfileStoreException.OversizedBlob()
        }
        if (size < 0 || size > Int.MAX_VALUE) {
            throw PublicProfileStoreException.UnexpectedLength()
        }
        val result = ByteArray(size.toInt())
        var offset = 0
        while (offset < result.size) {
            val count = stream.read(result, offset, result.size - offset)
            if (count <= 0) throw PublicProfileStoreException.UnexpectedLength()
            offset += count
        }
        if (stream.read() != -1) throw PublicProfileStoreException.UnexpectedLength()
        return result
    }
}

interface PublicProfileAtomicFileFacade {
    fun isPresent(): Boolean

    fun openRead(): FileInputStream

    fun startWrite(): FileOutputStream

    fun prepareWrite(stream: FileOutputStream)

    fun finishWrite(stream: FileOutputStream)

    fun failWrite(stream: FileOutputStream)
}
