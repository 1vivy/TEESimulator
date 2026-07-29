package org.matrix.teesimulator.physicalharness

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream

interface DonorStateBlobStore {
    fun read(): ByteArray?

    fun write(blob: ByteArray)
}

internal fun interface DonorStateArtifactProbe {
    fun hasArtifacts(): Boolean
}

sealed class DonorStateBlobStoreException(message: String) : RuntimeException(message) {
    class OversizedBlob : DonorStateBlobStoreException("durable state blob exceeds the size limit")

    class UnexpectedLength : DonorStateBlobStoreException("durable state blob length changed")
}

class AtomicFileDonorStateBlobStore
internal constructor(private val atomicFile: DonorAtomicFileFacade) :
    DonorStateBlobStore, DonorStateArtifactProbe {
    constructor(
        context: Context
    ) : this(AndroidDonorAtomicFileFacade(File(context.noBackupFilesDir, FILE_NAME)))

    private val monitor = Any()

    override fun hasArtifacts(): Boolean = synchronized(monitor) { atomicFile.isPresent() }

    override fun read(): ByteArray? =
        synchronized(monitor) {
            val presentBeforeOpen = atomicFile.isPresent()
            val stream =
                try {
                    atomicFile.openRead()
                } catch (failure: FileNotFoundException) {
                    val presentAfterOpen = atomicFile.isPresent()
                    if (!presentBeforeOpen && !presentAfterOpen) return@synchronized null
                    throw failure
                }
            stream.use(::readExactly)
        }

    override fun write(blob: ByteArray) {
        if (blob.size > DonorStateCodec.MAX_FILE_BYTES) {
            throw DonorStateBlobStoreException.OversizedBlob()
        }
        synchronized(monitor) {
            val stableBlob = blob.copyOf()
            val stream = atomicFile.startWrite()
            try {
                stream.write(stableBlob)
                atomicFile.finishWrite(stream)
            } catch (failure: Throwable) {
                try {
                    atomicFile.failWrite(stream)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                throw failure
            }
        }
    }

    private fun readExactly(stream: FileInputStream): ByteArray {
        val declaredSize = stream.channel.size()
        if (declaredSize > DonorStateCodec.MAX_FILE_BYTES) {
            throw DonorStateBlobStoreException.OversizedBlob()
        }
        if (declaredSize < 0 || declaredSize > Int.MAX_VALUE) {
            throw DonorStateBlobStoreException.UnexpectedLength()
        }
        val result = ByteArray(declaredSize.toInt())
        var offset = 0
        while (offset < result.size) {
            val count = stream.read(result, offset, result.size - offset)
            if (count < 0) throw DonorStateBlobStoreException.UnexpectedLength()
            if (count == 0) throw DonorStateBlobStoreException.UnexpectedLength()
            offset += count
        }
        if (stream.read() != -1) throw DonorStateBlobStoreException.UnexpectedLength()
        return result
    }

    companion object {
        const val FILE_NAME = "donor-state-v1.bin"
    }
}

internal interface DonorAtomicFileFacade {
    fun isPresent(): Boolean

    fun openRead(): FileInputStream

    fun startWrite(): FileOutputStream

    fun finishWrite(stream: FileOutputStream)

    fun failWrite(stream: FileOutputStream)
}

private class AndroidDonorAtomicFileFacade(private val baseFile: File) : DonorAtomicFileFacade {
    private val atomicFile = AtomicFile(baseFile)

    override fun isPresent(): Boolean =
        baseFile.exists() ||
            File(baseFile.path + LEGACY_BACKUP_SUFFIX).exists() ||
            File(baseFile.path + NEW_WRITE_SUFFIX).exists()

    override fun openRead(): FileInputStream = atomicFile.openRead()

    override fun startWrite(): FileOutputStream = atomicFile.startWrite()

    override fun finishWrite(stream: FileOutputStream) = atomicFile.finishWrite(stream)

    override fun failWrite(stream: FileOutputStream) = atomicFile.failWrite(stream)

    private companion object {
        const val LEGACY_BACKUP_SUFFIX = ".bak"
        const val NEW_WRITE_SUFFIX = ".new"
    }
}
