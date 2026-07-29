package org.matrix.teesimulator.physicalharness

import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import org.matrix.teesimulator.twophone.PublicProfileAtomicFileFacade
import org.matrix.teesimulator.twophone.PublicProfileStoreException

class AndroidPublicProfileAtomicFileFacade(
    private val baseFile: File,
    private val rootOwnedMode: Int? = null,
) : PublicProfileAtomicFileFacade {
    private val atomicFile = AtomicFile(baseFile)

    override fun isPresent(): Boolean =
        baseFile.exists() ||
            File(baseFile.path + LEGACY_BACKUP_SUFFIX).exists() ||
            File(baseFile.path + NEW_WRITE_SUFFIX).exists()

    override fun openRead(): FileInputStream =
        atomicFile.openRead().also { stream ->
            try {
                rootOwnedMode?.let { validateRootFile(stream, it) }
            } catch (failure: Throwable) {
                stream.close()
                throw failure
            }
        }

    override fun startWrite(): FileOutputStream {
        if (rootOwnedMode != null && Process.myUid() != TargetPublicProfileStore.REQUIRED_UID) {
            throw PublicProfileStoreException.RootOwnershipRequired()
        }
        return atomicFile.startWrite()
    }

    override fun prepareWrite(stream: FileOutputStream) {
        rootOwnedMode?.let { mode ->
            Os.fchmod(stream.fd, mode)
            validateRootFile(stream, mode)
        }
    }

    override fun finishWrite(stream: FileOutputStream) = atomicFile.finishWrite(stream)

    override fun failWrite(stream: FileOutputStream) = atomicFile.failWrite(stream)

    private fun validateRootFile(stream: FileInputStream, expectedMode: Int) {
        validateStat(Os.fstat(stream.fd).st_uid, Os.fstat(stream.fd).st_mode, expectedMode)
    }

    private fun validateRootFile(stream: FileOutputStream, expectedMode: Int) {
        validateStat(Os.fstat(stream.fd).st_uid, Os.fstat(stream.fd).st_mode, expectedMode)
    }

    private fun validateStat(uid: Int, mode: Int, expectedMode: Int) {
        if (uid != TargetPublicProfileStore.REQUIRED_UID) {
            throw PublicProfileStoreException.InvalidOwner()
        }
        val permissionMask = OsConstants.S_IRWXU or OsConstants.S_IRWXG or OsConstants.S_IRWXO
        if (mode and permissionMask != expectedMode) {
            throw PublicProfileStoreException.InvalidMode()
        }
    }

    private companion object {
        const val LEGACY_BACKUP_SUFFIX = ".bak"
        const val NEW_WRITE_SUFFIX = ".new"
    }
}
