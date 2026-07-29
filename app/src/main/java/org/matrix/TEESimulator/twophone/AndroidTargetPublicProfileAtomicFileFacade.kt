package org.matrix.TEESimulator.twophone

import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import org.matrix.teesimulator.twophone.PublicProfileAtomicFileFacade
import org.matrix.teesimulator.twophone.PublicProfileStoreException
import org.matrix.teesimulator.twophone.TargetPublicProfileStore

internal class AndroidTargetPublicProfileAtomicFileFacade : PublicProfileAtomicFileFacade {
    private val baseFile = File(TargetPublicProfileStore.FILE_PATH)
    private val atomicFile = AtomicFile(baseFile)

    override fun isPresent(): Boolean =
        baseFile.exists() ||
            File(baseFile.path + LEGACY_BACKUP_SUFFIX).exists() ||
            File(baseFile.path + NEW_WRITE_SUFFIX).exists()

    override fun openRead(): FileInputStream =
        atomicFile.openRead().also { stream ->
            try {
                validateRootFile(stream)
            } catch (failure: Throwable) {
                stream.close()
                throw failure
            }
        }

    override fun startWrite(): FileOutputStream {
        if (Process.myUid() != TargetPublicProfileStore.REQUIRED_UID) {
            throw PublicProfileStoreException.RootOwnershipRequired()
        }
        return atomicFile.startWrite()
    }

    override fun prepareWrite(stream: FileOutputStream) {
        Os.fchmod(stream.fd, TargetPublicProfileStore.REQUIRED_MODE)
        validateRootFile(stream)
    }

    override fun finishWrite(stream: FileOutputStream) = atomicFile.finishWrite(stream)

    override fun failWrite(stream: FileOutputStream) = atomicFile.failWrite(stream)

    private fun validateRootFile(stream: FileInputStream) {
        val stat = Os.fstat(stream.fd)
        validateStat(stat.st_uid, stat.st_mode)
    }

    private fun validateRootFile(stream: FileOutputStream) {
        val stat = Os.fstat(stream.fd)
        validateStat(stat.st_uid, stat.st_mode)
    }

    private fun validateStat(uid: Int, mode: Int) {
        if (uid != TargetPublicProfileStore.REQUIRED_UID) {
            throw PublicProfileStoreException.InvalidOwner()
        }
        val permissionMask = OsConstants.S_IRWXU or OsConstants.S_IRWXG or OsConstants.S_IRWXO
        if (mode and permissionMask != TargetPublicProfileStore.REQUIRED_MODE) {
            throw PublicProfileStoreException.InvalidMode()
        }
    }

    private companion object {
        const val LEGACY_BACKUP_SUFFIX = ".bak"
        const val NEW_WRITE_SUFFIX = ".new"
    }
}
