package org.matrix.teesimulator.physicalharness

import android.content.Context

sealed class DonorStateSecurityBootstrapException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class UnverifiableState(cause: Throwable? = null) :
        DonorStateSecurityBootstrapException("donor state cannot be authenticated", cause)

    class InconsistentArtifacts :
        DonorStateSecurityBootstrapException("donor state bootstrap is inconsistent")
}

internal interface DonorStateMacStore {
    fun exists(): Boolean

    fun openExisting(): HandleMac

    fun createNew(): HandleMac

    fun deleteCreated(mac: HandleMac)
}

internal class AndroidKeyStoreDonorStateMacStore : DonorStateMacStore {
    override fun exists(): Boolean = AndroidKeyStoreHandleMac.exists()

    override fun openExisting(): HandleMac = AndroidKeyStoreHandleMac.openExisting()

    override fun createNew(): HandleMac = AndroidKeyStoreHandleMac.createNew()

    override fun deleteCreated(mac: HandleMac) {
        val created =
            mac as? AndroidKeyStoreHandleMac
                ?: throw IllegalArgumentException("invalid donor state authenticator")
        created.deleteForBootstrapRollback()
    }
}

internal fun interface DonorOwnedAliasSource {
    fun hasOwnedAliases(): Boolean
}

internal class AndroidKeystoreDonorOwnedAliasSource(private val donor: AndroidKeystoreDonor) :
    DonorOwnedAliasSource {
    override fun hasOwnedAliases(): Boolean = donor.ownedAliases().isNotEmpty()
}

class DonorStateSecurityBootstrap
internal constructor(
    private val stateArtifacts: DonorStateArtifactProbe,
    private val blobStore: DonorStateBlobStore,
    private val macStore: DonorStateMacStore,
    private val donorAliases: DonorOwnedAliasSource,
) {
    constructor(
        context: Context,
        donor: AndroidKeystoreDonor,
    ) : this(
        AtomicFileDonorStateBlobStore(context),
        AndroidKeyStoreDonorStateMacStore(),
        AndroidKeystoreDonorOwnedAliasSource(donor),
    )

    private constructor(
        stateStore: AtomicFileDonorStateBlobStore,
        macStore: DonorStateMacStore,
        donorAliases: DonorOwnedAliasSource,
    ) : this(stateStore, stateStore, macStore, donorAliases)

    fun bootstrap(): HandleMac =
        synchronized(processWideLock) {
            inspectCurrentArtifacts()?.let {
                return@synchronized it
            }
            inspectCurrentArtifacts()?.let {
                return@synchronized it
            }
            createAuthenticatedEmptyState()
        }

    private fun inspectCurrentArtifacts(): HandleMac? {
        if (stateArtifacts.hasArtifacts()) {
            if (!macStore.exists()) {
                throw DonorStateSecurityBootstrapException.UnverifiableState()
            }
            return try {
                macStore.openExisting()
            } catch (failure: RuntimeException) {
                throw DonorStateSecurityBootstrapException.UnverifiableState(failure)
            }
        }
        if (donorAliases.hasOwnedAliases()) {
            throw DonorStateSecurityBootstrapException.InconsistentArtifacts()
        }
        if (macStore.exists()) {
            throw DonorStateSecurityBootstrapException.InconsistentArtifacts()
        }
        return null
    }

    private fun createAuthenticatedEmptyState(): HandleMac {
        val mac = macStore.createNew()
        try {
            val emptyState = DonorStateSnapshot(0uL, emptyList(), emptyList())
            blobStore.write(DonorStateCodec(mac).encode(emptyState))
            return mac
        } catch (failure: Throwable) {
            reconcileFailedWrite(mac, failure)
        }
    }

    private fun reconcileFailedWrite(mac: HandleMac, failure: Throwable): Nothing {
        if (cleanupProbeFailed(failure) { stateArtifacts.hasArtifacts() }) throw failure
        if (cleanupProbeFailed(failure) { donorAliases.hasOwnedAliases() }) throw failure
        try {
            macStore.deleteCreated(mac)
        } catch (rollbackFailure: Throwable) {
            failure.addSuppressed(rollbackFailure)
        }
        throw failure
    }

    private inline fun cleanupProbeFailed(failure: Throwable, probe: () -> Boolean): Boolean =
        try {
            probe()
        } catch (probeFailure: Throwable) {
            failure.addSuppressed(probeFailure)
            true
        }

    private companion object {
        val processWideLock = Any()
    }
}
