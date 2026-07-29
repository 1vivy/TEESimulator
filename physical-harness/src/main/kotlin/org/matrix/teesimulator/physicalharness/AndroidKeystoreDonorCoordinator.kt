package org.matrix.teesimulator.physicalharness

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.matrix.teesimulator.twophone.WireCallerIdentity

internal class AndroidKeystoreDonorCoordinator {
    val monitor = Any()
    val operations = ConcurrentHashMap<UUID, CoordinatedOperationRecord>()

    companion object {
        val processWide = AndroidKeystoreDonorCoordinator()
    }
}

internal class CoordinatedOperationRecord(
    val alias: String,
    val caller: WireCallerIdentity,
    val backendOperation: BackendSignOperation,
)
