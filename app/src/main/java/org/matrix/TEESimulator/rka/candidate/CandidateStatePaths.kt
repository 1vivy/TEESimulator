package org.matrix.TEESimulator.rka.candidate

import java.nio.file.Path

internal val PRODUCTION_RKA_STATE_ROOT: Path = Path.of("/data/adb/teesimulator-rka")

internal class CandidateStatePaths(baseRoot: Path, identityHash: IdentityHash) {
    val candidatesRoot: Path = baseRoot.resolve("candidates")
    val candidateRoot: Path = candidatesRoot.resolve(identityHash.directoryName())
    val keyStoreRoot: Path = candidateRoot.resolve("candidate-keystore")
    val leaseStatePath: Path = candidateRoot.resolve("synthetic-leases").resolve("state.bin")
    val pairedActivationRecordPath: Path =
        candidateRoot.resolve("records").resolve("paired-activation-v1")
}

private fun IdentityHash.directoryName(): String =
    copyBytes().joinToString("") { "%02x".format(it.toInt() and 0xff) }
