package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Path

internal data class EvidencePaths(
    val json: Path,
    val cbor: Path,
    val marker: Path,
    val lock: Path,
    val jsonBackup: Path,
    val cborBackup: Path,
    val parent: Path,
) {
    companion object {
        fun from(jsonPath: Path): EvidencePaths {
            val json = jsonPath.toAbsolutePath()
            val parent = json.parent ?: throw HostCliException("EVIDENCE_PATH_UNSAFE")
            val name = json.fileName.toString()
            if (name.isBlank()) throw HostCliException("EVIDENCE_PATH_UNSAFE")
            return EvidencePaths(
                json,
                json.resolveSibling("$name.cbor"),
                json.resolveSibling(".$name.transaction"),
                json.resolveSibling(".$name.lock"),
                json.resolveSibling(".$name.json.backup"),
                json.resolveSibling(".$name.cbor.backup"),
                parent,
            )
        }
    }
}
