package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedSidecarIdentityTest {
    @Test
    fun fixed_schema_fails_typed_when_absent_malformed_or_weakly_protected() {
        val root = Files.createTempDirectory("trusted-sidecar")
        try {
            val parent = root.resolve("pids")
            Files.createDirectory(parent)
            Files.setPosixFilePermissions(parent, DIRECTORY_MODE)
            val uid = unixId(parent, "unix:uid")
            val gid = unixId(parent, "unix:gid")
            val record = parent.resolve("sidecar.identity")
            val source = source(record, uid, gid)

            assertEquals(BridgeError.TrustedStateMissing, source.capture().failure())
            Files.write(record, "version=1\n".toByteArray())
            Files.setPosixFilePermissions(record, FILE_MODE)
            assertEquals(BridgeError.TrustedStateInvalid, source.capture().failure())
            Files.write(record, validRecord().toByteArray())
            Files.setPosixFilePermissions(record, DIRECTORY_MODE)
            assertEquals(BridgeError.TrustedStateInvalid, source.capture().failure())
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun captured_launch_nonce_and_inode_must_remain_exact_during_revalidation() {
        val root = Files.createTempDirectory("trusted-sidecar")
        try {
            val parent = root.resolve("pids")
            Files.createDirectory(parent)
            Files.setPosixFilePermissions(parent, DIRECTORY_MODE)
            val record = parent.resolve("sidecar.identity")
            Files.write(record, validRecord().toByteArray())
            Files.setPosixFilePermissions(record, FILE_MODE)
            val source = source(record, unixId(parent, "unix:uid"), unixId(parent, "unix:gid"))
            val captured = source.capture()
            assertTrue(captured is BridgeResult.Success)

            Files.write(
                record,
                validRecord().replace("generation=9", "generation=10").toByteArray(),
            )
            Files.setPosixFilePermissions(record, FILE_MODE)

            assertEquals(
                BridgeError.TrustedStateChanged,
                source.revalidate((captured as BridgeResult.Success).value).failure(),
            )
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun source(record: Path, uid: Int, gid: Int) =
        ProtectedSupervisorIdentitySource(
            processIdentity =
                ProcessIdentitySource {
                    ObservedProcessIdentity(
                        777,
                        listOf(
                            ProtectedSupervisorIdentitySource.FIXED_EXECUTABLE,
                            "--role",
                            "donor",
                        ),
                        ProtectedSupervisorIdentitySource.FIXED_EXECUTABLE,
                        1234,
                    )
                },
            recordPath = record,
            requiredUid = uid,
            requiredGid = gid,
        )

    private fun validRecord() =
        """
        version=1
        generation=9
        launch_nonce=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        uid=0
        gid=0
        pid=42
        start_time_ticks=777
        executable_inode=1234
        executable_path=/data/adb/teesimulator-rka/bin/rka-sidecar
        role=DONOR
        """
            .trimIndent() + "\n"

    private fun unixId(path: Path, attribute: String): Int =
        (Files.getAttribute(path, attribute) as Number).toInt()

    private fun BridgeResult<*>.failure(): BridgeError = (this as BridgeResult.Failure).error

    private companion object {
        val DIRECTORY_MODE =
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            )
        val FILE_MODE = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    }
}
