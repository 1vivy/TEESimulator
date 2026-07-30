package org.matrix.TEESimulator.rka.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedSidecarIdentityTest {
    @Test
    fun fixed_schema_rejects_missing_reordered_or_noncanonical_fields() {
        assertNull(SupervisorRecordTextParser.parse("version=1\n"))
        assertNull(
            SupervisorRecordTextParser.parse(
                validRecord()
                    .replace(
                        "generation=9\nlaunch_nonce=",
                        "launch_nonce=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\ngeneration=",
                    )
            )
        )
        assertNull(
            SupervisorRecordTextParser.parse(validRecord().replace("role=DONOR", "role=root"))
        )
        assertNull(
            SupervisorRecordTextParser.parse(
                validRecord()
                    .replace(SupervisorRecordFields.FIXED_EXECUTABLE, "/data/local/tmp/rka-sidecar")
            )
        )
    }

    @Test
    fun fixed_schema_parses_exact_root_launch_identity() {
        val parsed = SupervisorRecordTextParser.parse(validRecord())

        assertTrue(parsed != null)
        requireNotNull(parsed)
        assertEquals(9L, parsed.generation)
        assertEquals(0, parsed.uid)
        assertEquals(0, parsed.gid)
        assertEquals(42, parsed.pid)
        assertEquals(777L, parsed.startTimeTicks)
        assertEquals(1234L, parsed.executableInode)
        assertEquals(
            listOf(SupervisorRecordFields.FIXED_EXECUTABLE, "--role", "donor"),
            parsed.snapshot().cmdline,
        )
    }

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
}
