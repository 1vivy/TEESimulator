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
            SupervisorRecordTextParser.parse(validRecord().replace("role=DONOR", "role=donor"))
        )
        assertNull(
            SupervisorRecordTextParser.parse(
                validRecord().replace("role=DONOR", "role=DONOR\nrole=CANDIDATE")
            )
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
        assertEquals(BrokerSidecarRole.DONOR, parsed.role)
        assertEquals(
            listOf(SupervisorRecordFields.FIXED_EXECUTABLE, "--role", "donor"),
            parsed.snapshot().cmdline,
        )
    }

    @Test
    fun role_binding_rejects_both_cross_role_records() {
        val donor = requireNotNull(SupervisorRecordTextParser.parse(validRecord()))
        val candidate =
            requireNotNull(
                SupervisorRecordTextParser.parse(
                    validRecord().replace("role=DONOR", "role=CANDIDATE")
                )
            )

        assertNull(donor.snapshotFor(BrokerSidecarRole.CANDIDATE))
        assertNull(candidate.snapshotFor(BrokerSidecarRole.DONOR))
        assertEquals(BrokerSidecarRole.DONOR, donor.role)
        assertEquals(BrokerSidecarRole.CANDIDATE, candidate.role)
    }

    @Test
    fun role_record_snapshot_rejects_a_live_process_with_mismatched_role_argv() {
        val donor = requireNotNull(SupervisorRecordTextParser.parse(validRecord()))
        val snapshot = requireNotNull(donor.snapshotFor(BrokerSidecarRole.DONOR))
        val observed =
            ObservedProcessIdentity(
                startTimeTicks = snapshot.startTimeTicks,
                cmdline =
                    listOf(
                        SupervisorRecordFields.FIXED_EXECUTABLE,
                        "--role",
                        BrokerSidecarRole.CANDIDATE.argvValue,
                    ),
                executablePath = snapshot.executablePath,
                executableInode = snapshot.executableInode,
            )

        assertTrue(!identityMatches(PeerCredentials(0, 0, snapshot.pid), snapshot, observed))
    }

    @Test
    fun donor_admits_only_the_exact_root_provisioning_process_from_the_supervised_inode() {
        val donor = requireNotNull(SupervisorRecordTextParser.parse(validRecord()))
        val supervised = requireNotNull(donor.snapshotFor(BrokerSidecarRole.DONOR))
        val credentials = PeerCredentials(0, 0, 84)
        val observed =
            ObservedProcessIdentity(
                startTimeTicks = 991,
                cmdline = listOf(SupervisorRecordFields.FIXED_EXECUTABLE, "provision"),
                executablePath = supervised.executablePath,
                executableInode = supervised.executableInode,
            )

        val admitted =
            provisioningPeerSnapshot(BrokerSidecarRole.DONOR, credentials, supervised, observed)

        assertEquals(credentials.pid, requireNotNull(admitted).pid)
        assertEquals(observed.startTimeTicks, admitted.startTimeTicks)
        assertTrue(identityMatches(credentials, admitted, observed))
        assertNull(
            provisioningPeerSnapshot(BrokerSidecarRole.CANDIDATE, credentials, supervised, observed)
        )
        assertNull(
            provisioningPeerSnapshot(
                BrokerSidecarRole.DONOR,
                PeerCredentials(1, 0, credentials.pid),
                supervised,
                observed,
            )
        )
        assertNull(
            provisioningPeerSnapshot(
                BrokerSidecarRole.DONOR,
                credentials,
                supervised,
                observed.copy(cmdline = listOf(SupervisorRecordFields.FIXED_EXECUTABLE, "health")),
            )
        )
        assertNull(
            provisioningPeerSnapshot(
                BrokerSidecarRole.DONOR,
                credentials,
                supervised,
                observed.copy(executableInode = 1235),
            )
        )
    }

    @Test
    fun donor_admits_the_exact_root_synthetic_lease_probe_from_the_supervised_inode() {
        val donor = requireNotNull(SupervisorRecordTextParser.parse(validRecord()))
        val supervised = requireNotNull(donor.snapshotFor(BrokerSidecarRole.DONOR))
        val credentials = PeerCredentials(0, 0, 85)
        val observed =
            ObservedProcessIdentity(
                startTimeTicks = 992,
                cmdline = listOf(SupervisorRecordFields.FIXED_EXECUTABLE, "synthetic-lease-probe"),
                executablePath = supervised.executablePath,
                executableInode = supervised.executableInode,
            )

        val admitted =
            provisioningPeerSnapshot(BrokerSidecarRole.DONOR, credentials, supervised, observed)

        assertEquals(credentials.pid, requireNotNull(admitted).pid)
        assertEquals(observed.startTimeTicks, admitted.startTimeTicks)
        assertTrue(identityMatches(credentials, admitted, observed))
        assertNull(
            provisioningPeerSnapshot(BrokerSidecarRole.CANDIDATE, credentials, supervised, observed)
        )
        assertNull(
            provisioningPeerSnapshot(
                BrokerSidecarRole.DONOR,
                credentials,
                supervised,
                observed.copy(
                    cmdline =
                        listOf(
                            SupervisorRecordFields.FIXED_EXECUTABLE,
                            "synthetic-lease-probe-extra",
                        )
                ),
            )
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
