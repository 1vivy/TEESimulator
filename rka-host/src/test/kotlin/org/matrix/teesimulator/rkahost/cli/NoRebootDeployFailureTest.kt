package org.matrix.teesimulator.rkahost.cli

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NoRebootDeployFailureTest {
    @Test
    fun exactBusyBindUsesLazyDetachOnlyAfterStoppedUnambiguousMount() {
        Fixture(FixtureMutation.ROLLBACK_BUSY_BIND_SAFE).use { fixture ->
            assertEquals(4, fixture.run().exitCode)
            assertTrue(fixture.donorNormalUnmountAttempted())
            assertTrue(fixture.donorLazyUnmountAttempted())
            assertFalse(fixture.donorBindPresent())
            assertEquals(0, fixture.rollbackDonorAgain().exitCode)
        }
    }

    @Test
    fun unsafeBusyBindNeverUsesLazyDetach() {
        listOf(
                FixtureMutation.ROLLBACK_BUSY_BIND_NESTED,
                FixtureMutation.ROLLBACK_BUSY_BIND_LIVE,
                FixtureMutation.ROLLBACK_BUSY_BIND_AMBIGUOUS,
            )
            .forEach { mutation ->
                Fixture(mutation).use { fixture ->
                    val result = fixture.run()
                    assertEquals(mutation.name, 4, result.exitCode)
                    assertTrue(mutation.name, result.stderr.contains("ROLLBACK_BUSY_BIND_UNSAFE"))
                    assertTrue(mutation.name, fixture.donorNormalUnmountAttempted())
                    assertFalse(mutation.name, fixture.donorLazyUnmountAttempted())
                    assertTrue(mutation.name, fixture.donorBindPresent())
                }
            }
    }

    @Test
    fun hostileAndroidLogcatCannotBlockStandardPairAfterDonorDeploy() {
        Fixture(FixtureMutation.HOSTILE_LOGCAT).use { fixture ->
            val result = fixture.runWithMutationBounded(FixtureMutation.HOSTILE_LOGCAT, 30)

            assertTrue(
                "result=$result trace=${fixture.trace()}",
                fixture.trace().any { it.startsWith("DONOR_A ") && " deploy " in " $it " },
            )
            assertEquals(result.stderr, 0, result.exitCode)
            assertFalse(fixture.logcatInvoked())
        }
    }

    @Test
    fun ordinaryPairFileDescriptorIsRejectedBeforeAdb() {
        Fixture().use { fixture ->
            val result = fixture.runWithOrdinaryPairDescriptor()

            assertEquals(2, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=PAIR_DESCRIPTOR_INVALID"))
            assertTrue(fixture.trace().isEmpty())
        }
    }

    @Test
    fun unsealedMemfdIsRejectedBeforeAdb() {
        Fixture().use { fixture ->
            val result = fixture.runWithUnsealedMemfd()

            assertEquals(2, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=PAIR_DESCRIPTOR_INVALID"))
            assertTrue(fixture.trace().isEmpty())
        }
    }

    @Test
    fun exactCompatibilityMismatchStopsBeforeAnyMutation() {
        Fixture(FixtureMutation.INCOMPATIBLE_CANDIDATE).use { fixture ->
            val result = fixture.run()

            assertEquals(3, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=KSU_COMPATIBILITY_MISMATCH"))
            assertTrue(fixture.trace().all { "preflight" in it })
            assertFalse(fixture.trace().any { "push" in it || "deploy" in it || "rollback" in it })
        }
    }

    @Test
    fun sameArchiveDeploysDistinctRolesAndPublicPinsWithoutReboot() {
        Fixture().use { fixture ->
            val result = fixture.run()
            val repeated = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertEquals(repeated.stderr, 0, repeated.exitCode)
            assertTrue(result.stdout.contains("\"result\":\"DEPLOYED_NO_REBOOT\""))
            val trace = fixture.trace()
            val pushes = trace.filter { " push " in " $it " }
            assertEquals(8, pushes.size)
            val archives = pushes.filterNot { ".source-sha " in it }
            assertEquals(4, archives.size)
            assertEquals(
                1,
                archives.map { it.substringAfter("push ").substringBeforeLast(' ') }.toSet().size,
            )
            assertTrue(
                trace.any {
                    Regex("deploy .* DONOR [0-9a-f]{64} [0-9a-f]{40}$").containsMatchIn(it)
                }
            )
            assertTrue(
                trace.any {
                    Regex("deploy .* CANDIDATE [0-9a-f]{64} [0-9a-f]{40}$").containsMatchIn(it)
                }
            )
            assertTrue(trace.any { Regex("pair .* DONOR ").containsMatchIn(it) })
            assertTrue(trace.any { Regex("pair .* CANDIDATE ").containsMatchIn(it) })
            assertTrue(trace.any { "direct-probe" in it })
            val attempts =
                trace
                    .filter { " deploy " in " $it " }
                    .map { it.substringAfter("deploy ").substringBefore(' ') }
                    .toSet()
            assertEquals(2, attempts.size)
            assertTrue(fixture.hasCompleteAttemptReceipts(expectedAttempts = 2))
            assertTrue(fixture.hasAndroidWebViewOwnershipFacts(expectedAttempts = 2))
            assertTrue(fixture.hasDistinctMountViewFacts(expectedAttempts = 2))
            assertTrue(fixture.hasTls13ProbeReceipts(expectedAttempts = 2))
            assertTrue(fixture.tlsServersStopped())
            assertFalse(trace.any { forbidden.containsMatchIn(it) })
            println(
                "EFFECT_RECEIPT scenario=same-build attempts=2 devices=2 complete_receipts=4 order=${fixture.redactedOrder()}"
            )
        }
    }

    @Test
    fun donorDialsProfilesUseRemoteCandidateAndLocalInterfaces() {
        Fixture().use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.directProfile("DONOR_A").contains("dial_endpoint=100.88.0.2\n"))
            assertTrue(fixture.directProfile("DONOR_A").contains("listen_interface=192.168.50.9\n"))
            assertTrue(fixture.directProfile("CANDIDATE_B").contains("dial_endpoint=100.88.0.2\n"))
            assertTrue(
                fixture.directProfile("CANDIDATE_B").contains("listen_interface=100.88.0.2\n")
            )
        }
    }

    @Test
    fun donorWlanSourceAndCandidateTunTargetAreDiscoveredByRole() {
        Fixture(FixtureMutation.DONOR_WLAN_CANDIDATE_TUN).use { fixture ->
            val result = fixture.run()

            assertEquals(result.stderr, 0, result.exitCode)
            assertTrue(fixture.directProfile("DONOR_A").contains("dial_endpoint=100.88.0.2\n"))
            assertTrue(fixture.directProfile("DONOR_A").contains("listen_interface=192.168.50.9\n"))
            assertTrue(
                fixture.directProfile("CANDIDATE_B").contains("listen_interface=100.88.0.2\n")
            )
        }
    }

    @Test
    fun roleSwappedNetworkInterfacesFailBeforeUpload() {
        Fixture(FixtureMutation.NETWORK_SIDE_SWAP).use { fixture ->
            val result = fixture.run()

            assertEquals(3, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=DIRECT_PATH_UNAVAILABLE"))
            assertTrue(fixture.trace().none { " push " in " $it " || " deploy " in " $it " })
        }
    }

    @Test
    fun tunInterfaceSuffixIsNormalizedWithoutAcceptingMalformedCandidates() {
        Fixture(FixtureMutation.TUN_SUFFIX).use { fixture ->
            val result = fixture.run()
            assertEquals(result.stderr, 0, result.exitCode)
        }
        listOf(
                FixtureMutation.TUN_MULTIPLE,
                FixtureMutation.TUN_SPECIAL,
                FixtureMutation.TUN_UNSPECIFIED,
                FixtureMutation.TUN_LINK_LOCAL,
                FixtureMutation.TUN_MULTICAST,
                FixtureMutation.TUN_BROADCAST,
                FixtureMutation.TUN_WHITESPACE,
                FixtureMutation.TUN_MALFORMED,
            )
            .forEach { mutation ->
                Fixture(mutation).use { fixture ->
                    val result = fixture.run()
                    assertEquals(3, result.exitCode)
                    assertTrue(result.stderr.contains("RESULT=DIRECT_PATH_UNAVAILABLE"))
                    assertTrue(
                        fixture.trace().none { " push " in " $it " || " deploy " in " $it " }
                    )
                }
            }
    }

    @Test
    fun failedSecondInstallRollsBackBothSidesWithoutFallback() {
        Fixture(FixtureMutation.FAIL_CANDIDATE_DEPLOY).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            val trace = fixture.trace()
            assertTrue(trace.any { Regex("rollback .* CANDIDATE$").containsMatchIn(it) })
            assertTrue(trace.any { Regex("rollback .* DONOR$").containsMatchIn(it) })
            assertFalse(trace.any { "usb" in it.lowercase() || forbidden.containsMatchIn(it) })
            println(
                "EFFECT_RECEIPT scenario=second-side-failure rollback_devices=2 order=${fixture.redactedOrder()}"
            )
        }
    }

    @Test
    fun failedFirstInstallStillRunsIdempotentPairRollback() {
        Fixture(FixtureMutation.FAIL_DONOR_DEPLOY).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            val trace = fixture.trace()
            assertTrue(trace.any { Regex("rollback .* CANDIDATE$").containsMatchIn(it) })
            assertTrue(trace.any { Regex("rollback .* DONOR$").containsMatchIn(it) })
            assertFalse(trace.any { "usb" in it.lowercase() || forbidden.containsMatchIn(it) })
        }
    }

    @Test
    fun directOnlyCliRejectsUsbBeforeDeviceAccess() {
        Fixture().use { fixture ->
            val result = fixture.run(network = "usb")

            assertEquals(2, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=ARGUMENT_INVALID"))
            assertTrue(fixture.trace().isEmpty())
        }
    }

    @Test
    fun unavailableDirectPathStopsBeforeArchivePush() {
        Fixture(FixtureMutation.FAIL_CANDIDATE_NETWORK).use { fixture ->
            val result = fixture.run()

            assertEquals(3, result.exitCode)
            assertTrue(result.stderr.contains("RESULT=DIRECT_PATH_UNAVAILABLE"))
            assertFalse(fixture.trace().any { "push" in it || "deploy" in it })
        }
    }

    @Test
    fun mismatchedPeerPinRollsBackBothSides() {
        Fixture(FixtureMutation.MISMATCH_CANDIDATE_PIN).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            assertTrue(fixture.trace().count { " rollback " in " $it " } >= 2)
            assertFalse(fixture.trace().any { forbidden.containsMatchIn(it) })
        }
    }

    @Test
    fun failedSameBuildRedeployRestoresThePriorLiveBind() {
        Fixture().use { fixture ->
            val first = fixture.run()
            assertEquals(first.stderr, 0, first.exitCode)
            val priorActive = fixture.activeModuleBytes()

            val failed = fixture.runWithMismatchedProbe()

            assertEquals(4, failed.exitCode)
            assertArrayEquals(priorActive, fixture.activeModuleBytes())
            assertTrue(fixture.trace().count { " rollback " in " $it " } >= 2)
            println(
                "EFFECT_RECEIPT scenario=live-bind-rollback prior_bytes_restored=true order=${fixture.redactedOrder()}"
            )
        }
    }

    @Test
    fun failureAfterStoppingPriorRuntimeRestoresLiveState() {
        assertEarlyRedeployRecovery(FixtureMutation.AFTER_STOP)
    }

    @Test
    fun failureAfterUnmountingPriorBindRestoresLiveState() {
        assertEarlyRedeployRecovery(FixtureMutation.AFTER_UNMOUNT)
    }

    @Test
    fun activeHashFailureRestoresLiveState() {
        assertEarlyRedeployRecovery(FixtureMutation.ACTIVE_HASH)
    }

    @Test
    fun activeMetadataFailureRestoresLiveState() {
        assertEarlyRedeployRecovery(FixtureMutation.ACTIVE_METADATA)
    }

    @Test
    fun activeCopyFailureRestoresLiveState() {
        assertEarlyRedeployRecovery(FixtureMutation.ACTIVE_COPY)
    }

    @Test
    fun stalePartialTransactionRollbackIsIdempotent() {
        Fixture().use { fixture ->
            assertEquals(0, fixture.run().exitCode)
            val before = fixture.donorModuleSnapshot()

            assertEquals(4, fixture.runWithMutation(FixtureMutation.AFTER_UNMOUNT).exitCode)
            val repeatedRollback = fixture.rollbackDonorAgain()

            assertEquals(0, repeatedRollback.exitCode)
            assertSnapshotEquals(before, fixture.donorModuleSnapshot())
            assertTrue(fixture.donorBindPresent())
            assertTrue(fixture.donorRuntimeRunning())
        }
    }

    @Test
    fun rollbackVerificationFailureRetainsSnapshotsForExactRetry() {
        Fixture().use { fixture ->
            val installed = fixture.run()
            assertEquals(installed.stderr, 0, installed.exitCode)
            val before = fixture.donorModuleSnapshot()

            assertEquals(4, fixture.runWithMutation(FixtureMutation.ROLLBACK_VERIFY_ONCE).exitCode)
            val repeatedRollback = fixture.rollbackDonorAgain()

            assertEquals(repeatedRollback.stderr, 0, repeatedRollback.exitCode)
            assertSnapshotEquals(before, fixture.donorModuleSnapshot())
            assertTrue(fixture.donorBindPresent())
            assertTrue(fixture.donorRuntimeRunning())
        }
    }

    @Test
    fun remoteArchiveHashMismatchFailsBeforeInstall() {
        Fixture(FixtureMutation.CORRUPT_REMOTE_ARCHIVE).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            assertTrue(fixture.trace().any { " deploy " in " $it " })
            assertFalse(fixture.trace().any { " pair " in " $it " })
        }
    }

    @Test
    fun remoteSourceReceiptMismatchFailsBeforeInstall() {
        Fixture(FixtureMutation.CORRUPT_REMOTE_SOURCE).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            assertTrue(fixture.trace().any { " deploy " in " $it " })
            assertFalse(fixture.trace().any { " pair " in " $it " })
        }
    }

    @Test
    fun unrelatedWebViewOwnerIsRejected() {
        Fixture(FixtureMutation.WEBUI_WRONG_OWNER).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            assertFalse(result.stdout.contains("DEPLOYED_NO_REBOOT"))
        }
    }

    @Test
    fun ambiguousManagerOwnedWebViewsAreRejected() {
        Fixture(FixtureMutation.WEBUI_AMBIGUOUS_OWNER).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            assertFalse(result.stdout.contains("DEPLOYED_NO_REBOOT"))
        }
    }

    @Test
    fun missingManagerWebViewAssociationIsRejected() {
        Fixture(FixtureMutation.WEBUI_MISSING_OWNER).use { fixture ->
            val result = fixture.run()

            assertEquals(4, result.exitCode)
            assertFalse(result.stdout.contains("DEPLOYED_NO_REBOOT"))
        }
    }

    private fun assertEarlyRedeployRecovery(mutation: FixtureMutation) {
        Fixture().use { fixture ->
            assertEquals(0, fixture.run().exitCode)
            val before = fixture.donorModuleSnapshot()

            val failed = fixture.runWithMutation(mutation)

            assertEquals(4, failed.exitCode)
            assertSnapshotEquals(before, fixture.donorModuleSnapshot())
            assertTrue(fixture.donorBindPresent())
            assertTrue(fixture.donorRuntimeRunning())
        }
    }

    private fun assertSnapshotEquals(expected: ModuleSnapshot, actual: ModuleSnapshot) {
        assertArrayEquals(expected.bytes, actual.bytes)
        assertEquals(expected.permissions, actual.permissions)
        assertEquals(expected.modifiedMillis, actual.modifiedMillis)
    }

    private companion object {
        val forbidden = Regex("(^| )(reboot|soft-reboot|late-load|services|usb)( |$)")
    }
}
