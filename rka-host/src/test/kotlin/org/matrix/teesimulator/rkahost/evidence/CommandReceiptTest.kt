package org.matrix.teesimulator.rkahost.evidence

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CommandReceiptTest {
    @Test
    fun rejects_forbidden_argv_before_runner_execution() {
        // Given: a counting runner and dangerous literal/shell-smuggled argv variants.
        val runner = RecordingRunner()
        val commands =
            listOf(
                listOf("adb", "-s", "serial-A", "reboot"),
                listOf("adb", "-s", "serial-A", "shell", "reboot"),
                listOf("adb", "-s", "serial-A", "shell", "kill", "-9", "1"),
                listOf("adb", "-s", "serial-A", "shell", "getprop;reboot"),
                listOf("adb", "-s", "serial-A", "shell", "setprop", "ctl.restart", "keystore2"),
            )

        // When/Then: all are rejected before process execution.
        commands.forEach { argv ->
            assertThrows(CommandRejected::class.java) { AdbCommandPolicy(runner).execute(argv) }
        }
        assertEquals(0, runner.calls)
    }

    @Test
    fun permits_only_literal_read_only_argv_and_models_future_operations() {
        // Given: a fake ADB runner.
        val runner = RecordingRunner()

        // When: a literal allowlisted property read is traced.
        val trace =
            AdbCommandPolicy(runner)
                .execute(
                    listOf("adb", "-s", "serial-A", "shell", "getprop", "ro.build.fingerprint")
                )

        // Then: it executes once without leaking the serial and future service operations stay
        // plans only.
        assertEquals(1, runner.calls)
        assertFalse(trace.canonical().contains("serial-A"))
        assertEquals(false, FutureServiceOperation.KEYSTORE2_STATUS.executed)
        assertEquals(false, FutureServiceOperation.RKPD_STATUS.executed)
    }

    @Test
    fun reconnectCommandsRemainBoundToTheSelectedSerial() {
        AdbCommandTracePolicy.requireAllowed(listOf("adb", "-s", "serial-A", "reconnect"))
        AdbCommandTracePolicy.requireAllowed(
            listOf("adb", "-s", "192.0.2.7:5555", "connect", "192.0.2.7:5555")
        )

        assertThrows(CommandRejected::class.java) {
            AdbCommandTracePolicy.requireAllowed(
                listOf("adb", "-s", "192.0.2.7:5555", "connect", "192.0.2.8:5555")
            )
        }
        assertThrows(CommandRejected::class.java) {
            AdbCommandTracePolicy.requireAllowed(
                listOf("adb", "-s", "serial-A", "reconnect", "offline")
            )
        }
    }

    @Test
    fun classifies_reboot_before_any_runner_or_shape_fallback() {
        // Given: a literal reboot argv whose only valid outcome is a hard no-reboot classification.
        val runner = RecordingRunner()

        // When: the policy receives it.
        val failure =
            assertThrows(CommandRejected::class.java) {
                AdbCommandPolicy(runner).execute(listOf("adb", "-s", "serial-A", "shell", "reboot"))
            }

        // Then: it is classified as forbidden before it could reach a runner.
        assertEquals("ADB_FORBIDDEN_OPERATION", failure.message)
        assertEquals(0, runner.calls)
    }

    @Test
    fun rejectsMisleadingCleanTextWhenReadOnlyCommandExitsNonzero() {
        val runner = RecordingRunner(CommandResult(1, "clean"))

        val failure =
            assertThrows(CommandRejected::class.java) {
                AdbCommandPolicy(runner)
                    .execute(
                        listOf("adb", "-s", "serial-A", "shell", "getprop", "ro.build.fingerprint")
                    )
            }

        assertEquals("ADB_COMMAND_FAILED", failure.message)
        assertEquals(1, runner.calls)
    }

    @Test
    fun receipts_reject_nonce_binding_signature_and_chain_attacks() {
        // Given: a deterministic signer and a sentinel-derived canonical signed receipt.
        val signer = ReceiptTestKeys.signer
        val encoded = issue("nonce-A", signer)

        // When/Then: verification rejects wrong binding, replay, tamper, noncanonical, reorder, and
        // truncation.
        val verifier = ReceiptVerifier(ReceiptTestKeys.trustedKeys)
        verifier.verify(
            encoded,
            ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
        )
        assertThrows(ReceiptException::class.java) {
            verifier.verify(
                encoded,
                ReceiptBinding("commit-B", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
            )
        }
        assertThrows(ReceiptException::class.java) {
            verifier.verify(
                encoded,
                ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
            )
        }
        assertThrows(ReceiptException::class.java) {
            verifier.verify(
                encoded.replace("commit-A", "commit-X"),
                ReceiptBinding("commit-X", "profile-A", EndpointRole.DONOR, "session-A", "nonce-A"),
            )
        }
        assertThrows(ReceiptException::class.java) {
            ReceiptVerifier(ReceiptTestKeys.trustedKeys)
                .verify(
                    encoded.replace("version=2\n", "role=DONOR\nversion=2\n"),
                    ReceiptBinding(
                        "commit-A",
                        "profile-A",
                        EndpointRole.DONOR,
                        "session-A",
                        "nonce-A",
                    ),
                )
        }
        val tamperedSignature =
            encoded.replace(Regex("(?m)^signature=(.)")) {
                "signature=${if (it.groupValues[1] == "A") "B" else "A"}"
            }
        val signatureFailure =
            assertThrows(ReceiptException::class.java) {
                ReceiptVerifier(ReceiptTestKeys.trustedKeys)
                    .verify(
                        tamperedSignature,
                        ReceiptBinding(
                            "commit-A",
                            "profile-A",
                            EndpointRole.DONOR,
                            "session-A",
                            "nonce-A",
                        ),
                    )
            }
        assertEquals("RECEIPT_SIGNATURE_INVALID", signatureFailure.message)
    }

    @Test
    fun only_sentinel_derived_capability_can_be_signed() {
        val signer = ReceiptTestKeys.signer
        val encoded = issue("nonce-capability", signer)
        val verified =
            ReceiptVerifier(ReceiptTestKeys.trustedKeys)
                .verify(
                    encoded,
                    ReceiptBinding(
                        "commit-A",
                        "profile-A",
                        EndpointRole.DONOR,
                        "session-A",
                        "nonce-capability",
                    ),
                )
        assertEquals(2, verified.sampleCount)
    }

    @Test
    fun signs_three_samples_when_each_adjacent_interval_is_continuous() {
        val signer = ReceiptTestKeys.signer
        val service = ServiceIdentity("keystore2", "init", 42, 100, "/system/bin/keystore2", 0)
        val properties = mapOf("ro.build.fingerprint" to "build-A")
        val live =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A", MonotonicClock { 3_000 })
                .observe(SentinelSample("boot-A", 0, properties, emptySet(), 0), service)
                .observe(SentinelSample("boot-A", 1_500, properties, emptySet(), 1_500), service)
                .observe(SentinelSample("boot-A", 3_000, properties, emptySet(), 3_000), service)
                .assertLive(3_000)
        val encoded =
            EvidenceIssuer.sign(
                live,
                ReceiptBinding(
                    "commit-A",
                    "profile-A",
                    EndpointRole.DONOR,
                    "session-A",
                    "nonce-three",
                ),
                ReceiptMaterial(
                    EvidenceHash.sha256("trace"),
                    EvidenceHash.sha256("artifact"),
                    monotonicMillis = 3_000,
                ),
                signer,
            )

        assertEquals(
            3,
            ReceiptVerifier(ReceiptTestKeys.trustedKeys)
                .verify(
                    encoded,
                    ReceiptBinding(
                        "commit-A",
                        "profile-A",
                        EndpointRole.DONOR,
                        "session-A",
                        "nonce-three",
                    ),
                )
                .sampleCount,
        )
    }

    @Test
    fun atomic_store_leaves_old_or_new_never_partial_and_rejects_paths_modes_and_symlinks() {
        val root = Files.createTempDirectory("rka-receipt-")
        try {
            val signer = ReceiptTestKeys.signer
            val store = AtomicReceiptStore(root)
            val first = issue("nonce-1", signer)
            store.write("receipt", first)
            assertThrows(ReceiptException::class.java) {
                store.write("receipt", issue("nonce-2", signer), interruptBeforeRename = true)
            }
            assertTrue(Files.readString(root.resolve("receipt.receipt")).contains("nonce-1"))
            assertThrows(ReceiptException::class.java) { store.write("../escape", first) }
            Files.createSymbolicLink(root.resolve("link.receipt"), root.resolve("receipt.receipt"))
            assertThrows(ReceiptException::class.java) { store.read("link") }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun issue(nonce: String, signer: Ed25519ReceiptSigner): String {
        val service = ServiceIdentity("keystore2", "init", 42, 100, "/system/bin/keystore2", 0)
        val properties = mapOf("ro.build.fingerprint" to "build-A")
        val live =
            NoRebootSentinel("serial-A", EndpointRole.DONOR, "profile-A", MonotonicClock { 2_000 })
                .observe(SentinelSample("boot-A", 0, properties, emptySet(), 0), service)
                .observe(SentinelSample("boot-A", 2_000, properties, emptySet(), 2_000), service)
                .assertLive(2_000)
        return EvidenceIssuer.sign(
            live,
            ReceiptBinding("commit-A", "profile-A", EndpointRole.DONOR, "session-A", nonce),
            ReceiptMaterial(
                EvidenceHash.sha256("trace"),
                EvidenceHash.sha256("artifact"),
                monotonicMillis = 2_000,
            ),
            signer,
        )
    }

    private class RecordingRunner(private val result: CommandResult = CommandResult(0, "ok")) :
        LiteralCommandRunner {
        var calls = 0

        override fun run(argv: List<String>): CommandResult {
            calls += 1
            return result
        }
    }
}
