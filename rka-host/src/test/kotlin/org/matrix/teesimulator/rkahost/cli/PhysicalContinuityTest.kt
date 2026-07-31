package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PhysicalContinuityTest {
    private val binding =
        PairBinding("a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64))

    @Test
    fun rejectsChangedBootIdAndFabricatedTraceHash() {
        val baseline =
            SentinelBaseline("sentinel", "nonce", binding, "donor-boot", "candidate-boot", 100, 100)
        val manifest =
            PhysicalReceipt.create(
                baseline,
                "other-boot",
                "candidate-boot",
                200,
                200,
                "a".repeat(40),
                "b".repeat(64),
                listOf(listOf("adb", "-s", "DONOR_A", "shell", "getprop")),
            )
        assertThrows(HostCliException::class.java) {
            PhysicalReceipt.verify(
                manifest,
                baseline,
                binding,
                "a".repeat(40),
                "b".repeat(64),
                "nonce",
            )
        }
        val changedHash =
            manifest.replace(
                Regex(""""command_trace_sha256":"[0-9a-f]{64}""""),
                """"command_trace_sha256":"${"f".repeat(64)}"""",
            )
        assertThrows(HostCliException::class.java) {
            PhysicalReceipt.verify(
                changedHash,
                baseline,
                binding,
                "a".repeat(40),
                "b".repeat(64),
                "nonce",
            )
        }
        val otherBinding = binding.copy(profileSha256 = "e".repeat(64))
        val error =
            assertThrows(HostCliException::class.java) {
                PhysicalReceipt.verify(
                    manifest.replace("other-boot", "donor-boot"),
                    baseline,
                    otherBinding,
                    "a".repeat(40),
                    "b".repeat(64),
                    "nonce",
                )
            }
        assertEquals("PAIR_BINDING_MISMATCH", error.message)
    }

    @Test
    fun baselineStoreRejectsSymlinkAndUsesPrivateMode() {
        val root = Files.createTempDirectory("baseline-store-")
        val target = Files.writeString(root.resolve("target"), "x")
        val path = root.resolve("baseline.json")
        path.toFile().delete()
        Files.createSymbolicLink(path, target)
        assertThrows(HostCliException::class.java) {
            BaselineStore.create(path, SentinelBaseline("s", "n", binding, "d", "c", 1, 1))
        }
        assertEquals("x", Files.readString(target))
    }

    @Test
    fun concurrentBaselineWritersHaveExactlyOneWinner() {
        val path = Files.createTempDirectory("baseline-race-").resolve("baseline.json")
        val baseline = SentinelBaseline("s", "n", binding, "d", "c", 1, 1)
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val results =
            List(2) {
                pool.submit<String> {
                    ready.countDown()
                    start.await()
                    try {
                        BaselineStore.create(path, baseline)
                        "CREATED"
                    } catch (failure: HostCliException) {
                        failure.message ?: "UNKNOWN"
                    }
                }
            }
        ready.await(5, TimeUnit.SECONDS)
        start.countDown()
        val values = results.map { it.get(5, TimeUnit.SECONDS) }
        pool.shutdownNow()
        assertEquals(1, values.count { it == "CREATED" })
        assertEquals(1, values.count { it == "BASELINE_ALREADY_EXISTS" })
    }
}
