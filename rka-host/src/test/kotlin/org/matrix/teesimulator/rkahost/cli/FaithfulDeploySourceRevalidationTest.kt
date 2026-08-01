package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class FaithfulDeploySourceRevalidationTest {
    private val repository = Path.of(System.getProperty("user.dir")).parent
    private val installed = repository.resolve("rka-host/build/install/rka-host/bin/rka-host")

    @Test
    fun unmodifiedFaithfulStandardDeployRunsTheAuthoritativeInstalledLifecycle() {
        withFaithfulSource { source ->
            assertEquals(
                Files.readAllBytes(repository.resolve("scripts/rka-deploy.sh")).toList(),
                Files.readAllBytes(source.resolve("scripts/rka-deploy.sh")).toList(),
            )
            Fixture().use { fixture ->
                val result = fixture.runAuthoritativeTraceLifecycle(installed, source)

                assertEquals(result.deploy.stderr, 0, result.deploy.exitCode)
                assertEquals(86, result.trace.binding.eventCount)
                assertEquals("CLEAN", result.trace.verdict)
                assertEquals(result.receipt.stderr, 0, result.receipt.exitCode)
                assertEquals(result.cleanup.stderr, 0, result.cleanup.exitCode)
                println(
                    "FAITHFUL_UNMODIFIED_DEPLOY=true TRACE_EVENTS=${result.trace.binding.eventCount} " +
                        "RECEIPT_CLEAN=true"
                )
            }
        }
    }

    @Test
    fun faithfulStandardDeployMutationAfterBindingIsRejectedBeforeInjectedAdbAndReceipt() {
        withFaithfulSource { source ->
            Fixture().use { fixture ->
                val result = runMutation(fixture, source, disablePostBindRevalidation = false)

                assertEquals(result.originalDeploySha256, result.boundDeploySha256)
                assertEquals(
                    Hashes.sha256(
                        source
                            .resolve("scripts/rka-deploy.sh")
                            .toRealPath()
                            .toString()
                            .toByteArray()
                    ),
                    result.boundDeployPathSha256,
                )
                assertFaithfulMutationRejected(result)
                println(
                    "FAITHFUL_MUTATION_REJECTED=true MARKER=false TRACE=${result.traceVerdict} " +
                        "LIFECYCLE=${result.lifecycle} RECEIPT_NOT_SEALED=true"
                )
            }
        }
    }

    @Test
    fun disablingPostBindSourceRevalidationMakesTheFaithfulAssertionRed() {
        withFaithfulSource { source ->
            Fixture().use { fixture ->
                val result = runMutation(fixture, source, disablePostBindRevalidation = true)

                val killedMutant =
                    assertThrows(AssertionError::class.java) {
                        assertFaithfulMutationRejected(result)
                    }
                assertTrue(killedMutant.message.orEmpty().contains("injected ADB must not execute"))
                assertTrue(result.markerPresent)
                println("POST_BIND_REVALIDATION_MUTANT_KILLED=true MARKER=true")
            }
        }
    }

    private fun runMutation(
        fixture: Fixture,
        source: Path,
        disablePostBindRevalidation: Boolean,
    ): FaithfulDeployMutationResult {
        val marker = source.resolve("injected-adb-ran")
        val injectedAdb = source.resolve("injected-adb")
        Files.writeString(injectedAdb, "#!/bin/sh\nprintf injected > '$marker'\n")
        Files.setPosixFilePermissions(injectedAdb, PosixFilePermissions.fromString("rwx------"))
        return fixture.runFaithfulPostBindMutation(
            installed,
            source,
            injectedAdb,
            marker,
            disablePostBindRevalidation,
        )
    }

    private fun assertFaithfulMutationRejected(result: FaithfulDeployMutationResult) {
        assertFalse("injected ADB must not execute", result.markerPresent)
        assertEquals(2, result.mutatedDeploy.exitCode)
        assertTrue(result.mutatedDeploy.stderr.contains("RESULT=DEPLOY_SOURCE_MISMATCH"))
        assertEquals("CLEAN", result.traceVerdict)
        assertEquals(TraceLifecycleState.ACTIVE, result.lifecycle)
        assertEquals(2, result.receipt.exitCode)
        assertTrue(
            result.receipt.stderr,
            result.receipt.stderr.contains("RESULT=COMMAND_TRACE_NOT_SEALED"),
        )
    }

    private fun withFaithfulSource(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("faithful-standard-deploy-")
        val source = root.resolve("source")
        try {
            val clone =
                ProcessBuilder(
                        "git",
                        "clone",
                        "--shared",
                        "--no-hardlinks",
                        "--quiet",
                        repository.toString(),
                        source.toString(),
                    )
                    .start()
            assertEquals(clone.errorStream.bufferedReader().readText(), 0, clone.waitFor())
            assertEquals(
                ProcessBuilder("git", "rev-parse", "HEAD")
                    .directory(repository.toFile())
                    .start()
                    .let { process ->
                        process.inputStream.bufferedReader().readText().trim().also {
                            assertEquals(0, process.waitFor())
                        }
                    },
                ProcessBuilder("git", "rev-parse", "HEAD").directory(source.toFile()).start().let {
                    process ->
                    process.inputStream.bufferedReader().readText().trim().also {
                        assertEquals(0, process.waitFor())
                    }
                },
            )
            block(source)
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
