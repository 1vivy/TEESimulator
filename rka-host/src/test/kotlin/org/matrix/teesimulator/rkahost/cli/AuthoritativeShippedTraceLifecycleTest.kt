package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthoritativeShippedTraceLifecycleTest {
    @Test
    fun installedDistributionStandardWrapperAndRepositoryDeployProduceExactCompleteTrace() {
        val project = Path.of(System.getProperty("user.dir")).parent
        val installed = project.resolve("rka-host/build/install/rka-host/bin/rka-host")
        assertTrue(Files.isExecutable(installed))
        Fixture().use { fixture ->
            val result = fixture.runAuthoritativeTraceLifecycle(installed)
            val events =
                result.trace.canonical
                    .toString(Charsets.UTF_8)
                    .lineSequence()
                    .drop(1)
                    .filter(String::isNotEmpty)
                    .map { line ->
                        val values = line.split('|')
                        "${values[0]}:${values[2]}:${values[5]}:${values[6]}"
                    }
                    .toList()
            val expectedCommands =
                listOf(
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "PUSH",
                    "SHELL_SU",
                    "PUSH",
                    "SHELL_SU",
                    "PUSH",
                    "SHELL_SU",
                    "PUSH",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_GETPROP",
                    "SHELL_SU",
                    "SHELL_SU",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_CAT",
                    "SHELL_SU",
                    "SHELL_SU",
                )
            val expectedEvents =
                expectedCommands.flatMapIndexed { index, operation ->
                    val start = index * 2 + 1
                    val exit = start + 1
                    val exitStatus =
                        if (operation == "SHELL_GETPROP") "EXIT_NONZERO:19" else "EXIT_OK:0"
                    listOf("$start:$operation:START:-", "$exit:$operation:$exitStatus")
                }
            val normalizedEvents =
                events.map { event ->
                    val values = event.split(':', limit = 3)
                    if (values[1].startsWith("PUSH_")) "${values[0]}:PUSH:${values[2]}" else event
                }

            assertEquals(result.start.stderr, 0, result.start.exitCode)
            assertEquals(result.deploy.stderr, 0, result.deploy.exitCode)
            assertEquals(19, result.controlledNonzero.exitCode)
            assertTrue(result.controlledNonzero.stdout.contains("MISLEADING_SUCCESS_STDOUT"))
            assertTrue(
                result.controlledNonzero.stderr.contains("controlled failure remains visible")
            )
            assertEquals(result.stop.stderr, 0, result.stop.exitCode)
            assertEquals(result.receipt.stderr, 0, result.receipt.exitCode)
            assertEquals(result.verify.stderr, 0, result.verify.exitCode)
            assertEquals(result.cleanup.stderr, 0, result.cleanup.exitCode)
            assertEquals(result.trace.binding.eventCount, events.size)
            assertEquals(expectedEvents, normalizedEvents)
            assertTrue(events.any { ":EXIT_NONZERO:19" in it })
            assertFalse(result.trace.canonical.toString(Charsets.UTF_8).contains("DONOR_A"))
            assertFalse(result.trace.canonical.toString(Charsets.UTF_8).contains("CANDIDATE_B"))
            assertFalse(result.canonicalReceipt.contains("DONOR_A"))
            assertFalse(result.canonicalReceipt.contains("CANDIDATE_B"))
            assertTrue(
                result.canonicalReceipt.contains("\"command_trace_event_count\":${events.size}")
            )
            println("AUTHORITATIVE_EVENT_SET=${events.joinToString(",")}")
            println(
                "AUTHORITATIVE_TRACE_COUNT=${events.size} HEAD=${result.trace.binding.headSha256} " +
                    "CONTROLLED_EXIT=19 RECEIPT_VERIFIED=true CLEANUP=true"
            )
        }
    }
}
