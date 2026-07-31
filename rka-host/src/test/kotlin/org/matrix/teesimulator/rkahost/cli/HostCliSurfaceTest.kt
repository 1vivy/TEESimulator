package org.matrix.teesimulator.rkahost.cli

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HostCliSurfaceTest {
    @Test
    fun helpListsOnlyFixedCommands() {
        val bytes = ByteArrayOutputStream()
        val previous = System.out
        try {
            System.setOut(PrintStream(bytes))
            HostCli.run(arrayOf("--help"), Files.createTempDirectory("host-help-"))
        } finally {
            System.setOut(previous)
        }
        val help = bytes.toString()
        assertTrue(help.contains("device-pair bind"))
        assertTrue(help.contains("verify-physical"))
        assertFalse(help.contains("shell"))
        assertFalse(help.contains("exec"))
    }

    @Test
    fun physicalCommandRejectsPairPathArgument() {
        val exit =
            HostCli.run(
                arrayOf("sentinel", "start", "--pair", "/tmp/pair"),
                Files.createTempDirectory("host-physical-"),
            )
        assertTrue(exit != 0)
    }
}
