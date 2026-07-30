package org.matrix.teesimulator.rkahost

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Test

class CallerOnlyRuntimeBoundaryTest {
    @Test
    fun rebootArgumentsAreRejectedBeforeAnyLegacyRunnerOperation() {
        val operationLog = Files.createTempFile("rka-caller-only-operation", ".log")
        val fakeAdb = Files.createTempFile("rka-caller-only-adb", ".sh")
        try {
            Files.writeString(
                fakeAdb,
                "#!/bin/sh\nprintf 'invoked\\n' >> \"${operationLog.toAbsolutePath()}\"\nexit 1\n",
            )
            check(fakeAdb.toFile().setExecutable(true))

            val run =
                CandidateIdentityGateCli::class.java.declaredMethods.single { method ->
                    method.name.startsWith("run") &&
                        method.parameterTypes.firstOrNull() == Array<String>::class.java
                }
            val result =
                when (run.parameterCount) {
                    1 -> run.invoke(CandidateIdentityGateCli, *arrayOf(rebootArguments)) as Int
                    2 ->
                        run.invoke(
                            CandidateIdentityGateCli,
                            *arrayOf(rebootArguments, legacyRunnerFactory(fakeAdb)),
                        ) as Int
                    else -> error("UNEXPECTED_CLI_RUN_SHAPE")
                }

            assertEquals(1, result)
            assertEquals(0, Files.readAllLines(operationLog).size)
        } finally {
            Files.deleteIfExists(fakeAdb)
            Files.deleteIfExists(operationLog)
        }
    }

    private fun legacyRunnerFactory(fakeAdb: Path): (Any?) -> Any = { candidate ->
        val runnerClass = Class.forName("org.matrix.teesimulator.rkahost.CandidateAdb")
        runnerClass.declaredConstructors
            .single { constructor -> constructor.parameterCount == 2 }
            .newInstance(candidate, fakeAdb.toString())
    }

    private companion object {
        val rebootArguments =
            arrayOf(
                "candidate-identity-gate",
                "--candidate",
                "127.0.0.1:5555",
                "--prefer",
                "ROOT_DAEMON",
                "--allow-fallback",
                "CANDIDATE_COMPANION",
                "--reboot",
            )
    }
}
