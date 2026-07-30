package org.matrix.teesimulator.rkahost

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.isDirectory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeIsolationTest {
    @Test
    fun productionSourcesExcludeRetiredProbeOwnership() {
        val root = Path.of("").toAbsolutePath().parent
        val productionSources =
            listOf(
                root.resolve("module"),
                root.resolve("app/src/main"),
                root.resolve("rka-host/src/main"),
                root.resolve("rka-fixture/src/main"),
            )

        val forbidden =
            listOf(
                "CandidateCompanionService",
                "CandidateRootProbe",
                "CANDIDATE_COMPANION",
                "--reboot",
            )

        productionSources.forEach { source ->
            assertTrue("missing production source: $source", source.isDirectory())
            Files.walk(source).use { paths ->
                paths.filter(Files::isRegularFile).forEach { path ->
                    val contents = Files.readAllBytes(path).decodeToString()
                    forbidden.forEach { token ->
                        assertFalse(
                            "retired probe ownership token $token found in $path",
                            contents.contains(token),
                        )
                    }
                }
            }
        }
    }
}
