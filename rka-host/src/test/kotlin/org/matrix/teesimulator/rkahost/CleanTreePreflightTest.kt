package org.matrix.teesimulator.rkahost

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CleanTreePreflightTest {
    @Test
    fun cleanRepositoryPasses() {
        inRepository { repository -> assertClean(runGate(repository)) }
    }

    @Test
    fun trackedModificationIsReported() {
        inRepository { repository ->
            repository.resolve("tracked.txt").writeText("changed\n")

            assertDirty(runGate(repository), "tracked.txt")
        }
    }

    @Test
    fun stagedFileIsReported() {
        inRepository { repository ->
            repository.resolve("staged.txt").writeText("staged\n")
            git(repository, "add", "staged.txt")

            assertDirty(runGate(repository), "staged.txt")
        }
    }

    @Test
    fun untrackedFileIsReported() {
        inRepository { repository ->
            repository.resolve("untracked.txt").writeText("untracked\n")

            assertDirty(runGate(repository), "untracked.txt")
        }
    }

    @Test
    fun ignoredFileIsReported() {
        inRepository { repository ->
            repository.resolve(".gitignore").writeText("ignored.txt\n")
            git(repository, "add", ".gitignore")
            git(repository, "commit", "-m", "ignore fixture")
            repository.resolve("ignored.txt").writeText("ignored\n")

            assertDirty(runGate(repository), "ignored.txt")
        }
    }

    @Test
    fun harnessOnlyFilesRemainClean() {
        inRepository { repository ->
            repository.resolve(".gitignore").writeText(".omo/ignored\n.codegraph/ignored\n")
            git(repository, "add", ".gitignore")
            git(repository, "commit", "-m", "ignore harness fixtures")
            repository.resolve(".omo").createDirectories()
            repository.resolve(".codegraph").createDirectories()
            repository.resolve(".omo/untracked").writeText("harness\n")
            repository.resolve(".omo/ignored").writeText("harness\n")
            repository.resolve(".codegraph/untracked").writeText("harness\n")
            repository.resolve(".codegraph/ignored").writeText("harness\n")

            assertClean(runGate(repository))
        }
    }

    private fun inRepository(assertions: (Path) -> Unit) {
        val repository = Files.createTempDirectory("rka-clean-tree-")
        try {
            git(repository, "init", "--quiet")
            git(repository, "config", "user.name", "RKA Test")
            git(repository, "config", "user.email", "rka-test@example.invalid")
            git(repository, "config", "commit.gpgsign", "false")
            repository.resolve("tracked.txt").writeText("base\n")
            git(repository, "add", "tracked.txt")
            git(repository, "commit", "--quiet", "-m", "base")
            assertions(repository)
        } finally {
            repository.toFile().deleteRecursively()
        }
    }

    private fun runGate(repository: Path): ProcessResult {
        val script =
            """
            set -o pipefail
            {
              git diff --name-only -z -- . ':(exclude).omo' ':(exclude).omo/**' ':(exclude).codegraph' ':(exclude).codegraph/**'
              git diff --cached --name-only -z -- . ':(exclude).omo' ':(exclude).omo/**' ':(exclude).codegraph' ':(exclude).codegraph/**'
              git ls-files -z --others --exclude-standard
              git ls-files -z --others --ignored --exclude-standard
            } | python3 -c 'import sys; paths=sorted({p.decode("utf-8","surrogateescape") for p in sys.stdin.buffer.read().split(b"\0") if p and not (p==b".omo" or p.startswith(b".omo/") or p==b".codegraph" or p.startswith(b".codegraph/"))}); print("CLEAN_OUTSIDE_HARNESS" if not paths else "DIRTY_OUTSIDE_HARNESS:\n"+"\n".join(paths)); raise SystemExit(bool(paths))'
            """
                .trimIndent()
        val process =
            ProcessBuilder("bash", "-c", script)
                .directory(repository.toFile())
                .redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }.trimEnd()
        return ProcessResult(process.waitFor(), output)
    }

    private fun git(repository: Path, vararg arguments: String) {
        val process =
            ProcessBuilder(listOf("git") + arguments)
                .directory(repository.toFile())
                .redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        assertEquals(output, 0, process.waitFor())
    }

    private fun assertClean(result: ProcessResult) {
        assertEquals(result.output, 0, result.exitCode)
        assertEquals("CLEAN_OUTSIDE_HARNESS", result.output)
    }

    private fun assertDirty(result: ProcessResult, expectedPath: String) {
        assertNotEquals(result.output, 0, result.exitCode)
        assertTrue(result.output.startsWith("DIRTY_OUTSIDE_HARNESS:\n"))
        assertTrue(result.output.lineSequence().drop(1).contains(expectedPath))
    }

    private data class ProcessResult(val exitCode: Int, val output: String)
}
