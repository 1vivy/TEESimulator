package org.matrix.TEESimulator.rka.journal

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RkpJournalBoundaryTest {
    @Test
    fun productionDtosRejectPrivateMaterialFieldsAndMutation() {
        val sources =
            listOf(
                    "RkpJournal.kt",
                    "RkpJournalCodec.kt",
                    "FileRkpJournalStore.kt",
                    "DurableIrpcKeyBatchGenerator.kt",
                )
                .joinToString("\n") { name ->
                    String(
                        Files.readAllBytes(
                            Path.of("src/main/java/org/matrix/TEESimulator/rka/journal", name)
                        ),
                        StandardCharsets.UTF_8,
                    )
                }

        assertTrue(publicBoundaryIsSafe(sources))
        val mutated = Files.createTempFile("rkp-boundary-", ".kt")
        try {
            Files.write(
                mutated,
                (sources + "\ndata class Mutated(val keyBlob: ByteArray, val alias: String)")
                    .toByteArray(StandardCharsets.UTF_8),
            )
            assertFalse(
                publicBoundaryIsSafe(String(Files.readAllBytes(mutated), StandardCharsets.UTF_8))
            )
        } finally {
            Files.deleteIfExists(mutated)
        }
    }

    private fun publicBoundaryIsSafe(source: String): Boolean =
        listOf("keyBlob", "privateBytes", "IBinder", " alias:").none(source::contains)
}
