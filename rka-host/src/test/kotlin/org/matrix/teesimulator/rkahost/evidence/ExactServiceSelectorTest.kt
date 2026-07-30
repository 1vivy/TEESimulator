package org.matrix.teesimulator.rkahost.evidence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ExactServiceSelectorTest {
    private val expected = ServiceExpectation("keystore2", "init", "/system/bin/keystore2")
    private val match = ServiceIdentity("keystore2", "init", 11, 22, "/system/bin/keystore2", 0)

    @Test
    fun rejects_multiple_matches() {
        // Given: two exact-looking process rows.
        val selector = ExactServiceSelector(expected)

        // When/Then: ambiguity is inert.
        assertEquals(
            SelectorFailure.MULTIPLE_MATCHES,
            assertThrows(SelectorException::class.java) {
                    selector.select(listOf(match, match.copy(pid = 12)))
                }
                .failure,
        )
    }

    @Test
    fun rejects_zero_forged_and_changed_start_metadata() {
        // Given: an exact selector.
        val selector = ExactServiceSelector(expected)

        // When/Then: no broad PID discovery or forged metadata is accepted.
        assertEquals(
            SelectorFailure.ZERO_MATCHES,
            assertThrows(SelectorException::class.java) { selector.select(emptyList()) }.failure,
        )
        assertEquals(
            SelectorFailure.FORGED_METADATA,
            assertThrows(SelectorException::class.java) {
                    selector.select(listOf(match.copy(initOwner = "shell")))
                }
                .failure,
        )
        assertEquals(
            SelectorFailure.START_TIME_AMBIGUITY,
            assertThrows(SelectorException::class.java) {
                    selector.requireStable(match, match.copy(startTimeTicks = 23))
                }
                .failure,
        )
    }

    @Test
    fun accepts_one_exact_match() {
        // Given/When: one exact init-owned service process.
        val selected = ExactServiceSelector(expected).select(listOf(match))

        // Then: its exact identity is returned.
        assertEquals(match, selected)
    }
}
