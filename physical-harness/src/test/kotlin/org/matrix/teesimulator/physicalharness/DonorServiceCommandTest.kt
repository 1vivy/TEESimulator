package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class DonorServiceCommandTest {
    @Test
    fun nullAndUnknownActionsAreInertRegardlessOfProfileInput() {
        assertEquals(DonorServiceCommand.Inert, DonorServiceCommand.parse(null, null))
        assertEquals(
            DonorServiceCommand.Inert,
            DonorServiceCommand.parse("unknown.action", "approved.profile"),
        )
    }

    @Test
    fun startAcceptsOnlyABoundedValidProfileIdentifier() {
        assertEquals(
            "approved.profile",
            assertIs<DonorServiceCommand.Start>(
                    DonorServiceCommand.parse(DonorService.ACTION_START, "approved.profile")
                )
                .profileId,
        )
        listOf(null, "", "x".repeat(65), "../profile", "with space", "é").forEach { profileId ->
            assertFailsWith<DonorServiceCommandException.InvalidStart> {
                DonorServiceCommand.parse(DonorService.ACTION_START, profileId)
            }
        }
    }

    @Test
    fun stopCarriesNoProfileMaterial() {
        assertEquals(
            DonorServiceCommand.Stop,
            DonorServiceCommand.parse(DonorService.ACTION_STOP, "ignored.profile"),
        )
    }
}
