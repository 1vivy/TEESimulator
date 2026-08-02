package org.matrix.TEESimulator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLaunchPlanTest {
    @Test
    fun localAndLegacyLaunchOnlyLegacyKeystoreRuntime() {
        listOf(emptyArray(), arrayOf("legacy")).forEach { args ->
            val plan = AppLaunchPlan.parse(args)

            assertEquals(AppRuntimeRole.LOCAL, plan.role)
            assertTrue(plan.startsKeystoreInterception)
            assertFalse(plan.startsCandidateRuntime)
            assertFalse(plan.startsDonorProvisioning)
        }
    }

    @Test
    fun donorLaunchStartsOnlyDonorProvisioning() {
        val plan = AppLaunchPlan.parse(arrayOf("--rka-role", "donor"))

        assertEquals(AppRuntimeRole.DONOR, plan.role)
        assertTrue(plan.startsDonorProvisioning)
        assertFalse(plan.startsCandidateRuntime)
        assertFalse(plan.startsKeystoreInterception)
    }

    @Test
    fun candidateLaunchStartsCandidateRuntimeAndKeystoreInterception() {
        val plan = AppLaunchPlan.parse(arrayOf("--rka-role", "candidate"))

        assertEquals(AppRuntimeRole.CANDIDATE, plan.role)
        assertTrue(plan.startsCandidateRuntime)
        assertTrue(plan.startsKeystoreInterception)
        assertFalse(plan.startsDonorProvisioning)
    }

    @Test
    fun nonCanonicalOrAdditionalArgumentsFailClosed() {
        listOf(
                arrayOf("--rka-role"),
                arrayOf("--rka-role", "DONOR"),
                arrayOf("--rka-role", "candidate", "--rka-candidate"),
                arrayOf("--rka-role", "local"),
                arrayOf("unexpected"),
            )
            .forEach { args ->
                assertThrows(IllegalArgumentException::class.java) { AppLaunchPlan.parse(args) }
            }
    }
}
