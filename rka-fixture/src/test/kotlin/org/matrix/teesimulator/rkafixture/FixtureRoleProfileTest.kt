package org.matrix.teesimulator.rkafixture

import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FixtureRoleProfileTest {
    @Test
    fun parsesTheDonorRole() {
        // Given: a donor-only profile. When: it is parsed. Then: it selects DONOR.
        val role = FixtureRoleProfile.parse(setOf("DONOR"))

        assertEquals(FixtureRole.DONOR, role)
    }

    @Test
    fun parsesTheTargetRole() {
        // Given: a target-only profile. When: it is parsed. Then: it selects TARGET.
        val role = FixtureRoleProfile.parse(setOf("TARGET"))

        assertEquals(FixtureRole.TARGET, role)
    }

    @Test
    fun rejectsAMissingRole() {
        // Given: an empty profile. When: it is parsed. Then: it returns MISSING_ROLE.
        val failure =
            assertFailsWith<FixtureRoleProfileError.MissingRole> {
                FixtureRoleProfile.parse(emptySet())
            }

        assertEquals("MISSING_ROLE", failure.message)
        assertEquals(FixtureRoleProfileErrorCode.MISSING_ROLE, failure.code)
    }

    @Test
    fun rejectsAnUnknownRole() {
        // Given: an unknown role profile. When: it is parsed. Then: it returns UNKNOWN_ROLE.
        val failure =
            assertFailsWith<FixtureRoleProfileError.UnknownRole> {
                FixtureRoleProfile.parse(setOf("OBSERVER"))
            }

        assertEquals("UNKNOWN_ROLE", failure.message)
        assertEquals(FixtureRoleProfileErrorCode.UNKNOWN_ROLE, failure.code)
    }

    @Test
    fun rejectsSimultaneousRolesBeforeTheActivationProbeRuns() {
        // Given: a dual-role profile and activation probe. When: startup validates it. Then: no
        // probe runs.
        val activationCalls = AtomicInteger()

        val failure =
            assertFailsWith<FixtureRoleProfileError.RoleConflict> {
                FixtureRoleProfile.activate(setOf("DONOR", "TARGET")) {
                    activationCalls.incrementAndGet()
                }
            }

        assertEquals("ROLE_CONFLICT", failure.message)
        assertEquals(FixtureRoleProfileErrorCode.ROLE_CONFLICT, failure.code)
        assertEquals(0, activationCalls.get())
    }

    @Test
    fun rejectsMissingRoleBeforeTheActivationProbeRuns() {
        // Given: a missing-role profile and activation probe. When: startup validates it. Then: no
        // probe runs.
        val activationCalls = AtomicInteger()

        val failure =
            assertFailsWith<FixtureRoleProfileError.MissingRole> {
                FixtureRoleProfile.activate(emptySet()) { activationCalls.incrementAndGet() }
            }

        assertEquals(FixtureRoleProfileErrorCode.MISSING_ROLE, failure.code)
        assertEquals(0, activationCalls.get())
    }

    @Test
    fun rejectsUnknownRoleBeforeTheActivationProbeRuns() {
        // Given: an unknown-role profile and activation probe. When: startup validates it. Then: no
        // probe runs.
        val activationCalls = AtomicInteger()

        val failure =
            assertFailsWith<FixtureRoleProfileError.UnknownRole> {
                FixtureRoleProfile.activate(setOf("OBSERVER")) { activationCalls.incrementAndGet() }
            }

        assertEquals(FixtureRoleProfileErrorCode.UNKNOWN_ROLE, failure.code)
        assertEquals(0, activationCalls.get())
    }

    @Test
    fun rejectsDonorAndTargetAsAConflictEvenWithAnUnknownRole() {
        // Given: both active roles plus malformed input. When: startup validates it. Then: the
        // conflict wins and no probe runs.
        val activationCalls = AtomicInteger()

        val failure =
            assertFailsWith<FixtureRoleProfileError.RoleConflict> {
                FixtureRoleProfile.activate(setOf("DONOR", "TARGET", "OBSERVER")) {
                    activationCalls.incrementAndGet()
                }
            }

        assertEquals(FixtureRoleProfileErrorCode.ROLE_CONFLICT, failure.code)
        assertEquals(0, activationCalls.get())
    }
}
