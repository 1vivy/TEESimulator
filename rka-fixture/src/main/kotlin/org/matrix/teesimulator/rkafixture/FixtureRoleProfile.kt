package org.matrix.teesimulator.rkafixture

enum class FixtureRole {
    DONOR,
    TARGET,
}

enum class FixtureRoleProfileErrorCode {
    MISSING_ROLE,
    ROLE_CONFLICT,
    UNKNOWN_ROLE,
}

sealed class FixtureRoleProfileError(val code: FixtureRoleProfileErrorCode) :
    IllegalArgumentException(code.name) {
    data object MissingRole : FixtureRoleProfileError(FixtureRoleProfileErrorCode.MISSING_ROLE)

    data object RoleConflict : FixtureRoleProfileError(FixtureRoleProfileErrorCode.ROLE_CONFLICT)

    data object UnknownRole : FixtureRoleProfileError(FixtureRoleProfileErrorCode.UNKNOWN_ROLE)
}

object FixtureRoleProfile {
    fun parse(activeRoles: Set<String>): FixtureRole {
        if (activeRoles.containsAll(MUTUALLY_EXCLUSIVE_ROLE_NAMES)) {
            throw FixtureRoleProfileError.RoleConflict
        }
        return when (activeRoles.size) {
            0 -> throw FixtureRoleProfileError.MissingRole
            1 -> parseRole(activeRoles.single())
            else -> throw FixtureRoleProfileError.UnknownRole
        }
    }

    fun activate(activeRoles: Set<String>, onValidatedRole: (FixtureRole) -> Unit): FixtureRole {
        val role = parse(activeRoles)
        onValidatedRole(role)
        return role
    }

    private fun parseRole(roleName: String): FixtureRole =
        when (roleName) {
            "DONOR" -> FixtureRole.DONOR
            "TARGET" -> FixtureRole.TARGET
            else -> throw FixtureRoleProfileError.UnknownRole
        }

    private val MUTUALLY_EXCLUSIVE_ROLE_NAMES =
        setOf(FixtureRole.DONOR.name, FixtureRole.TARGET.name)
}
