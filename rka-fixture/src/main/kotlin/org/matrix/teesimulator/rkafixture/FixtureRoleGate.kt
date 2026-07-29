package org.matrix.teesimulator.rkafixture

import org.matrix.teesimulator.physicalharness.DonorStartupGate

class FixtureRoleActivation internal constructor(val role: FixtureRole)

class FixtureRoleGate(private val onValidatedRole: (FixtureRole) -> Unit = {}) {
    fun <T> activate(activeRoles: Set<String>, operation: (FixtureRoleActivation) -> T): T {
        var result: ActivatedResult<T>? = null
        FixtureRoleProfile.activate(activeRoles) { role ->
            onValidatedRole(role)
            result = ActivatedResult(operation(FixtureRoleActivation(role)))
        }
        return checkNotNull(result).value
    }

    private class ActivatedResult<T>(val value: T)
}

sealed class FixtureDonorStartupError(message: String) : SecurityException(message) {
    data object WrongRole : FixtureDonorStartupError("donor startup requires DONOR role")
}

class FixtureDonorStartupGate(private val roleGate: FixtureRoleGate) : DonorStartupGate {
    override fun runWhenAuthorized(activeRoles: Set<String>, action: () -> Unit) {
        roleGate.activate(activeRoles) { activation ->
            if (activation.role != FixtureRole.DONOR) throw FixtureDonorStartupError.WrongRole
            action()
        }
    }
}
