package org.matrix.teesimulator.physicalharness

fun interface DonorStartupGate {
    fun runWhenAuthorized(activeRoles: Set<String>, action: () -> Unit)
}

sealed class DonorStartupGateException(message: String) : SecurityException(message) {
    data object MissingActivation :
        DonorStartupGateException("donor startup role activation missing")
}

object DonorStartupGates {
    private val refusingGate = DonorStartupGate { _, _ ->
        throw DonorStartupGateException.MissingActivation
    }

    @Volatile private var activeGate: DonorStartupGate = refusingGate

    fun install(gate: DonorStartupGate) {
        activeGate = gate
    }

    fun runWhenAuthorized(activeRoles: Set<String>, action: () -> Unit) {
        activeGate.runWhenAuthorized(activeRoles, action)
    }
}
