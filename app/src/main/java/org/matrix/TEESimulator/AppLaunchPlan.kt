package org.matrix.TEESimulator

enum class AppRuntimeRole {
    LOCAL,
    DONOR,
    CANDIDATE,
}

data class AppLaunchPlan(
    val role: AppRuntimeRole,
    val startsCandidateRuntime: Boolean,
    val startsDonorProvisioning: Boolean,
    val startsKeystoreInterception: Boolean,
) {
    companion object {
        fun parse(args: Array<String>): AppLaunchPlan =
            when (args.toList()) {
                emptyList<String>(),
                listOf("legacy") -> LOCAL
                listOf("--rka-role", "donor") -> DONOR
                listOf("--rka-role", "candidate") -> CANDIDATE
                else -> throw IllegalArgumentException("Invalid TEESimulator runtime arguments")
            }

        private val LOCAL =
            AppLaunchPlan(
                role = AppRuntimeRole.LOCAL,
                startsCandidateRuntime = false,
                startsDonorProvisioning = false,
                startsKeystoreInterception = true,
            )
        private val DONOR =
            AppLaunchPlan(
                role = AppRuntimeRole.DONOR,
                startsCandidateRuntime = false,
                startsDonorProvisioning = true,
                startsKeystoreInterception = false,
            )
        private val CANDIDATE =
            AppLaunchPlan(
                role = AppRuntimeRole.CANDIDATE,
                startsCandidateRuntime = true,
                startsDonorProvisioning = false,
                startsKeystoreInterception = true,
            )
    }
}
