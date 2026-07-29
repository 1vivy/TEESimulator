package org.matrix.teesimulator.physicalharness

sealed class DonorServiceCommand {
    class Start(val profileId: String) : DonorServiceCommand() {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Start && profileId == other.profileId)

        override fun hashCode(): Int = profileId.hashCode()
    }

    data object Stop : DonorServiceCommand()

    data object Inert : DonorServiceCommand()

    companion object {
        fun parse(action: String?, profileId: String?): DonorServiceCommand =
            when (action) {
                DonorService.ACTION_START -> Start(validStartProfileId(profileId))
                DonorService.ACTION_STOP -> Stop
                else -> Inert
            }

        private fun validStartProfileId(profileId: String?): String {
            if (profileId == null) throw DonorServiceCommandException.InvalidStart()
            return try {
                DonorProfile.requireValidProfileId(profileId)
            } catch (_: DonorProfileException.InvalidProfileId) {
                throw DonorServiceCommandException.InvalidStart()
            }
        }
    }
}

sealed class DonorServiceCommandException(message: String) : RuntimeException(message) {
    class InvalidStart : DonorServiceCommandException("invalid donor start command")
}
