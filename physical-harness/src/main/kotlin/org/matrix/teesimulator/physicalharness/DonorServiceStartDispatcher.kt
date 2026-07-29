package org.matrix.teesimulator.physicalharness

class DonorServiceStartDispatcher(private val controller: DonorServiceController) {
    fun dispatch(action: String?, profileId: String?, startId: Int): Boolean =
        when (action) {
            DonorService.ACTION_START -> controller.handleExplicitStart(profileId, startId)
            DonorService.ACTION_STOP -> controller.handle(DonorServiceCommand.Stop, startId)
            else -> controller.handle(DonorServiceCommand.Inert, startId)
        }
}
