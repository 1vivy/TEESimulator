package org.matrix.TEESimulator.rka.donor

import org.matrix.TEESimulator.rka.bridge.BridgeMessage

internal object DonorDispatchAdapter {
    fun dispatch(
        command: BridgeMessage.CandidateCommand,
        backend: DonorKeyMintBackend,
    ): BridgeMessage = DonorBridgeDispatcher.dispatch(command, backend)

    fun dispatch(
        command: BridgeMessage.CandidateCommand,
        backend: DonorKeyMintBackend,
        dispatcher: (BridgeMessage.CandidateCommand, DonorKeyMintBackend) -> BridgeMessage,
    ): BridgeMessage = dispatcher(command, backend)
}
