package org.matrix.TEESimulator.rka.donor

import org.matrix.TEESimulator.rka.bridge.BridgeMessage
import org.matrix.TEESimulator.rka.candidate.IdentityHash

internal object DonorDispatchAdapter {
    fun dispatch(
        command: BridgeMessage.CandidateCommand,
        backend: DonorKeyMintBackend,
        candidate: IdentityHash,
    ): BridgeMessage = DonorBridgeDispatcher.dispatch(command, backend, candidate)
}
