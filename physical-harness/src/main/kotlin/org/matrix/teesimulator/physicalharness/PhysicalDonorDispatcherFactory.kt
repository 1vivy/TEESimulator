package org.matrix.teesimulator.physicalharness

import java.time.Instant
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDonorDispatcher

fun interface DonorSessionDispatcherFactory {
    fun create(
        pair: PairIdentity,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        expectedCaller: WireCallerIdentity,
    ): WireDonorDispatcher
}

class PhysicalDonorDispatcherFactory(
    private val process: PhysicalDonorProcess,
    private val now: () -> Instant,
) : DonorSessionDispatcherFactory {
    override fun create(
        pair: PairIdentity,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        expectedCaller: WireCallerIdentity,
    ): WireDonorDispatcher =
        WireDonorDispatcher.create(pair, clientNonce, serverNonce, now) { sessionId ->
            process.newSessionBackend(pair, sessionId, expectedCaller)
        }
}
