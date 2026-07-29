package org.matrix.teesimulator.physicalharness

import java.net.Socket
import kotlin.test.Test

class SocketShutdownTraversalTest {
    @Test
    fun toleratesRemovalBetweenSizeAndIteration() {
        val concurrentlyEmptiedSockets =
            object : AbstractCollection<Socket>() {
                override val size = 1

                override fun iterator(): Iterator<Socket> = emptyList<Socket>().iterator()
            }

        closeSockets(concurrentlyEmptiedSockets)
    }
}
