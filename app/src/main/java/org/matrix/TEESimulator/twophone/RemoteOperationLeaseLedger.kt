package org.matrix.TEESimulator.twophone

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

internal class RemoteOperationLeaseLedger<T>(private val create: () -> T) {
    private val random = SecureRandom()
    private val entries = ConcurrentHashMap<Long, T>()

    fun allocate(): Long {
        while (true) {
            val lease = random.nextLong() and Long.MAX_VALUE
            if (lease != 0L && entries.putIfAbsent(lease, create()) == null) return lease
        }
    }

    fun leaseCount(): Long {
        allocate()
        return entries.size.toLong()
    }
}
