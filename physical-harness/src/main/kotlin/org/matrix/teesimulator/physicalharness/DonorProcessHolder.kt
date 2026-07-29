package org.matrix.teesimulator.physicalharness

fun interface PhysicalDonorProcessFactory<P : Any> {
    fun create(): P
}

class DonorProcessHolder<P : Any> {
    private val monitor = Any()
    private var process: P? = null

    fun getOrCreate(factory: PhysicalDonorProcessFactory<P>): P =
        synchronized(monitor) {
            process?.let {
                return@synchronized it
            }
            factory.create().also { process = it }
        }
}

object ProductionDonorProcessHolder {
    val instance = DonorProcessHolder<PhysicalDonorProcess>()
}
