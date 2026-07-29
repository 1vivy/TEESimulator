package org.matrix.teesimulator.physicalharness

import android.content.Context

fun interface DonorRuntimeControlFactory {
    fun create(): DonorRuntimeControl
}

class DonorRuntimeHolder {
    private val monitor = Any()
    private var runtime: DonorRuntimeControl? = null

    fun getOrCreate(factory: DonorRuntimeControlFactory): DonorRuntimeControl =
        synchronized(monitor) {
            runtime?.let {
                return@synchronized it
            }
            factory.create().also { runtime = it }
        }
}

object ProductionDonorRuntimeHolder {
    private val holder = DonorRuntimeHolder()

    fun get(applicationContext: Context): DonorRuntimeControl =
        holder.getOrCreate { DonorRuntimeOwner.production(applicationContext.applicationContext) }
}
