package org.matrix.teesimulator.physicalharness

import java.time.Instant

interface DonorRuntimeControl {
    val state: DonorRuntimeState

    fun start(profileId: String, now: Instant): DonorRuntimeStartResult

    fun stop(): DonorRuntimeStopResult

    fun stopUntil(deadlineNanos: Long): DonorRuntimeStopResult = stop()
}
