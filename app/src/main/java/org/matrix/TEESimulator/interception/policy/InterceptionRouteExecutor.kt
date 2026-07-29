package org.matrix.TEESimulator.interception.policy

import java.util.concurrent.atomic.AtomicInteger

/**
 * Deterministic host-test harness for [FixtureInterceptionPolicy]. Production Binder routing enters
 * through the Keystore interceptors and does not call this class.
 */
class InterceptionRouteExecutor(
    private val policy: FixtureInterceptionPolicy,
    private val remoteCall: (InterceptionRequest) -> ByteArray,
) {
    private val remoteCalls = AtomicInteger()
    private val platformContinuations = AtomicInteger()

    val remoteCallCount: Int
        get() = remoteCalls.get()

    val platformContinuationCount: Int
        get() = platformContinuations.get()

    fun execute(request: InterceptionRequest, platformResult: ByteArray): ByteArray =
        when (policy.decide(request)) {
            InterceptionDecision.REMOTE -> {
                remoteCalls.incrementAndGet()
                remoteCall(request)
            }
            InterceptionDecision.PLATFORM -> {
                platformContinuations.incrementAndGet()
                platformResult
            }
        }
}
