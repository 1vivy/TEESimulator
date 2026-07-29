package org.matrix.teesimulator.physicalharness

import java.time.Instant
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

internal class DonorServiceControllerRig(
    callbackExecutor: Executor = Executor(Runnable::run),
    val runtime: FakeServiceRuntime = FakeServiceRuntime(),
    val host: FakeDonorServiceHost = FakeDonorServiceHost(),
    val worker: ExecutorService = newDonorServiceTestWorker(),
    shutdownTimeoutMillis: Long = 1_000,
) : AutoCloseable {
    val events = CopyOnWriteArrayList<String>()
    val controller =
        DonorServiceController(
            runtime,
            worker,
            callbackExecutor,
            { Instant.parse("2026-01-02T03:04:05Z") },
            host.also { it.events = events },
            shutdownTimeoutMillis = shutdownTimeoutMillis,
        )

    init {
        runtime.events = events
    }

    override fun close() {
        controller.close()
    }
}

internal class FakeServiceRuntime : DonorRuntimeControl {
    @Volatile override var state = DonorRuntimeState.STOPPED
    @Volatile var activeProfileId: String? = null
    @Volatile var startFailure: RuntimeException? = null
    @Volatile var startFailureState = DonorRuntimeState.STOPPED
    @Volatile var stopFailure: RuntimeException? = null
    val stopFailuresRemaining = AtomicInteger()
    @Volatile var startEntered = CountDownLatch(0)
    @Volatile var releaseStart = CountDownLatch(0)
    @Volatile var startsFinished = CountDownLatch(0)
    @Volatile var stopEntered = CountDownLatch(0)
    @Volatile var releaseStop = CountDownLatch(0)
    @Volatile var stopsFinished = CountDownLatch(0)
    var events: CopyOnWriteArrayList<String>? = null
    val startCalls = AtomicInteger()
    val stopCalls = AtomicInteger()
    val stopDeadlines = CopyOnWriteArrayList<Long>()
    val stopThreadNames = CopyOnWriteArrayList<String>()
    private val activeCalls = AtomicInteger()
    val maxConcurrentCalls = AtomicInteger()

    override fun start(profileId: String, now: Instant): DonorRuntimeStartResult {
        enterCall()
        startCalls.incrementAndGet()
        events?.add("runtime-start:$profileId")
        startEntered.countDown()
        try {
            releaseStart.await()
            startFailure?.let {
                state = startFailureState
                throw it
            }
            if (state == DonorRuntimeState.RUNNING) {
                if (activeProfileId == profileId) return DonorRuntimeStartResult.ALREADY_RUNNING
                throw DonorRuntimeException.ConflictingProfile()
            }
            state = DonorRuntimeState.RUNNING
            activeProfileId = profileId
            return DonorRuntimeStartResult.STARTED
        } finally {
            startsFinished.countDown()
            exitCall()
        }
    }

    override fun stop(): DonorRuntimeStopResult = stopUntil(Long.MAX_VALUE)

    override fun stopUntil(deadlineNanos: Long): DonorRuntimeStopResult {
        enterCall()
        stopCalls.incrementAndGet()
        stopDeadlines += deadlineNanos
        stopThreadNames += Thread.currentThread().name
        events?.add("runtime-stop")
        stopEntered.countDown()
        try {
            releaseStop.await()
            if (
                stopFailuresRemaining.getAndUpdate { remaining ->
                    (remaining - 1).coerceAtLeast(0)
                } > 0
            ) {
                throw TestServiceFailure()
            }
            stopFailure?.let { throw it }
            val result =
                if (state == DonorRuntimeState.STOPPED) {
                    DonorRuntimeStopResult.ALREADY_STOPPED
                } else {
                    DonorRuntimeStopResult.STOPPED
                }
            state = DonorRuntimeState.STOPPED
            activeProfileId = null
            return result
        } finally {
            stopsFinished.countDown()
            exitCall()
        }
    }

    private fun enterCall() {
        val active = activeCalls.incrementAndGet()
        while (true) {
            val maximum = maxConcurrentCalls.get()
            if (active <= maximum || maxConcurrentCalls.compareAndSet(maximum, active)) return
        }
    }

    private fun exitCall() {
        activeCalls.decrementAndGet()
    }
}

internal class FakeDonorServiceHost : DonorServiceController.Host {
    lateinit var events: CopyOnWriteArrayList<String>
    val foregroundCalls = AtomicInteger()
    val stopCalls = AtomicInteger()
    val removeForegroundCalls = AtomicInteger()
    val terminateProcessCalls = AtomicInteger()
    val stoppedStartIds = CopyOnWriteArrayList<Int>()
    val stopSelfResults = ConcurrentLinkedQueue<Boolean>()
    @Volatile var foregroundFailure: RuntimeException? = null
    @Volatile var foregroundEntered = CountDownLatch(0)
    @Volatile var releaseForeground = CountDownLatch(0)
    @Volatile var foregroundAttemptsFinished = CountDownLatch(0)
    @Volatile var stopSelfFailure: RuntimeException? = null
    @Volatile var removeForegroundFailure: RuntimeException? = null
    @Volatile var stopSelfEntered = CountDownLatch(0)
    @Volatile var releaseStopSelf = CountDownLatch(0)
    @Volatile var stopSelfAttemptsFinished = CountDownLatch(0)
    @Volatile var removeForegroundEntered = CountDownLatch(0)
    @Volatile var releaseRemoveForeground = CountDownLatch(0)
    @Volatile var removalsFinished = CountDownLatch(0)
    @Volatile var stopsFinished = CountDownLatch(0)
    @Volatile var terminationEntered = CountDownLatch(0)

    override fun startForegroundNow() {
        foregroundCalls.incrementAndGet()
        events += "foreground-start"
        foregroundEntered.countDown()
        try {
            releaseForeground.await()
            foregroundFailure?.let { throw it }
        } finally {
            foregroundAttemptsFinished.countDown()
        }
    }

    override fun stopSelfIfLatest(startId: Int): Boolean {
        var stopped = false
        stopCalls.incrementAndGet()
        stoppedStartIds += startId
        events += "stop-self:$startId"
        stopSelfEntered.countDown()
        try {
            releaseStopSelf.await()
            stopSelfFailure?.let { throw it }
            stopped = stopSelfResults.poll() ?: true
            return stopped
        } finally {
            stopSelfAttemptsFinished.countDown()
            if (!stopped) stopsFinished.countDown()
        }
    }

    override fun removeForeground() {
        removeForegroundCalls.incrementAndGet()
        events += "foreground-remove"
        removeForegroundEntered.countDown()
        try {
            releaseRemoveForeground.await()
            removeForegroundFailure?.let { throw it }
        } finally {
            removalsFinished.countDown()
            stopsFinished.countDown()
        }
    }

    override fun terminateDonorProcess(): Nothing {
        terminateProcessCalls.incrementAndGet()
        events += "process-terminate"
        terminationEntered.countDown()
        throw TestDonorProcessTermination()
    }
}

internal class QueuedCallbackExecutor : Executor {
    private val tasks = ConcurrentLinkedQueue<Runnable>()

    override fun execute(command: Runnable) {
        tasks += command
    }

    fun runAll() {
        while (true) {
            val task = tasks.poll() ?: return
            task.run()
        }
    }
}

internal fun CountDownLatch.awaitTest() {
    check(await(5, TimeUnit.SECONDS))
}

internal class TestServiceFailure : RuntimeException()

internal class TestDonorProcessTermination : RuntimeException()

internal class RejectingDonorServiceExecutor : AbstractExecutorService() {
    @Volatile private var shutdown = false

    override fun execute(command: Runnable) {
        throw RejectedExecutionException()
    }

    override fun shutdown() {
        shutdown = true
    }

    override fun shutdownNow(): MutableList<Runnable> {
        shutdown = true
        return mutableListOf()
    }

    override fun isShutdown(): Boolean = shutdown

    override fun isTerminated(): Boolean = shutdown

    override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = shutdown
}

private fun newDonorServiceTestWorker(): ExecutorService =
    Executors.newSingleThreadExecutor { task ->
        Thread(task, "donor-service-controller-test").apply { isDaemon = true }
    }
