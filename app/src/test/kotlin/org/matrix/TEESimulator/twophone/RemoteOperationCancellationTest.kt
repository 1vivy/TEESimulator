package org.matrix.TEESimulator.twophone

import android.os.RemoteException
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.matrix.TEESimulator.interception.keystore.shim.RemoteSigningOperationBinder
import org.matrix.teesimulator.twophone.BeginRequestPayload
import org.matrix.teesimulator.twophone.BeginResultPayload
import org.matrix.teesimulator.twophone.LifecycleRequestPayload
import org.matrix.teesimulator.twophone.UpdateRequestPayload
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireKeyHandle
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireOperationHandle
import org.matrix.teesimulator.twophone.WireOperationSpec
import org.matrix.teesimulator.twophone.WireOutcome

class RemoteOperationCancellationTest {
    @Test
    fun ownerDeathBeforeUpdatePublishesCancellationIsSticky() {
        val keyId = UUID.randomUUID()
        val operationId = UUID.randomUUID()
        var updateDispatched = false
        val connection =
            ScriptedConnection { payload ->
                when (payload) {
                    is BeginRequestPayload -> beginResult(operationId, keyId)
                    is UpdateRequestPayload -> {
                        updateDispatched = true
                        error("owner-dead update must not dispatch")
                    }
                    else -> error("unexpected payload")
                }
            }
        val manager = manager(connection)
        val operation = beginOperation(manager, keyId, operationId)

        assertFalse(manager.cancelActiveOperation(operationId))
        assertFailsWith<TargetSessionException.Cancelled> { operation.update(byteArrayOf(1)) }

        assertFalse(updateDispatched)
        assertTrue(connection.closed)
    }

    @Test
    fun ownerDeathCancelsBlockedRemoteUpdateAndClosesTheSession() {
        val keyId = UUID.randomUUID()
        val operationId = UUID.randomUUID()
        val updateStarted = CountDownLatch(1)
        val cancellationObserved = CountDownLatch(1)
        val donorAbortCalls = AtomicInteger()
        val connectionClosed = AtomicBoolean(false)
        val connection =
            object : TargetConnection {
                override val protocol = "TLSv1.3"
                var closed = false

                override fun exchange(
                    sequence: ULong,
                    payload: LifecycleRequestPayload,
                    caller: WireCallerIdentity,
                    deadline: Instant,
                    cancellation: TargetCallCancellation,
                ): WireOutcome =
                    when (payload) {
                        is BeginRequestPayload -> beginResult(operationId, keyId)
                        is UpdateRequestPayload -> {
                            val registration =
                                cancellation.onCancel { cancellationObserved.countDown() }
                            try {
                                updateStarted.countDown()
                                check(cancellationObserved.await(3, TimeUnit.SECONDS))
                                throw TargetSessionException.Cancelled()
                            } finally {
                                registration.close()
                            }
                        }
                        else -> error("unexpected payload")
                    }

                override fun close() {
                    if (connectionClosed.compareAndSet(false, true)) {
                        closed = true
                        donorAbortCalls.incrementAndGet()
                    }
                }
            }
        val manager = manager(connection)
        val operation = beginOperation(manager, keyId, operationId)
        val lease = FakeOriginProcessDeathLease()
        val binder = RemoteSigningOperationBinder(operation, lease)
        val workerFailure = AtomicReference<Throwable?>()
        val worker =
            Thread {
                runCatching { binder.update(byteArrayOf(1)) }
                    .exceptionOrNull()
                    ?.let(workerFailure::set)
            }

        worker.start()
        assertTrue(updateStarted.await(3, TimeUnit.SECONDS))
        lease.triggerDeath()
        worker.join(TimeUnit.SECONDS.toMillis(3))

        assertFalse(worker.isAlive)
        assertTrue(cancellationObserved.await(0, TimeUnit.MILLISECONDS))
        assertTrue(workerFailure.get() is RemoteException)
        assertTrue(connection.closed)
        assertTrue(lease.watchClosed.get())
        lease.triggerDeath()
        assertEquals(1, donorAbortCalls.get())
    }

    private fun manager(connection: TargetConnection): TargetSessionManager {
        val rig = TargetLoopbackTestRig()
        return TargetSessionManager.createForTest(
            rig.profile,
            rig.caller,
            Instant::now,
            TargetConnectionFactory { _, _ -> connection },
        )
    }

    private fun beginOperation(
        manager: TargetSessionManager,
        keyId: UUID,
        operationId: UUID,
    ): RemoteSigningOperation {
        val operation = WireOperationHandle(operationId, keyId, byteArrayOf(3))
        manager.exchange(
            BeginRequestPayload(
                UUID.randomUUID(),
                0uL,
                WireKeyHandle(keyId, byteArrayOf(1)),
                WireOperationSpec(WireKeyPurpose.SIGN, WireDigest.SHA256),
            )
        )
        return RemoteSigningOperation(manager, operation)
    }

    private fun beginResult(operationId: UUID, keyId: UUID): WireOutcome =
        WireOutcome.Success(
            BeginResultPayload(WireOperationHandle(operationId, keyId, byteArrayOf(3)), 0uL)
        )

    private class ScriptedConnection(
        private val response: (LifecycleRequestPayload) -> WireOutcome,
    ) : TargetConnection {
        override val protocol = "TLSv1.3"
        var closed = false

        override fun exchange(
            sequence: ULong,
            payload: LifecycleRequestPayload,
            caller: WireCallerIdentity,
            deadline: Instant,
            cancellation: TargetCallCancellation,
        ): WireOutcome = response(payload)

        override fun close() {
            closed = true
        }
    }
}
