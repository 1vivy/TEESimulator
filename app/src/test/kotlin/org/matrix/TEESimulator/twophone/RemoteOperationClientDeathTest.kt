package org.matrix.TEESimulator.twophone

import android.os.RemoteException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.matrix.TEESimulator.interception.keystore.shim.RemoteSigningOperationBinder

class RemoteOperationClientDeathTest {
    @Test
    fun originProcessDeathAbortsTheRemoteOperationExactlyOnceAndClosesTheWatch() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        try {
            val lifecycle = RemoteNormalizedKeyLifecycle(manager)
            val generated =
                lifecycle.generate(RemoteKeyGeneration("client-death-key", byteArrayOf(1, 2, 3)))
            val lease = FakeOriginProcessDeathLease()
            val binder = RemoteSigningOperationBinder(lifecycle.begin(generated), lease)
            val backend = rig.backends.single()

            lease.triggerDeath()

            assertEquals(1, backend.abortCalls.get())
            assertTrue(lease.watchClosed.get())
            assertFailsWith<RemoteException> { binder.update(byteArrayOf(4)) }
            assertEquals(1, backend.abortCalls.get())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    @Test
    fun originDeathDuringWatchClaimAbortsAndClosesTheReturnedWatch() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        try {
            val lifecycle = RemoteNormalizedKeyLifecycle(manager)
            val generated =
                lifecycle.generate(RemoteKeyGeneration("claim-race-key", byteArrayOf(4, 5, 6)))
            val lease = FakeOriginProcessDeathLease(triggerDuringClaim = true)
            val binder = RemoteSigningOperationBinder(lifecycle.begin(generated), lease)
            val backend = rig.backends.single()

            assertEquals(1, backend.abortCalls.get())
            assertTrue(lease.watchClosed.get())
            assertFailsWith<RemoteException> { binder.update(byteArrayOf(7)) }
            assertEquals(1, backend.abortCalls.get())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }

    @Test
    fun watchClaimFailureClosesTheLeaseAndAbortsTheRemoteOperation() {
        val rig = TargetLoopbackTestRig()
        rig.startServer()
        val manager = rig.manager()
        try {
            val lifecycle = RemoteNormalizedKeyLifecycle(manager)
            val generated =
                lifecycle.generate(RemoteKeyGeneration("claim-failure-key", byteArrayOf(7, 8, 9)))
            val lease =
                FakeOriginProcessDeathLease(
                    claimFailure = IllegalStateException("watch registration failed")
                )
            val backend = rig.backends.single()

            assertFailsWith<IllegalStateException> {
                RemoteSigningOperationBinder(lifecycle.begin(generated), lease)
            }

            assertTrue(lease.closed.get())
            assertEquals(1, backend.abortCalls.get())
        } finally {
            manager.close()
            rig.stopServer()
        }
    }
}
