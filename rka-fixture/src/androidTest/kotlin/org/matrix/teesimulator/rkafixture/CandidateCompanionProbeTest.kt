package org.matrix.teesimulator.rkafixture

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import junit.framework.TestCase

class CandidateCompanionProbeTest : TestCase() {
    fun testCandidateCompanionOwner() {
        val instrumentation =
            Class.forName("androidx.test.platform.app.InstrumentationRegistry")
                .getMethod("getInstrumentation")
                .invoke(null) as android.app.Instrumentation
        val phase =
            Class.forName("androidx.test.platform.app.InstrumentationRegistry")
                .getMethod("getArguments")
                .invoke(null)
                .let { it as Bundle }
                .getString("phase", "PRE")
        val context = instrumentation.targetContext
        val connected = ArrayBlockingQueue<IBinder>(1)
        val connection =
            object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, service: IBinder) {
                    connected.offer(service)
                }

                override fun onServiceDisconnected(name: ComponentName?) = Unit
            }
        val intent = Intent(context, CandidateCompanionService::class.java)
        assertTrue(context.bindService(intent, connection, Context.BIND_AUTO_CREATE))
        try {
            val endpoint = requireNotNull(connected.poll(10, TimeUnit.SECONDS))
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeInterfaceToken(CandidateCompanionService.DESCRIPTOR)
                data.writeStrongBinder(Binder())
                data.writeString(phase)
                assertTrue(
                    endpoint.transact(CandidateCompanionService.TRANSACTION_OPEN, data, reply, 0)
                )
                reply.readException()
                val receipt = requireNotNull(reply.readString())
                val status = Bundle()
                status.putString("candidate_receipt", receipt.replace("\n", ";"))
                instrumentation.sendStatus(0, status)
                if (phase != "CLEANUP") {
                    assertTrue(receipt.contains("OWNER=CANDIDATE_COMPANION"))
                    assertTrue(receipt.contains("PROVEN=true"))
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        } finally {
            context.unbindService(connection)
        }
    }
}
