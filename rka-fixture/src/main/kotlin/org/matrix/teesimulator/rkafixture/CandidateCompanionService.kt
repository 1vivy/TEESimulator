package org.matrix.teesimulator.rkafixture

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel

class CandidateCompanionService : Service() {
    private var session: ClientOwnedCandidateSession? = null
    private var clientToken: IBinder? = null

    private val endpoint =
        object : Binder() {
            override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean =
                when (code) {
                    TRANSACTION_OPEN -> {
                        data.enforceInterface(DESCRIPTOR)
                        val token =
                            requireNotNull(data.readStrongBinder()) {
                                "CANDIDATE_CLIENT_TOKEN_REQUIRED"
                            }
                        closeSession()
                        val nextSession = ClientOwnedCandidateSession(::onSessionClosed)
                        token.linkToDeath(nextSession::clientDied, 0)
                        nextSession.linkToClientDeath()
                        clientToken = token
                        session = nextSession
                        reply?.writeNoException()
                        val phase = requireNotNull(data.readString()) { "PROBE_PHASE_REQUIRED" }
                        val receipt =
                            when (phase) {
                                "PRE" ->
                                    CandidateRootProbe.runCompanion(
                                        true,
                                        phase,
                                        filesDir.toPath().resolve("candidate-probe"),
                                    )
                                "POST" ->
                                    CandidateRootProbe.runCompanion(
                                        false,
                                        phase,
                                        filesDir.toPath().resolve("candidate-probe"),
                                    )
                                "CLEANUP" -> {
                                    CandidateRootProbe.cleanupCompanion(
                                        filesDir.toPath().resolve("candidate-probe")
                                    )
                                    "CLEANUP=COMPANION_ALIAS_AND_STAGING_REMOVED\n"
                                }
                                else -> error("PROBE_PHASE_INVALID")
                            }
                        reply?.writeString(receipt)
                        true
                    }
                    TRANSACTION_CLOSE -> {
                        data.enforceInterface(DESCRIPTOR)
                        closeSession()
                        reply?.writeNoException()
                        true
                    }
                    else -> super.onTransact(code, data, reply, flags)
                }
        }

    override fun onBind(intent: Intent?): IBinder = endpoint

    override fun onDestroy() {
        closeSession()
        super.onDestroy()
    }

    private fun closeSession() {
        val active = session ?: return
        val token = clientToken
        active.close()
        if (token != null) runCatching { token.unlinkToDeath(active::clientDied, 0) }
        clientToken = null
        session = null
    }

    private fun onSessionClosed() = Unit

    companion object {
        const val DESCRIPTOR = "org.matrix.teesimulator.rkafixture.CandidateCompanionService"
        const val TRANSACTION_OPEN = IBinder.FIRST_CALL_TRANSACTION
        const val TRANSACTION_CLOSE = IBinder.FIRST_CALL_TRANSACTION + 1
    }
}
