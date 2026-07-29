package org.matrix.teesimulator.physicalharness

import android.content.Context
import org.matrix.teesimulator.twophone.PairIdentity
import org.matrix.teesimulator.twophone.WireCallerIdentity

class PhysicalDonorProcess
private constructor(
    private val authenticatedStateStore: AuthenticatedDonorStateStore,
    private val donor: AndroidKeystoreDonor,
    private val authenticator: HandleAuthenticator,
    private val repository: DonorLifecycleRepository,
) {
    internal constructor(
        authenticatedStateStore: AuthenticatedDonorStateStore,
        repository: DonorLifecycleRepository,
        donor: AndroidKeystoreDonor,
        authenticator: HandleAuthenticator,
    ) : this(authenticatedStateStore, donor, authenticator, repository)

    init {
        repository.recover()
    }

    fun newSessionBackend(
        pair: PairIdentity,
        sessionId: ByteArray,
        expectedCaller: WireCallerIdentity,
    ): AndroidWireDonorBackend =
        AndroidWireDonorBackend(
            sessionId,
            PairIdentity(pair.targetPin, pair.donorPin),
            WireCallerIdentity(
                expectedCaller.signingCertificateDigest,
                expectedCaller.attestationApplicationIdDigest,
            ),
            repository,
            donor,
            authenticator,
        )

    companion object {
        fun create(context: Context, mac: HandleMac): PhysicalDonorProcess =
            create(context, mac, AndroidKeystoreDonor(context))

        internal fun create(
            context: Context,
            mac: HandleMac,
            donor: AndroidKeystoreDonor,
        ): PhysicalDonorProcess {
            val authenticator = HandleAuthenticator(mac)
            val stateStore =
                CodecAuthenticatedDonorStateStore(
                    AtomicFileDonorStateBlobStore(context),
                    DonorStateCodec(mac),
                )
            val repository =
                DonorLifecycleRepository(
                    stateStore,
                    AndroidKeystoreDurableKeyStore(donor),
                    authenticator,
                )
            return PhysicalDonorProcess(stateStore, donor, authenticator, repository)
        }
    }
}
