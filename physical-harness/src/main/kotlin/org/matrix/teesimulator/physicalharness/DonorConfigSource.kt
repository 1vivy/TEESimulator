package org.matrix.teesimulator.physicalharness

import java.net.InetAddress
import java.time.Instant
import org.matrix.teesimulator.twophone.SpkiPin

fun interface DonorConfigSource {
    fun load(profileId: String, now: Instant): DonorProfile?
}

sealed class DonorConfigSourceException(message: String) : RuntimeException(message) {
    class IdentityAliasMismatch :
        DonorConfigSourceException("stored donor identity alias does not match AndroidKeyStore")
}

class StoredDonorConfigSource(private val store: DonorPublicProfileStore) : DonorConfigSource {
    override fun load(profileId: String, now: Instant): DonorProfile? {
        DonorProfile.requireValidProfileId(profileId)
        val publicProfile = store.load() ?: return null
        if (publicProfile.donorIdentity.alias != AndroidKeyStoreDonorTlsServerIdentity.KEY_ALIAS) {
            throw DonorConfigSourceException.IdentityAliasMismatch()
        }
        return DonorProfile.create(
            profileId,
            InetAddress.getByAddress(publicProfile.bindEndpoint.address),
            publicProfile.bindEndpoint.port,
            SpkiPin.parse(publicProfile.donorIdentity.pin.toString()),
            SpkiPin.parse(publicProfile.targetPin.toString()),
            publicProfile.targetIdentityCertificateDer,
            publicProfile.targetTrustChainDer.drop(1),
            now,
        )
    }
}
