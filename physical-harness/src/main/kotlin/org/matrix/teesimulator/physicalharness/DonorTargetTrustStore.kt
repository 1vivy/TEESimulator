package org.matrix.teesimulator.physicalharness

import java.security.KeyStore

object DonorTargetTrustStore {
    fun create(profile: DonorProfile): KeyStore =
        try {
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                profile.targetTrustAnchorCertificates.forEachIndexed { index, certificate ->
                    setCertificateEntry(
                        "target-anchor-${index.toString().padStart(4, '0')}",
                        certificate,
                    )
                }
            }
        } catch (failure: java.security.GeneralSecurityException) {
            throw PinnedJsseContextException.InvalidTrust(failure)
        }
}
