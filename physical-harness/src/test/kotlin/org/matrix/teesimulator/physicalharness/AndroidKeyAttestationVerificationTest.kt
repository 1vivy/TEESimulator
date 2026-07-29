package org.matrix.teesimulator.physicalharness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AndroidKeyAttestationVerificationTest {
    private val identity =
        CallerIdentityCanonicalizer()
            .canonicalize(
                listOf(CallerPackageIdentity("org.example.donor", 3, listOf(byteArrayOf(1, 2))))
            )
    private val challenge = byteArrayOf(7, 8, 9)

    @Test
    fun acceptsExactTeeAttestationAndIgnoresNoUnrelatedCertificate() {
        val backend = FakeAndroidKeyStoreBackend { requestedChallenge ->
            SyntheticAndroidKeyAttestation.material(
                requestedChallenge,
                identity.attestationApplicationIdDer,
            )
        }
        val metadata = donor(backend).generate("key", challenge, identity.wireIdentity)

        assertContentEquals(challenge, metadata.attestationChallenge)
        assertContentEquals(backend.metadata("key")!!.generatedPublicKey, metadata.publicKey)
    }

    @Test
    fun failedGenerationVerificationDeletesNewAlias() {
        val backend = FakeAndroidKeyStoreBackend {
            SyntheticAndroidKeyAttestation.material(
                challenge = byteArrayOf(1),
                applicationId = identity.attestationApplicationIdDer,
            )
        }

        assertFailsWith<AndroidKeystoreDonorException.AttestationRejected> {
            donor(backend).generate("key", challenge, identity.wireIdentity)
        }
        assertEquals(listOf("key"), backend.deletedAliases)
        assertEquals(null, backend.metadata("key"))
    }

    @Test
    fun rejectsNonTeeKeyInfoAndEitherNonTeeAttestationSecurityLevel() {
        val materials =
            listOf(
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    backendSecurityLevel = BackendSecurityLevel.SOFTWARE,
                ),
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    backendSecurityLevel = BackendSecurityLevel.STRONGBOX,
                ),
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    attestationSecurityLevel = 0,
                ),
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    keymasterSecurityLevel = 2,
                ),
            )

        materials.forEachIndexed { index, material ->
            val backend = FakeAndroidKeyStoreBackend { material }
            assertFailsWith<AndroidKeystoreDonorException.AttestationRejected> {
                donor(backend).generate("key-$index", challenge, identity.wireIdentity)
            }
            assertEquals(listOf("key-$index"), backend.deletedAliases)
        }
    }

    @Test
    fun requiresExactlyOneExplicitTag709WithExactApplicationIdBytes() {
        val wrongApplicationId = identity.attestationApplicationIdDer.copyOf().also { it[0] = 0 }
        val materials =
            listOf(
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    applicationIds = listOf(SyntheticApplicationId(wrongApplicationId)),
                ),
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    applicationIds =
                        listOf(
                            SyntheticApplicationId(identity.attestationApplicationIdDer),
                            SyntheticApplicationId(
                                identity.attestationApplicationIdDer,
                                AuthorizationListLocation.TEE,
                            ),
                        ),
                ),
                SyntheticAndroidKeyAttestation.material(
                    challenge,
                    identity.attestationApplicationIdDer,
                    applicationIds =
                        listOf(
                            SyntheticApplicationId(
                                identity.attestationApplicationIdDer,
                                explicit = false,
                            )
                        ),
                ),
            )

        materials.forEachIndexed { index, material ->
            val backend = FakeAndroidKeyStoreBackend { material }
            assertFailsWith<AndroidKeystoreDonorException.AttestationRejected> {
                donor(backend).generate("key-$index", challenge, identity.wireIdentity)
            }
        }
    }

    @Test
    fun rejectsTag709FromCertificateWhosePublicKeyDoesNotMatchGeneratedKey() {
        val material =
            SyntheticAndroidKeyAttestation.material(
                challenge,
                identity.attestationApplicationIdDer,
                extensionPublicKeyMatches = false,
            )
        val backend = FakeAndroidKeyStoreBackend { material }

        assertFailsWith<AndroidKeystoreDonorException.AttestationRejected> {
            donor(backend).generate("key", challenge, identity.wireIdentity)
        }
        assertEquals(listOf("key"), backend.deletedAliases)
    }

    private fun donor(backend: FakeAndroidKeyStoreBackend) =
        AndroidKeystoreDonor(identityResolver = { identity }, backend = backend)
}
