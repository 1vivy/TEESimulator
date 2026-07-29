package org.matrix.teesimulator.rkafixture

import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class FixtureAttestationCoreTest {
    @Test
    fun attestsTheCallerChallengeSignsWithTheAttestedKeyAndDeletesTheAlias() {
        // Given: an ephemeral key backend and a caller-supplied challenge. When: the core attests
        // and signs. Then: the attested key verifies the signature and the alias is removed.
        val backend = InMemoryAttestationKeyStore()
        val challenge = ByteArray(FixtureAttestationChallenge.BYTES) { (it + 3).toByte() }
        val result =
            FixtureRoleGate().activate(setOf("TARGET")) { activation ->
                FixtureAttestationCore(backend, SecureRandom()).attestAndSign(activation, challenge)
            }

        assertContentEquals(challenge, backend.attestedChallenge)
        assertContentEquals(challenge, result.certificateChainDer.single())
        assertTrue(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(backend.attestedPublicKey)
                update(result.payload)
                verify(result.signature)
            }
        )
        assertTrue(backend.aliases.isEmpty())
    }

    @Test
    fun deletesAnAliasWhenAttestationGenerationFailsAfterCreation() {
        // Given: a backend that creates an alias before failing. When: attestation runs. Then: the
        // failure is retained and teardown removes the ephemeral alias.
        val backend = InMemoryAttestationKeyStore(failAfterAliasCreation = true)
        val challenge = ByteArray(FixtureAttestationChallenge.BYTES)

        assertFailsWith<FixtureCoreError.KeyStoreOperation> {
            FixtureRoleGate().activate(setOf("DONOR")) { activation ->
                FixtureAttestationCore(backend, SecureRandom()).attestAndSign(activation, challenge)
            }
        }
        assertEquals(1, backend.deletedAliases)
        assertTrue(backend.aliases.isEmpty())
    }

    @Test
    fun exposesAliasCleanupWhenGenerationAndDeletionBothFail() {
        // Given: a backend with a primary generation failure and a failed alias deletion. When: the
        // core finishes. Then: callers receive the distinct compound cleanup failure.
        val backend = FailingCleanupKeyStore()

        val failure =
            assertFailsWith<FixtureCoreError.AliasCleanup> {
                FixtureRoleGate().activate(setOf("TARGET")) { activation ->
                    FixtureAttestationCore(backend, SecureRandom())
                        .attestAndSign(activation, ByteArray(FixtureAttestationChallenge.BYTES))
                }
            }

        assertIs<FixtureCoreError.KeyStoreOperation>(failure.cause)
    }

    @Test
    fun returnsTheStableBackendCategoryAndNumericCode() {
        // Given: a classified AndroidKeyStore boundary failure. When: the core maps it to a reply.
        // Then: the response carries only the stable category and numeric code.
        val backend = ClassifiedFailureKeyStore()

        val failure =
            assertFailsWith<FixtureCoreError.KeyStoreOperation> {
                FixtureRoleGate().activate(setOf("TARGET")) { activation ->
                    FixtureAttestationCore(backend, SecureRandom())
                        .attestAndSign(activation, ByteArray(FixtureAttestationChallenge.BYTES))
                }
            }

        assertEquals(
            "{\"version\":1,\"status\":\"error\",\"code\":\"KEYSTORE_PERMISSION_17\"}",
            FixtureCommandResponse.failure(failure),
        )
    }

    private class InMemoryAttestationKeyStore(private val failAfterAliasCreation: Boolean = false) :
        FixtureAttestationKeyStore {
        val aliases = mutableMapOf<String, PrivateKey>()
        lateinit var attestedChallenge: ByteArray
        lateinit var attestedPublicKey: PublicKey
        var deletedAliases = 0

        override fun generate(alias: String, challenge: ByteArray): FixtureAttestedKeyMaterial {
            val pair =
                KeyPairGenerator.getInstance("EC").run {
                    initialize(256)
                    generateKeyPair()
                }
            aliases[alias] = pair.private
            attestedChallenge = challenge.copyOf()
            attestedPublicKey = pair.public
            if (failAfterAliasCreation) throw IllegalStateException("generation failed")
            return FixtureAttestedKeyMaterial(listOf(challenge), pair.public)
        }

        override fun sign(alias: String, payload: ByteArray): ByteArray {
            val key = checkNotNull(aliases[alias])
            return Signature.getInstance("SHA256withECDSA").run {
                initSign(key)
                update(payload)
                sign()
            }
        }

        override fun delete(alias: String) {
            aliases.remove(alias)
            deletedAliases += 1
        }
    }

    private class FailingCleanupKeyStore : FixtureAttestationKeyStore {
        override fun generate(alias: String, challenge: ByteArray): FixtureAttestedKeyMaterial {
            throw IllegalStateException("generation failed")
        }

        override fun sign(alias: String, payload: ByteArray): ByteArray = error("unreachable")

        override fun delete(alias: String) {
            throw IllegalStateException("delete failed")
        }
    }

    private class ClassifiedFailureKeyStore : FixtureAttestationKeyStore {
        override fun generate(alias: String, challenge: ByteArray): FixtureAttestedKeyMaterial {
            throw FixtureKeyStoreBackendFailure(
                FixtureKeyStoreDiagnostic(FixtureKeyStoreFailureCategory.PERMISSION, 17),
                IllegalStateException("permission failure"),
            )
        }

        override fun sign(alias: String, payload: ByteArray): ByteArray = error("unreachable")

        override fun delete(alias: String) = Unit
    }
}
