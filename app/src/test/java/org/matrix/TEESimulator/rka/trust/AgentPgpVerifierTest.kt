package org.matrix.TEESimulator.rka.trust

import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentPgpVerifierTest {
    private val oldHash = "1".repeat(64)
    private val newHash = "2".repeat(64)
    private val anchor =
        Files.readAllBytes(repositoryRoot().resolve("module/rka-agent-pgp-public.gpg"))
    private val bundle = resource("rka/agent-pgp-valid-bundle.txt")
    private val message = resource("rka/agent-pgp-valid-message.txt")
    private val signature = resource("rka/agent-pgp-valid-signature.pgp")

    @Test
    fun verifiesCanonicalFixtureWithConfiguredAgentPublicKey() {
        assertArrayEquals(message, AgentPgpVerifier.canonicalMessage(bundle, oldHash, newHash))
        assertTrue(AgentPgpVerifier.verify(anchor, bundle, signature, oldHash, newHash))
    }

    @Test
    fun rejectsModifiedBundle() {
        val modified = bundle.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }

        assertFalse(AgentPgpVerifier.verify(anchor, modified, signature, oldHash, newHash))
    }

    @Test
    fun rejectsModifiedSignature() {
        val modified = signature.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }

        assertFalse(AgentPgpVerifier.verify(anchor, bundle, modified, oldHash, newHash))
    }

    @Test
    fun rejectsOtherSigner() {
        val otherSignature = resource("rka/agent-pgp-wrong-signer-signature.pgp")

        assertFalse(AgentPgpVerifier.verify(anchor, bundle, otherSignature, oldHash, newHash))
    }

    @Test
    fun rejectsMissingTrustAnchor() {
        assertFalse(AgentPgpVerifier.verify(byteArrayOf(), bundle, signature, oldHash, newHash))
    }

    @Test
    fun rejectsHashBindingMismatch() {
        assertFalse(AgentPgpVerifier.verify(anchor, bundle, signature, "4".repeat(64), newHash))
    }

    @Test
    fun packagedTrustAnchorContainsOnlyPublicKeyPackets() {
        val inspection = AgentPgpVerifier.inspectAnchor(anchor)

        assertEquals(1, inspection.publicPrimaryKeys)
        assertEquals(0, inspection.publicSubkeys)
        assertEquals(0, inspection.userIds)
        assertEquals(0, inspection.userAttributes)
        assertEquals(0, inspection.secretKeys)
    }

    private fun resource(name: String): ByteArray =
        Files.readAllBytes(
            java.nio.file.Path.of(
                checkNotNull(javaClass.classLoader?.getResource(name)) { "missing test resource" }
                    .toURI()
            )
        )

    private fun repositoryRoot() =
        generateSequence(java.nio.file.Path.of(System.getProperty("user.dir")).toAbsolutePath()) {
                it.parent
            }
            .first { Files.isDirectory(it.resolve("module")) }
}
