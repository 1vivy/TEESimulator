package org.matrix.teesimulator.rka

import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolSecretFieldAllowlistTest {
    @Test
    fun payloadModelsContainOnlyAllowlistedPublicFields() {
        // Given: every normalized request and response payload model.
        val modelTypes =
            listOf(
                GenerateRequest::class,
                GenerateResponse::class,
                GetMetadataRequest::class,
                GetMetadataResponse::class,
                DeleteRequest::class,
                DeleteResponse::class,
                BeginRequest::class,
                BeginResponse::class,
                UpdateRequest::class,
                UpdateResponse::class,
                FinishRequest::class,
                FinishResponse::class,
                AbortRequest::class,
                AbortResponse::class,
            )
        val allowed =
            setOf(
                "logicalName",
                "attestationChallenge",
                "mutationId",
                "purpose",
                "digest",
                "curve",
                "keyHandle",
                "publicKeySpki",
                "certificateChain",
                "lifecycleRevision",
                "operationId",
                "operationHandle",
                "chunkIndex",
                "input",
                "output",
                "signature",
                "result",
                "terminalState",
            )

        // When: the serialized field surface is inspected.
        val observed =
            modelTypes.flatMap { type -> type.java.declaredFields.map { it.name } }.toSet()
        val forbidden = Regex("(?i)(blob|private|alias|dice|uds|rkpd)")
        val mapFields =
            modelTypes.flatMap { type ->
                type.java.declaredFields.filter { field ->
                    Map::class.java.isAssignableFrom(field.type)
                }
            }

        // Then: no unreviewed secret-bearing field can enter a payload model.
        assertTrue(
            "unexpected payload fields: ${observed - allowed}",
            observed.all(allowed::contains),
        )
        assertTrue(
            "forbidden secret-bearing payload field",
            observed.none(forbidden::containsMatchIn),
        )
        assertTrue("arbitrary map payload field", mapFields.isEmpty())
    }
}
