package org.matrix.teesimulator.physicalharness

import android.content.Context
import java.nio.charset.StandardCharsets
import java.util.UUID
import org.matrix.teesimulator.twophone.KeyState
import org.matrix.teesimulator.twophone.WireCallerIdentity
import org.matrix.teesimulator.twophone.WireDigest
import org.matrix.teesimulator.twophone.WireEcCurve
import org.matrix.teesimulator.twophone.WireKeyAlgorithm
import org.matrix.teesimulator.twophone.WireKeyMetadata
import org.matrix.teesimulator.twophone.WireKeyPurpose
import org.matrix.teesimulator.twophone.WireKeySpec

sealed class AndroidKeystoreDonorException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    class WrongCaller : AndroidKeystoreDonorException("wrong caller")

    class InvalidAlias : AndroidKeystoreDonorException("invalid key alias")

    class InvalidChallenge : AndroidKeystoreDonorException("invalid attestation challenge")

    class AliasAlreadyExists : AndroidKeystoreDonorException("key alias already exists")

    class KeyNotFound : AndroidKeystoreDonorException("key not found")

    class OperationNotFound : AndroidKeystoreDonorException("operation not found")

    class AttestationRejected internal constructor(message: String, cause: Throwable? = null) :
        AndroidKeystoreDonorException(message, cause)

    class BackendFailure(cause: Throwable) :
        AndroidKeystoreDonorException("AndroidKeyStore operation failed", cause)
}

class AndroidKeystoreOperationHandle internal constructor(val id: UUID) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is AndroidKeystoreOperationHandle && id == other.id)

    override fun hashCode(): Int = id.hashCode()
}

class AndroidKeystoreDonor
internal constructor(
    private val identityResolver: () -> CanonicalCallerIdentity,
    private val backend: AndroidKeyStoreBackend,
    private val operationIdFactory: () -> UUID = UUID::randomUUID,
    private val coordinator: AndroidKeystoreDonorCoordinator = AndroidKeystoreDonorCoordinator(),
) {
    constructor(
        context: Context
    ) : this(
        identityResolver = AndroidOwnCallerIdentityResolver(context)::resolve,
        backend = PlatformAndroidKeyStoreBackend(),
        coordinator = AndroidKeystoreDonorCoordinator.processWide,
    )

    internal fun ownedAliases(): Set<String> =
        synchronized(coordinator.monitor) {
            backend.aliases().filterTo(mutableSetOf(), DonorKeyAliasPolicy::isOwnedAlias)
        }

    internal fun inspect(
        alias: String,
        caller: WireCallerIdentity,
        expectedChallenge: ByteArray?,
    ): DurableKeyInspection {
        val identity = requireOwnCaller(caller)
        validateAlias(alias)
        val stableChallenge = expectedChallenge?.copyOf()
        return synchronized(coordinator.monitor) {
            val material =
                backend.metadata(alias) ?: return@synchronized DurableKeyInspection.Absent
            try {
                DurableKeyInspection.Verified(verifiedMetadata(material, identity, stableChallenge))
            } catch (_: AndroidKeystoreDonorException.AttestationRejected) {
                DurableKeyInspection.Rejected
            }
        }
    }

    internal fun deleteIfExact(
        alias: String,
        caller: WireCallerIdentity,
        expectedMetadata: WireKeyMetadata,
    ): DurableDeleteOutcome {
        val identity = requireOwnCaller(caller)
        validateAlias(alias)
        val stableExpected = expectedMetadata.defensiveCopy()
        return synchronized(coordinator.monitor) {
            val material =
                backend.metadata(alias) ?: return@synchronized DurableDeleteOutcome.ABSENT
            val actual =
                try {
                    verifiedMetadata(material, identity, stableExpected.attestationChallenge)
                } catch (_: AndroidKeystoreDonorException.AttestationRejected) {
                    return@synchronized DurableDeleteOutcome.MISMATCH
                }
            if (!metadataMaterialEquals(actual, stableExpected)) {
                return@synchronized DurableDeleteOutcome.MISMATCH
            }
            coordinator.operations.values.filter { it.alias == alias }.forEach(::abortForDelete)
            backend.delete(alias)
            if (backend.containsAlias(alias)) {
                throw AndroidKeystoreDonorException.BackendFailure(
                    IllegalStateException("AndroidKeyStore deletion postcondition failed")
                )
            }
            DurableDeleteOutcome.DELETED
        }
    }

    fun generate(alias: String, challenge: ByteArray, caller: WireCallerIdentity): WireKeyMetadata {
        val identity = requireOwnCaller(caller)
        validateAlias(alias)
        validateChallenge(challenge)
        val challengeBytes = challenge.copyOf()
        return synchronized(coordinator.monitor) {
            if (backend.containsAlias(alias)) {
                throw AndroidKeystoreDonorException.AliasAlreadyExists()
            }
            val material = backend.generate(alias, challengeBytes)
            try {
                verifiedMetadata(material, identity, challengeBytes)
            } catch (exception: AndroidKeystoreDonorException.AttestationRejected) {
                cleanupFailedGeneration(alias, exception)
            }
        }
    }

    fun metadata(alias: String, caller: WireCallerIdentity): WireKeyMetadata {
        val identity = requireOwnCaller(caller)
        validateAlias(alias)
        return synchronized(coordinator.monitor) {
            val material =
                backend.metadata(alias) ?: throw AndroidKeystoreDonorException.KeyNotFound()
            verifiedMetadata(material, identity, expectedChallenge = null)
        }
    }

    fun delete(alias: String, caller: WireCallerIdentity) {
        val identity = requireOwnCaller(caller)
        validateAlias(alias)
        synchronized(coordinator.monitor) {
            val material =
                backend.metadata(alias) ?: throw AndroidKeystoreDonorException.KeyNotFound()
            AndroidKeyAttestationVerifier.verify(material, identity, expectedChallenge = null)
            coordinator.operations.values.filter { it.alias == alias }.forEach(::abortForDelete)
            backend.delete(alias)
        }
    }

    fun begin(alias: String, caller: WireCallerIdentity): AndroidKeystoreOperationHandle {
        val identity = requireOwnCaller(caller)
        validateAlias(alias)
        return synchronized(coordinator.monitor) {
            val material =
                backend.metadata(alias) ?: throw AndroidKeystoreDonorException.KeyNotFound()
            AndroidKeyAttestationVerifier.verify(material, identity, expectedChallenge = null)
            val backendOperation = backend.begin(alias)
            registerOperation(alias, caller, backendOperation)
        }
    }

    fun update(
        handle: AndroidKeystoreOperationHandle,
        caller: WireCallerIdentity,
        input: ByteArray,
    ): ByteArray {
        return synchronized(coordinator.monitor) {
            requireOwnCaller(caller)
            val operation = operation(handle, caller)
            synchronized(operation) {
                requireActive(handle, operation)
                try {
                    operation.backendOperation.update(input.copyOf())
                } catch (exception: RuntimeException) {
                    terminalizeFailedOperation(handle, operation, exception)
                }
            }
            ByteArray(0)
        }
    }

    fun finish(
        handle: AndroidKeystoreOperationHandle,
        caller: WireCallerIdentity,
        input: ByteArray,
    ): ByteArray {
        return synchronized(coordinator.monitor) {
            requireOwnCaller(caller)
            val operation = operation(handle, caller)
            synchronized(operation) {
                requireActive(handle, operation)
                try {
                    operation.backendOperation.finish(input.copyOf()).copyOf().also {
                        coordinator.operations.remove(handle.id, operation)
                    }
                } catch (exception: RuntimeException) {
                    terminalizeFailedOperation(handle, operation, exception)
                }
            }
        }
    }

    fun abort(handle: AndroidKeystoreOperationHandle, caller: WireCallerIdentity) {
        synchronized(coordinator.monitor) {
            requireOwnCaller(caller)
            val operation = operation(handle, caller)
            synchronized(operation) {
                requireActive(handle, operation)
                coordinator.operations.remove(handle.id, operation)
                operation.backendOperation.abort()
            }
        }
    }

    private fun requireOwnCaller(caller: WireCallerIdentity): CanonicalCallerIdentity {
        val identity = identityResolver()
        if (identity.wireIdentity != caller) {
            throw AndroidKeystoreDonorException.WrongCaller()
        }
        return identity
    }

    private fun validateAlias(alias: String) {
        val size = alias.toByteArray(StandardCharsets.UTF_8).size
        if (alias.isBlank() || size > MAX_ALIAS_UTF8_BYTES) {
            throw AndroidKeystoreDonorException.InvalidAlias()
        }
    }

    private fun validateChallenge(challenge: ByteArray) {
        if (challenge.isEmpty() || challenge.size > MAX_ATTESTATION_CHALLENGE_BYTES) {
            throw AndroidKeystoreDonorException.InvalidChallenge()
        }
    }

    private fun verifiedMetadata(
        material: BackendKeyMaterial,
        identity: CanonicalCallerIdentity,
        expectedChallenge: ByteArray?,
    ): WireKeyMetadata {
        val verified = AndroidKeyAttestationVerifier.verify(material, identity, expectedChallenge)
        return WireKeyMetadata(
            state = KeyState.ACTIVE,
            attestationChallenge = verified.challenge,
            publicKey = verified.publicKey,
            certificateChain = verified.certificateChain,
            keySpec = KEY_SPEC,
        )
    }

    private fun cleanupFailedGeneration(
        alias: String,
        verificationFailure: AndroidKeystoreDonorException.AttestationRejected,
    ): Nothing {
        try {
            backend.delete(alias)
        } catch (cleanupFailure: RuntimeException) {
            verificationFailure.addSuppressed(cleanupFailure)
        }
        throw verificationFailure
    }

    private fun registerOperation(
        alias: String,
        caller: WireCallerIdentity,
        backendOperation: BackendSignOperation,
    ): AndroidKeystoreOperationHandle {
        while (true) {
            val id = operationIdFactory()
            val record = CoordinatedOperationRecord(alias, caller, backendOperation)
            if (coordinator.operations.putIfAbsent(id, record) == null) {
                return AndroidKeystoreOperationHandle(id)
            }
        }
    }

    private fun operation(
        handle: AndroidKeystoreOperationHandle,
        caller: WireCallerIdentity,
    ): CoordinatedOperationRecord {
        val operation =
            coordinator.operations[handle.id]
                ?: throw AndroidKeystoreDonorException.OperationNotFound()
        if (operation.caller != caller) {
            throw AndroidKeystoreDonorException.WrongCaller()
        }
        return operation
    }

    private fun requireActive(
        handle: AndroidKeystoreOperationHandle,
        operation: CoordinatedOperationRecord,
    ) {
        if (coordinator.operations[handle.id] !== operation) {
            throw AndroidKeystoreDonorException.OperationNotFound()
        }
    }

    private fun terminalizeFailedOperation(
        handle: AndroidKeystoreOperationHandle,
        operation: CoordinatedOperationRecord,
        failure: RuntimeException,
    ): Nothing {
        coordinator.operations.remove(handle.id, operation)
        try {
            operation.backendOperation.abort()
        } catch (abortFailure: RuntimeException) {
            failure.addSuppressed(abortFailure)
        }
        throw failure
    }

    private fun abortForDelete(operation: CoordinatedOperationRecord) {
        synchronized(operation) {
            val entry =
                coordinator.operations.entries.firstOrNull { it.value === operation } ?: return
            coordinator.operations.remove(entry.key, operation)
            operation.backendOperation.abort()
        }
    }

    companion object {
        const val MAX_ALIAS_UTF8_BYTES = 255
        const val MAX_ATTESTATION_CHALLENGE_BYTES = 128

        private val KEY_SPEC =
            WireKeySpec(
                WireKeyAlgorithm.EC,
                WireEcCurve.P256,
                WireDigest.SHA256,
                WireKeyPurpose.SIGN,
            )
    }
}
