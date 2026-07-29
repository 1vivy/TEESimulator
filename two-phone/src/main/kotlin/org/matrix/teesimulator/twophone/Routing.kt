package org.matrix.teesimulator.twophone

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

enum class SecurityLevel {
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    AVF,
}

enum class RouteDecision {
    REMOTE,
    PLATFORM_BYTE_FOR_BYTE,
}

data class RouteRequest(
    val securityLevel: SecurityLevel,
    val attested: Boolean,
    val caller: CallerIdentity,
    val purpose: String,
    val challenge: ByteArray,
    val userAuthenticationRequired: Boolean,
    val deviceLocalSemantics: Boolean,
    val platformParcel: ByteArray,
) {
    companion object {
        fun trustedAttested(caller: CallerIdentity, purpose: String, challenge: ByteArray) =
            RouteRequest(
                SecurityLevel.TRUSTED_ENVIRONMENT,
                true,
                caller,
                purpose,
                challenge,
                false,
                false,
                byteArrayOf(0x4b, 0x4d, 0x54),
            )
    }
}

data class RoutingPolicy(val allowlistedUids: Set<Int>, val allowlistedPurposes: Set<String>)

sealed class RoutingException(message: String) : RuntimeException(message) {
    class UnsupportedLocalSemantics : RoutingException("device-local/user-auth semantics rejected")

    class DonorUnavailable : RoutingException("routed donor unavailable; fail closed")
}

interface DonorTransport {
    fun generate(request: GenerateRequest): GeneratedKey

    fun metadata(handle: KeyHandle, caller: CallerIdentity): KeyMetadata
}

class FakePinnedTransport(private val pins: PairIdentity, private val donor: FakeDonorAdapter) :
    DonorTransport {
    var available = true

    override fun generate(request: GenerateRequest): GeneratedKey {
        if (!available) throw RoutingException.DonorUnavailable()
        return donor.forPresentedPair(pins).generate(request)
    }

    override fun metadata(handle: KeyHandle, caller: CallerIdentity): KeyMetadata {
        if (!available) throw RoutingException.DonorUnavailable()
        return donor.forPresentedPair(pins).metadata(handle, caller)
    }
}

/**
 * Host-testable policy seam intended for KeyMintSecurityLevelInterceptor. It never interprets a
 * platform parcel on pass-through paths and has no software/keybox fallback.
 */
class KeyMintSecurityLevelRoutingSeam(
    private val policy: RoutingPolicy,
    private val transport: DonorTransport,
) {
    val localFallbackCount: Int
        get() = 0

    fun decide(request: RouteRequest): RouteDecision {
        val remoteEligible =
            request.securityLevel == SecurityLevel.TRUSTED_ENVIRONMENT &&
                request.attested &&
                request.caller.uid in policy.allowlistedUids &&
                request.purpose in policy.allowlistedPurposes
        if (!remoteEligible) {
            return RouteDecision.PLATFORM_BYTE_FOR_BYTE
        }
        if (request.userAuthenticationRequired || request.deviceLocalSemantics) {
            throw RoutingException.UnsupportedLocalSemantics()
        }
        return RouteDecision.REMOTE
    }

    fun platformBytes(request: RouteRequest): ByteArray {
        check(decide(request) == RouteDecision.PLATFORM_BYTE_FOR_BYTE)
        return request.platformParcel
    }

    fun generate(request: RouteRequest, logicalName: String): GeneratedKey {
        check(decide(request) == RouteDecision.REMOTE)
        return transport.generate(GenerateRequest(logicalName, request.challenge, request.caller))
    }
}

class InMemoryTargetStore {
    internal val states = ConcurrentHashMap<UUID, KeyState>()
}

class TargetCoordinator(
    private val pair: PairIdentity,
    private val caller: CallerIdentity,
    private val donor: FakeDonorAdapter,
    private val store: InMemoryTargetStore,
) {
    fun reconcile() {
        donor.forPresentedPair(pair).allMetadata().forEach { (handle, state) ->
            store.states[handle.id] = state
        }
    }

    fun stateOf(handle: KeyHandle): KeyState = store.states[handle.id] ?: KeyState.ABSENT
}
