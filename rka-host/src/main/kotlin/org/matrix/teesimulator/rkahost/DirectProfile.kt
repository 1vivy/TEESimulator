package org.matrix.teesimulator.rkahost

import java.time.Duration

enum class DirectPath {
    LAN,
    TAILSCALE,
}

class DirectEndpoint private constructor(val host: String, val port: Int) {
    companion object {
        operator fun invoke(host: String, port: Int): DirectEndpoint {
            require(port in 1..65535) { "DIRECT_ENDPOINT_INVALID" }
            require(host == host.lowercase() && host.isNotEmpty() && host.length <= 253) {
                "DIRECT_ENDPOINT_INVALID"
            }
            val labels = host.split('.')
            require(labels.all { it.matches(Regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?")) }) {
                "DIRECT_ENDPOINT_INVALID"
            }
            if (labels.size == 4 && labels.all { it.all(Char::isDigit) }) {
                require(labels.all { it == "0" || (!it.startsWith('0') && it.toInt() <= 255) }) {
                    "DIRECT_ENDPOINT_INVALID"
                }
            }
            return DirectEndpoint(host, port)
        }
    }

    override fun equals(other: Any?): Boolean =
        other is DirectEndpoint && host == other.host && port == other.port

    override fun hashCode(): Int = 31 * host.hashCode() + port
}

class DirectProfile
private constructor(
    val epoch: Long,
    val path: DirectPath,
    val connect: DirectEndpoint,
    val listenInterface: String,
    private val pin: ByteArray,
    val connectTimeout: Duration,
    val listenTimeout: Duration,
) {
    fun peerSpki(): ByteArray = pin.copyOf()

    companion object {
        fun create(
            epoch: Long,
            path: DirectPath,
            connect: DirectEndpoint,
            listenInterface: String,
            peerSpki: ByteArray,
            connectTimeout: Duration,
            listenTimeout: Duration,
        ): DirectProfile {
            require(epoch > 0) { "DIRECT_PROFILE_EPOCH_INVALID" }
            require(canonicalIpv4(listenInterface) != "0.0.0.0") { "DIRECT_LISTEN_ADDRESS_INVALID" }
            require(peerSpki.size == PIN_BYTES) { "DIRECT_PEER_PIN_INVALID" }
            require(bounded(connectTimeout) && bounded(listenTimeout)) { "DIRECT_TIMEOUT_INVALID" }
            return DirectProfile(
                epoch,
                path,
                connect,
                listenInterface,
                peerSpki.copyOf(),
                connectTimeout,
                listenTimeout,
            )
        }

        private fun bounded(timeout: Duration): Boolean =
            !timeout.isZero && !timeout.isNegative && timeout <= MAX_TIMEOUT

        private fun canonicalIpv4(value: String): String {
            val octets = value.split('.')
            require(octets.size == 4) { "DIRECT_LISTEN_ADDRESS_INVALID" }
            require(octets.all { it.matches(Regex("0|[1-9][0-9]{0,2}")) }) {
                "DIRECT_LISTEN_ADDRESS_INVALID"
            }
            require(octets.all { it.toInt() <= 255 }) { "DIRECT_LISTEN_ADDRESS_INVALID" }
            return octets.joinToString(".")
        }

        private val MAX_TIMEOUT: Duration = Duration.ofSeconds(30)
        private const val PIN_BYTES = 32
    }
}

internal enum class DirectTransportKind {
    DIRECT_PINNED_TLS,
    DIAGNOSTIC_USB,
}

internal data class DirectEvidenceInput(
    val path: DirectPath,
    val connect: DirectEndpoint,
    val listenInterface: String,
    val epoch: Long,
    val peerSpki: ByteArray,
    val transport: DirectTransportKind,
)

private object ReciprocalPinnedTlsAdmission

internal sealed interface DirectProbe {
    data object Unreachable : DirectProbe

    class PinnedTls
    private constructor(
        val evidence: DirectEvidenceInput,
        private val admission: ReciprocalPinnedTlsAdmission,
    ) : DirectProbe {
        companion object {
            fun fromTrusted(input: DirectEvidenceInput): DirectProbe =
                if (input.transport == DirectTransportKind.DIRECT_PINNED_TLS) {
                    PinnedTls(
                        input.copy(peerSpki = input.peerSpki.copyOf()),
                        ReciprocalPinnedTlsAdmission,
                    )
                } else {
                    Unreachable
                }
        }
    }
}

internal object TrustedDirectProbeFactory {
    fun fromPinnedTls(input: DirectEvidenceInput): DirectProbe =
        DirectProbe.PinnedTls.fromTrusted(input)
}

data class UsbDiagnosticEvidence(val kind: DiagnosticTransportKind, val succeeded: Boolean)

enum class DirectReadinessStatus {
    DIRECT_READY,
    DIRECT_NETWORK_BLOCKED,
}

data class DirectReadiness(
    val status: DirectReadinessStatus,
    val diagnosticUsb: UsbDiagnosticEvidence?,
)

internal object DirectReadinessAdapter {
    fun assess(
        profile: DirectProfile,
        probe: DirectProbe,
        usb: UsbDiagnosticEvidence? = null,
    ): DirectReadiness {
        val evidence = (probe as? DirectProbe.PinnedTls)?.evidence
        val ready =
            evidence != null &&
                evidence.path == profile.path &&
                evidence.connect == profile.connect &&
                evidence.listenInterface == profile.listenInterface &&
                evidence.epoch == profile.epoch &&
                evidence.peerSpki.contentEquals(profile.peerSpki()) &&
                evidence.transport == DirectTransportKind.DIRECT_PINNED_TLS &&
                probeHasReciprocalAdmission(probe)
        return DirectReadiness(
            if (ready) DirectReadinessStatus.DIRECT_READY
            else DirectReadinessStatus.DIRECT_NETWORK_BLOCKED,
            usb,
        )
    }
}

private fun probeHasReciprocalAdmission(probe: DirectProbe): Boolean =
    (probe as? DirectProbe.PinnedTls) != null

class DirectProfileRotation(initial: DirectProfile) {
    var active: DirectProfile = initial
        private set

    private var prepared: DirectProfile? = null

    fun prepare(next: DirectProfile) {
        require(next.path == active.path && next.epoch > active.epoch) { "DIRECT_ROTATION_INVALID" }
        require(!next.peerSpki().contentEquals(active.peerSpki())) { "DIRECT_ROTATION_INVALID" }
        prepared = next
    }

    fun activate() {
        active = requireNotNull(prepared) { "DIRECT_ROTATION_INVALID" }
        prepared = null
    }
}

object DirectProfileSelector {
    fun select(profiles: List<DirectProfile>, path: DirectPath): DirectProfile {
        val candidates = profiles.filter { it.path == path }
        val newest = candidates.maxOfOrNull { it.epoch } ?: error("DIRECT_PROFILE_MISSING")
        require(candidates.count { it.epoch == newest } == 1) { "DIRECT_PROFILE_AMBIGUOUS" }
        return candidates.first { it.epoch == newest }
    }
}
