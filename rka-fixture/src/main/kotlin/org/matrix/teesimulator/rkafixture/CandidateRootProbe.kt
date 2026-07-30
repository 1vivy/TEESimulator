package org.matrix.teesimulator.rkafixture

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.Date
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

object CandidateRootProbe {
    const val ALIAS = "teesim_rka_candidate_probe_v1"
    private const val WATCHDOG_MILLIS = 30_000L
    private val stagingDirectory = Path.of("/data/local/tmp/teesim-rka-candidate-probe")
    private val approvedProfile = Path.of("/data/adb/tricky_store/rka-candidate-owner.conf")

    @JvmStatic
    fun main(arguments: Array<String>) {
        val action = arguments.singleOrNull()
        when (action) {
            "pre" -> emit(runBounded(createIdentity = true, rebootPhase = "PRE"))
            "post" -> emit(runBounded(createIdentity = false, rebootPhase = "POST"))
            "cleanup" -> {
                keyStore().deleteEntry(ALIAS)
                stagingDirectory.toFile().deleteRecursively()
                println("CLEANUP=ALIAS_AND_STAGING_REMOVED")
            }
            "persist-root-profile" -> {
                persistProfile(CandidateIdentityOwner.ROOT_DAEMON)
                println("PROFILE=VERSION_1_ROOT_DAEMON")
            }
            "persist-companion-profile" -> {
                persistProfile(CandidateIdentityOwner.CANDIDATE_COMPANION)
                println("PROFILE=VERSION_1_CANDIDATE_COMPANION")
            }
            else -> {
                println("PROVEN=false")
                println("ERROR_CODE=ARGUMENT_INVALID")
            }
        }
    }

    internal fun runCompanion(createIdentity: Boolean, rebootPhase: String, staging: Path): String =
        encode(
            runBounded(
                createIdentity,
                rebootPhase,
                staging,
                CandidateIdentityOwner.CANDIDATE_COMPANION.name,
            )
        )

    internal fun cleanupCompanion(staging: Path) {
        keyStore().deleteEntry(ALIAS)
        staging.toFile().deleteRecursively()
    }

    private fun runBounded(
        createIdentity: Boolean,
        rebootPhase: String,
        staging: Path = stagingDirectory,
        owner: String = CandidateIdentityOwner.ROOT_DAEMON.name,
    ): ProbeReceipt {
        val executor = Executors.newSingleThreadExecutor()
        val started = System.nanoTime()
        return try {
            val future =
                executor.submit(Callable { prove(createIdentity, rebootPhase, staging, owner) })
            val proof = future.get(WATCHDOG_MILLIS, TimeUnit.MILLISECONDS)
            proof.copy(watchdogLatencyMillis = elapsedMillis(started))
        } catch (failure: Throwable) {
            val typed = failure.findProbeFailure()
            ProbeReceipt.failed(
                errorCode =
                    when {
                        failure.cause is java.util.concurrent.TimeoutException ||
                            failure is java.util.concurrent.TimeoutException -> "WATCHDOG_TIMEOUT"
                        typed != null -> typed.code
                        else -> failure.rootCause().javaClass.simpleName.uppercase()
                    },
                rebootPhase = rebootPhase,
                latency = elapsedMillis(started),
                owner = owner,
                detail =
                    failure
                        .rootCause()
                        .message
                        ?.uppercase()
                        ?.replace(Regex("[^A-Z0-9_.:-]"), "_")
                        ?.take(160),
            )
        } finally {
            executor.shutdownNow()
        }
    }

    private fun prove(
        createIdentity: Boolean,
        rebootPhase: String,
        staging: Path,
        owner: String,
    ): ProbeReceipt {
        val store =
            try {
                keyStore()
            } catch (failure: Throwable) {
                throw ProbeFailure("KEYSTORE_PROVIDER_UNAVAILABLE", failure)
            }
        val states = mutableListOf<CandidateGateState>()
        var generateCount = 0
        if (createIdentity) {
            check(!store.containsAlias(ALIAS)) { "ALIAS_PREEXISTS" }
            try {
                generateIdentity()
            } catch (failure: Throwable) {
                throw ProbeFailure("IDENTITY_GENERATION_PROVIDER_FAILED", failure)
            }
            generateCount = 1
        } else {
            check(store.containsAlias(ALIAS)) { "ALIAS_MISSING_AFTER_REBOOT" }
        }
        states += CandidateGateState.IDENTITY_CREATED

        val privateKey = requireNotNull(store.getKey(ALIAS, null) as? PrivateKey)
        val certificate = requireNotNull(store.getCertificate(ALIAS) as? X509Certificate)
        val keyInfo =
            try {
                KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    .getKeySpec(privateKey, KeyInfo::class.java)
            } catch (failure: Throwable) {
                throw ProbeFailure("KEY_INFO_PROVIDER_FAILED", failure)
            }
        val encodedNull = privateKey.encoded == null
        val hardware = keyInfo.isInsideSecureHardware
        val tee = keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        val ecP256 =
            privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC && keyInfo.keySize == 256
        check(encodedNull) { "PRIVATE_KEY_EXPORTABLE" }
        check(hardware) { "SOFTWARE_KEY" }
        check(tee) { "SECURITY_LEVEL_NOT_TEE" }
        check(ecP256) { "KEY_NOT_EC_P256" }

        Files.createDirectories(staging)
        Files.write(staging.resolve("public-trust.der"), certificate.encoded)
        states += CandidateGateState.PUBLIC_TRUST_STAGED
        Files.write(
            staging.resolve("profile.conf"),
            "version=1\nowner=$owner\n".encodeToByteArray(),
        )
        states += CandidateGateState.PROFILE_STAGED
        val tls =
            try {
                provePinnedMutualTls(store, certificate, states)
            } catch (failure: Throwable) {
                throw ProbeFailure("TLS_PROOF_PROVIDER_FAILED", failure)
            }
        states += CandidateGateState.TLS_PROVED
        states += CandidateGateState.ACTIVE
        return ProbeReceipt(
            owner = owner,
            proven = true,
            stateSequence = states.joinToString(",") { it.name },
            privateKeyEncodedNull = true,
            insideSecurityHardware = true,
            teeSecurityLevel = true,
            ecP256 = true,
            tlsProtocol = tls.protocol,
            clientCertificateRequired = tls.clientAuthenticated,
            pinnedPeer = tls.pinned,
            candidateLocalGenerateCount = generateCount,
            watchdogLatencyMillis = 0,
            watchdogTimedOut = false,
            rebootPhase = rebootPhase,
            errorCode = null,
        )
    }

    private fun generateIdentity() {
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val now = System.currentTimeMillis()
        generator.initialize(
            KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY,
                )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                .setCertificateSubject(X500Principal("CN=TEESimulator Candidate Probe"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(Date(now - Duration.ofDays(1).toMillis()))
                .setCertificateNotAfter(Date(now + Duration.ofDays(30).toMillis()))
                .build()
        )
        generator.generateKeyPair()
    }

    private fun provePinnedMutualTls(
        store: KeyStore,
        certificate: X509Certificate,
        states: MutableList<CandidateGateState>,
    ): TlsProof {
        val keyManagers = arrayOf<KeyManager>(PinnedKeyManager(store, certificate))
        val trustManagers = arrayOf<TrustManager>(PinnedTrustManager(certificate))
        val serverContext =
            SSLContext.getInstance("TLS").apply { init(keyManagers, trustManagers, null) }
        val clientContext =
            SSLContext.getInstance("TLS").apply { init(keyManagers, trustManagers, null) }
        val server =
            (serverContext.serverSocketFactory.createServerSocket(
                    0,
                    1,
                    InetAddress.getLoopbackAddress(),
                ) as SSLServerSocket)
                .apply {
                    enabledProtocols = arrayOf("TLSv1.3")
                    needClientAuth = true
                }
        states += CandidateGateState.LISTENER_READY
        val workers = Executors.newSingleThreadExecutor()
        return try {
            val accepted =
                workers.submit(
                    Callable {
                        (server.accept() as SSLSocket).use { socket ->
                            socket.enabledProtocols = arrayOf("TLSv1.3")
                            socket.startHandshake()
                            TlsProof(
                                socket.session.protocol,
                                socket.session.peerCertificates.isNotEmpty(),
                                true,
                            )
                        }
                    }
                )
            try {
                (clientContext.socketFactory.createSocket(
                        InetAddress.getLoopbackAddress(),
                        server.localPort,
                    ) as SSLSocket)
                    .use { socket ->
                        socket.enabledProtocols = arrayOf("TLSv1.3")
                        socket.startHandshake()
                        check(socket.session.protocol == "TLSv1.3") { "TLS_VERSION_INVALID" }
                    }
            } catch (clientFailure: Throwable) {
                try {
                    accepted.get(2, TimeUnit.SECONDS)
                } catch (serverFailure: Throwable) {
                    throw serverFailure
                }
                throw clientFailure
            }
            accepted.get(10, TimeUnit.SECONDS)
        } finally {
            server.close()
            workers.shutdownNow()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun persistProfile(owner: CandidateIdentityOwner) {
        Files.createDirectories(requireNotNull(approvedProfile.parent))
        val temporary = approvedProfile.resolveSibling("${approvedProfile.fileName}.tmp")
        Files.write(temporary, "version=1\nowner=${owner.name}\n".encodeToByteArray())
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------"))
        Files.move(
            temporary,
            approvedProfile,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    private fun elapsedMillis(started: Long): Long =
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

    private fun Throwable.rootCause(): Throwable {
        var result = this
        while (result.cause != null && result.cause !== result) result = result.cause!!
        return result
    }

    private fun Throwable.findProbeFailure(): ProbeFailure? {
        var current: Throwable? = this
        while (current != null) {
            if (current is ProbeFailure) return current
            current = current.cause
        }
        return null
    }

    private fun emit(receipt: ProbeReceipt) = print(encode(receipt))

    private fun encode(receipt: ProbeReceipt): String = buildString {
        appendLine("SCHEMA_VERSION=1")
        appendLine("OWNER=${receipt.owner}")
        appendLine("PROVEN=${receipt.proven}")
        appendLine("STATE_SEQUENCE=${receipt.stateSequence}")
        appendLine("PRIVATE_KEY_ENCODED_NULL=${receipt.privateKeyEncodedNull}")
        appendLine("INSIDE_SECURITY_HARDWARE=${receipt.insideSecurityHardware}")
        appendLine("TEE_SECURITY_LEVEL=${receipt.teeSecurityLevel}")
        appendLine("EC_P256=${receipt.ecP256}")
        appendLine("TLS_PROTOCOL=${receipt.tlsProtocol}")
        appendLine("CLIENT_CERT_REQUIRED=${receipt.clientCertificateRequired}")
        appendLine("PINNED_PEER=${receipt.pinnedPeer}")
        appendLine("CANDIDATE_LOCAL_GENERATE_COUNT=${receipt.candidateLocalGenerateCount}")
        appendLine("WATCHDOG_LATENCY_MILLIS=${receipt.watchdogLatencyMillis}")
        appendLine("WATCHDOG_TIMED_OUT=${receipt.watchdogTimedOut}")
        appendLine("REBOOT_PHASE=${receipt.rebootPhase}")
        receipt.errorCode?.let { appendLine("ERROR_CODE=$it") }
        receipt.errorDetail?.let { appendLine("ERROR_DETAIL=$it") }
    }

    private data class TlsProof(
        val protocol: String,
        val clientAuthenticated: Boolean,
        val pinned: Boolean,
    )

    private class ProbeFailure(val code: String, cause: Throwable) : RuntimeException(code, cause)

    private data class ProbeReceipt(
        val owner: String,
        val proven: Boolean,
        val stateSequence: String,
        val privateKeyEncodedNull: Boolean,
        val insideSecurityHardware: Boolean,
        val teeSecurityLevel: Boolean,
        val ecP256: Boolean,
        val tlsProtocol: String,
        val clientCertificateRequired: Boolean,
        val pinnedPeer: Boolean,
        val candidateLocalGenerateCount: Int,
        val watchdogLatencyMillis: Long,
        val watchdogTimedOut: Boolean,
        val rebootPhase: String,
        val errorCode: String?,
        val errorDetail: String? = null,
    ) {
        companion object {
            fun failed(
                errorCode: String,
                rebootPhase: String,
                latency: Long,
                owner: String,
                detail: String?,
            ) =
                ProbeReceipt(
                    owner,
                    false,
                    "",
                    false,
                    false,
                    false,
                    false,
                    "",
                    false,
                    false,
                    0,
                    latency,
                    errorCode == "WATCHDOG_TIMEOUT",
                    rebootPhase,
                    errorCode,
                    detail,
                )
        }
    }

    private class PinnedKeyManager(
        private val store: KeyStore,
        private val certificate: X509Certificate,
    ) : X509ExtendedKeyManager() {
        override fun chooseClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            socket: java.net.Socket?,
        ) = ALIAS

        override fun chooseEngineClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            engine: SSLEngine?,
        ) = ALIAS

        override fun chooseServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            socket: java.net.Socket?,
        ) = ALIAS

        override fun chooseEngineServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            engine: SSLEngine?,
        ) = ALIAS

        override fun getCertificateChain(alias: String?) = arrayOf(certificate)

        override fun getPrivateKey(alias: String?) = store.getKey(ALIAS, null) as PrivateKey

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) =
            arrayOf(ALIAS)

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) =
            arrayOf(ALIAS)
    }

    private class PinnedTrustManager(certificate: X509Certificate) : X509TrustManager {
        private val pin = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            checkPinned(chain)

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            checkPinned(chain)

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

        private fun checkPinned(chain: Array<out X509Certificate>?) {
            val leaf = requireNotNull(chain?.firstOrNull()) { "TLS_PEER_CERT_MISSING" }
            check(MessageDigest.getInstance("SHA-256").digest(leaf.encoded).contentEquals(pin)) {
                "TLS_PIN_MISMATCH"
            }
        }
    }
}
