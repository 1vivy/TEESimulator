package org.matrix.TEESimulator.rka.donor

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.ATTESTATION_OID
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.IrpcGeneratedKey
import org.matrix.TEESimulator.rka.broker.IrpcKeyBatch
import org.matrix.TEESimulator.rka.broker.IrpcResolvedIdentity
import org.matrix.TEESimulator.rka.broker.RkpKeyCount
import org.matrix.TEESimulator.rka.candidate.IdentityHash
import org.matrix.TEESimulator.rka.journal.RkpCertification
import org.matrix.TEESimulator.rka.journal.RkpCertifiedKey
import org.matrix.TEESimulator.rka.journal.RkpIrpcIdentity
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalRecord
import org.matrix.TEESimulator.rka.journal.RkpJournalState
import org.matrix.TEESimulator.rka.journal.RkpJournalStore
import org.matrix.TEESimulator.rka.journal.RkpOpaqueHandle

internal val donorTestCandidate = IdentityHash.of(ByteArray(32) { 0x2a })

internal fun DonorKeyMintBackend.generate(request: DonorGenerateRequest) =
    generate(donorTestCandidate, request)

internal fun DonorKeyMintBackend.get(handle: DonorKeyHandle) = get(donorTestCandidate, handle)

internal fun DonorKeyMintBackend.list() = list(donorTestCandidate)

internal fun DonorKeyMintBackend.delete(handle: DonorKeyHandle) = delete(donorTestCandidate, handle)

internal fun DonorKeyMintBackend.begin(handle: DonorKeyHandle) = begin(donorTestCandidate, handle)

internal fun DonorKeyMintBackend.updateAad(handle: DonorOperationHandle, input: ByteArray) =
    updateAad(donorTestCandidate, handle, input)

internal fun DonorKeyMintBackend.update(handle: DonorOperationHandle, input: ByteArray) =
    update(donorTestCandidate, handle, input)

internal fun DonorKeyMintBackend.finish(handle: DonorOperationHandle, input: ByteArray) =
    finish(donorTestCandidate, handle, input)

internal fun DonorKeyMintBackend.abort(handle: DonorOperationHandle) =
    abort(donorTestCandidate, handle)

internal class DonorFixture {
    val challenge = ByteArray(32) { (it + 1).toByte() }
    val aaid = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
    val transcript = "bound donor transcript".toByteArray()
    val alias = DonorKeyHandle.of(ByteArray(16) { (it + 40).toByte() })
    val rootKey = ecKey()
    val rkpKey = ecKey()
    val rootCertificate =
        certificate(
            subject = "CN=Task20 Root",
            issuer = "CN=Task20 Root",
            publicKey = rootKey,
            signer = rootKey,
            serial = 1,
            usage = KeyUsage.keyCertSign,
        )
    val rkpCertificate =
        certificate(
            subject = "CN=Task20 RKP Subject",
            issuer = "CN=Task20 Root",
            publicKey = rkpKey,
            signer = rootKey,
            serial = 2,
            usage = KeyUsage.digitalSignature,
        )
    val chain = listOf(rkpCertificate.encoded, rootCertificate.encoded)
    val journal = RkpJournal(MemoryDonorJournalStore())
    val certified: RkpJournalRecord
    val rkpHandle: RkpOpaqueHandle

    init {
        val identity =
            IrpcResolvedIdentity(
                "android.hardware.security.keymint.IRemotelyProvisionedComponent",
                "android.hardware.security.keymint.IRemotelyProvisionedComponent/default",
                "TEE",
                "task20-irpc",
                3,
            )
        val batch =
            IrpcKeyBatch(
                identity,
                listOf(
                    IrpcGeneratedKey(byteArrayOf(1), rkpKey.public.encoded, ByteArray(32) { 0x5a })
                ),
            )
        val count = (RkpKeyCount.parse(1) as BrokerOutcome.Success).value
        val intent = journal.begin(count, RkpIrpcIdentity.from(identity))
        val entries = journal.deriveEntries(intent, batch.publicKeys().zip(batch.spkiPublicKeys()))
        batch.recordInJournal(journal, intent, entries)
        val prepared =
            journal.transition(requireNotNull(journal.recover()), RkpJournalState.CSR_PREPARED)
        val chainHash = sha256(chain.reduce(ByteArray::plus))
        val requestId = 20L
        val certification =
            RkpCertification(
                requestId,
                prepared.batchId,
                listOf(
                    RkpCertifiedKey(
                        0,
                        prepared.entries.single().handle,
                        prepared.entries.single().copyPublicHash(),
                        prepared.entries.single().copySpkiHash(),
                        chainHash,
                        chain.size,
                    )
                ),
                8,
                activationBinding(prepared, requestId, chainHash, chain.size, 8),
            )
        check(journal.certifyCurrent(certification))
        certified = requireNotNull(journal.recover())
        rkpHandle = certified.entries.single().handle
    }

    fun request(
        chain: List<ByteArray> = this.chain,
        challenge: ByteArray = this.challenge,
        aaid: ByteArray = this.aaid,
    ): DonorGenerateRequest =
        DonorGenerateRequest(alias, rkpHandle, chain, challenge, aaid, transcript)

    private fun activationBinding(
        record: RkpJournalRecord,
        requestId: Long,
        chainHash: ByteArray,
        certificateCount: Int,
        epoch: Long,
    ): ByteArray {
        val entry = record.entries.single()
        val lease = MessageDigest.getInstance("SHA-256")
        lease.update("TEESimulator-RS activation v1\u0000".toByteArray())
        lease.update("lease".toByteArray())
        lease.update(
            ByteBuffer.allocate(Long.SIZE_BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(requestId)
                .array()
        )
        lease.update(entry.copySpkiHash())
        return MessageDigest.getInstance("SHA-256")
            .apply {
                update(lease.digest().copyOf(16))
                update(record.batchId.copyBytes())
                update(entry.order.toByte())
                update(entry.copyPublicHash())
                update(entry.copySpkiHash())
                update(chainHash)
                update(certificateCount.toByte())
                update(
                    ByteBuffer.allocate(Long.SIZE_BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putLong(epoch)
                        .array()
                )
            }
            .digest()
    }
}

internal class FakeDonorKeyMintDevice(private val fixture: DonorFixture) : DonorKeyMintDevice {
    var generateCalls = 0
    var importSyntheticLeaseCalls = 0
    var exposureCalls = 0
    var deleteCalls = 0
    var beginCalls = 0
    var updateAadCalls = 0
    var updateCalls = 0
    var finishCalls = 0
    var abortCalls = 0
    var failGenerate = false
    var wrongAaid = false
    var wrongChallenge = false
    var wrongIssuer = false
    var wrongSignature = false
    var wrongCharacteristics = false
    var wrongSpki = false
    var failUpdate = false
    var lastAttestationKey: DonorAttestationKey? = null
    var lastParameters: DonorKeyParameters? = null
    var syntheticLeaseKey: KeyPair? = null
    private var applicationKey: KeyPair? = null

    override fun generate(
        parameters: DonorKeyParameters,
        attestationKey: DonorAttestationKey,
    ): DonorKeyCreation {
        generateCalls += 1
        lastParameters = parameters
        lastAttestationKey = attestationKey
        if (failGenerate) throw IllegalStateException("ambiguous KeyMint generation")
        val key = ecKey()
        applicationKey = key
        val certificateKey = if (wrongSpki) ecKey() else key
        val issuer = if (wrongIssuer) "CN=Wrong Issuer" else "CN=Task20 RKP Subject"
        val signer = if (wrongIssuer || wrongSignature) fixture.rootKey else fixture.rkpKey
        val leaf =
            attestedCertificate(
                certificateKey,
                signer,
                issuer,
                if (wrongChallenge) ByteArray(32) { 99 } else parameters.challenge,
                if (wrongAaid) byteArrayOf(1, 2, 3) else parameters.aaid,
            )
        val characteristics =
            DonorKeyCharacteristics.exact().let {
                if (wrongCharacteristics) it.copy(curve = DonorCurve.P384) else it
            }
        return DonorKeyCreation(ByteArray(32) { 0x6b }, characteristics, listOf(leaf.encoded))
    }

    override fun importSyntheticLease(
        parameters: DonorSyntheticLeaseParameters,
        privateKeyPkcs8: DonorSecretBytes,
        attestationKey: DonorAttestationKey,
    ): DonorSyntheticLeaseCreation {
        importSyntheticLeaseCalls += 1
        val key = requireNotNull(syntheticLeaseKey)
        val supplied = privateKeyPkcs8.copyBytes()
        try {
            require(supplied.contentEquals(key.private.encoded))
        } finally {
            supplied.fill(0)
        }
        val leaf =
            attestedCertificate(
                key,
                fixture.rkpKey,
                fixture.rkpCertificate.subjectX500Principal.name,
                parameters.challenge,
                parameters.aaid,
                attestKey = true,
            )
        return DonorSyntheticLeaseCreation(
            ByteArray(32) { 0x7c },
            DonorSyntheticLeaseCharacteristics.exact(),
            listOf(leaf.encoded),
        )
    }

    override fun begin(keyBlob: ByteArray): DonorOperationEndpoint {
        beginCalls += 1
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(requireNotNull(applicationKey).private)
        return object : DonorOperationEndpoint {
            override fun updateAad(input: ByteArray) {
                updateAadCalls += 1
            }

            override fun update(input: ByteArray): ByteArray {
                updateCalls += 1
                if (failUpdate) throw IllegalStateException("operation failed")
                signature.update(input)
                return ByteArray(0)
            }

            override fun finish(input: ByteArray): ByteArray {
                finishCalls += 1
                signature.update(input)
                return signature.sign()
            }

            override fun abort() {
                abortCalls += 1
            }
        }
    }

    override fun delete(keyBlob: ByteArray) {
        deleteCalls += 1
        applicationKey = null
    }
}

private class MemoryDonorJournalStore : RkpJournalStore {
    private var value: ByteArray? = null

    override fun read(): ByteArray? = value?.copyOf()

    override fun replace(value: ByteArray) {
        this.value = value.copyOf()
    }
}

internal fun ecKey(): KeyPair =
    KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

private fun certificate(
    subject: String,
    issuer: String,
    publicKey: KeyPair,
    signer: KeyPair,
    serial: Long,
    usage: Int,
): X509Certificate {
    val now = Instant.now()
    val builder =
        JcaX509v3CertificateBuilder(
            X500Name(issuer),
            BigInteger.valueOf(serial),
            Date.from(now.minusSeconds(60)),
            Date.from(now.plusSeconds(3_600)),
            X500Name(subject),
            publicKey.public,
        )
    builder.addExtension(Extension.keyUsage, true, KeyUsage(usage))
    return JcaX509CertificateConverter()
        .getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private))
        )
}

private fun attestedCertificate(
    key: KeyPair,
    signer: KeyPair,
    issuer: String,
    challenge: ByteArray,
    aaid: ByteArray,
    attestKey: Boolean = false,
): X509Certificate {
    val now = Instant.now()
    val description =
        DERSequence(
            arrayOf(
                ASN1Integer(400),
                ASN1Enumerated(1),
                ASN1Integer(400),
                ASN1Enumerated(1),
                DEROctetString(challenge),
                DEROctetString(ByteArray(0)),
                DERSequence(arrayOf(DERTaggedObject(true, 709, DEROctetString(aaid)))),
                if (attestKey) {
                    DERSequence(
                        arrayOf(
                            DERTaggedObject(true, 1, DERSet(ASN1Integer(7))),
                            DERTaggedObject(true, 503, org.bouncycastle.asn1.DERNull.INSTANCE),
                            DERTaggedObject(true, 702, ASN1Integer(2)),
                        )
                    )
                } else {
                    DERSequence()
                },
            )
        )
    val builder =
        JcaX509v3CertificateBuilder(
            X500Name(issuer),
            BigInteger.valueOf(30),
            Date.from(now.minusSeconds(60)),
            Date.from(now.plusSeconds(3_600)),
            X500Name("CN=Task20 Foreground"),
            key.public,
        )
    builder.addExtension(ATTESTATION_OID, false, description)
    builder.addExtension(
        Extension.keyUsage,
        true,
        KeyUsage(if (attestKey) KeyUsage.keyCertSign else KeyUsage.digitalSignature),
    )
    if (attestKey) builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
    return JcaX509CertificateConverter()
        .getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private))
        )
}

internal fun sha256(value: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(value)
