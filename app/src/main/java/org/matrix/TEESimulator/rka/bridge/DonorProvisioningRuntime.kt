package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.rka.broker.AttestationChallenge
import org.matrix.TEESimulator.rka.broker.AuthenticatedQuarantineRequest
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.QuarantineController
import org.matrix.TEESimulator.rka.broker.QuarantineReceiptStore
import org.matrix.TEESimulator.rka.broker.QuarantineResult
import org.matrix.TEESimulator.rka.broker.RkpKeyCount
import org.matrix.TEESimulator.rka.donor.AndroidDonorKeyMintDevice
import org.matrix.TEESimulator.rka.donor.DonorDispatchAdapter
import org.matrix.TEESimulator.rka.donor.DonorKeyMintBackend
import org.matrix.TEESimulator.rka.journal.DurableIrpcKeyBatchGenerator
import org.matrix.TEESimulator.rka.journal.FileHalCsrJournal
import org.matrix.TEESimulator.rka.journal.FileQuarantineReceiptRegistry
import org.matrix.TEESimulator.rka.journal.FileRkpJournalStore
import org.matrix.TEESimulator.rka.journal.RkpBatchId
import org.matrix.TEESimulator.rka.journal.RkpCertification
import org.matrix.TEESimulator.rka.journal.RkpCertifiedKey
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalState

object DonorProvisioningRuntime {
    private val started = AtomicBoolean()
    private val root = Path.of("/data/adb/teesimulator-rka")
    private val client by lazy(IrpcClient::android)
    private val journal by lazy { RkpJournal(FileRkpJournalStore.production(root)) }
    private val csrJournal by lazy { FileHalCsrJournal(root) }
    private val quarantineReceiptStore by lazy { FileQuarantineReceiptRegistry.production(root) }
    private val donorBackend = lazy {
        val device = AndroidDonorKeyMintDevice.resolve()
        DonorKeyMintBackend(device, journal).also {
            device.onDeath(it::binderDied)
            it.reconcile()
        }
    }
    private var activeRequestId: RequestId? = null
    private var activeCancellation: BrokerCancellation? = null
    private val quarantineController by lazy {
        buildQuarantineController(
            journal,
            quarantineReceiptStore,
            cancel = {
                activeCancellation?.cancel()
                activeCancellation = null
                activeRequestId = null
            },
            cancelled = { activeRequestId == null && activeCancellation == null },
        )
    }

    internal fun buildQuarantineController(
        journal: RkpJournal,
        receipts: QuarantineReceiptStore,
        cancel: () -> Unit,
        cancelled: () -> Boolean,
    ): QuarantineController =
        QuarantineController(
            exactQuarantine = journal::quarantineHandles,
            cancel = cancel,
            cancelled = cancelled,
            discard = journal::discardRetainedBlob,
            discarded = journal::retainedBlobDiscarded,
            wipe = journal::wipeRetainedBlob,
            wiped = journal::retainedBlobWiped,
            receipts = receipts,
            expectedBatch = { journal.recover()?.batchId?.copyBytes() },
            complete = journal::completeQuarantine,
            requireActiveBatch = true,
        )

    fun initializeLifecycle() {
        if (!started.compareAndSet(false, true)) return
        Thread(
                {
                    while (!Thread.currentThread().isInterrupted) {
                        when (val accepted = BrokerBridgeFactory.acceptDonor(::dispatch)) {
                            is BridgeResult.Success -> accepted.value.close()
                            is BridgeResult.Failure -> {
                                if (donorBackend.isInitialized()) donorBackend.value.peerDied()
                                SystemLogger.warning(
                                    "RKA donor bridge exchange failed: ${accepted.error}"
                                )
                            }
                        }
                    }
                },
                "rka-donor-broker",
            )
            .apply { isDaemon = true }
            .start()
    }

    @Synchronized
    private fun dispatch(message: BridgeMessage): BridgeMessage =
        when (message) {
            is BridgeMessage.PublicKeyRequest -> provision(message)
            is BridgeMessage.CertificationRequest -> certify(message)
            is BridgeMessage.CandidateCommand ->
                DonorDispatchAdapter.dispatch(message, donorBackend.value)
            is BridgeMessage.Cancel -> {
                val handles = message.brokerHandles()
                val batchId = message.cleanupBatchId()
                val actionIds = message.cleanupActionIds()
                val result =
                    try {
                        quarantineController.quarantine(
                            if (batchId == null) {
                                AuthenticatedQuarantineRequest.fromTrustedBridge(
                                    message.requestId,
                                    handles.map(Hash32::copyBytes),
                                )
                            } else {
                                AuthenticatedQuarantineRequest.fromTrustedBridge(
                                    message.requestId,
                                    handles.map(Hash32::copyBytes),
                                    batchId,
                                    actionIds,
                                )
                            }
                        )
                    } finally {
                        handles.forEach(Hash32::close)
                        batchId?.close()
                        actionIds.forEach(Hash32::close)
                    }
                if (result == QuarantineResult.QUARANTINED) {
                    BridgeMessage.Cancel(message.requestId)
                } else {
                    failure(message.requestId)
                }
            }
            else -> failure(message.requestId)
        }

    private fun provision(request: BridgeMessage.PublicKeyRequest): BridgeMessage {
        var stage = "CHALLENGE"
        return try {
            val challenge =
                AttestationChallenge.parse(request.challenge.copyBytes()) as? BrokerOutcome.Success
                    ?: return failure(request.requestId)
            activeRequestId = null
            activeCancellation = null
            val deadline = BrokerDeadline.at(BridgeLimits.DEADLINE_MILLIS)
            val cancellation = BrokerCancellation.active()
            activeCancellation = cancellation
            val generator = DurableIrpcKeyBatchGenerator(client, journal)
            stage = "KEY_COUNT"
            val count =
                RkpKeyCount.parse(request.keyCount) as? BrokerOutcome.Success
                    ?: return failure(request.requestId)
            val generatedOutcome =
                generator.generate(count.value, deadline, cancellation) { stage = it }
            val generated =
                generatedOutcome as? BrokerOutcome.Success
                    ?: return rejected(request.requestId, stage, generatedOutcome)
            val batch = generated.value
            stage = "IRPC_CSR"
            val csrOutcome =
                client.generateCertificateRequest(batch, challenge.value, deadline, cancellation)
            val csr =
                csrOutcome as? BrokerOutcome.Success
                    ?: return rejected(request.requestId, stage, csrOutcome).also {
                        journal.quarantineCurrent()
                    }
            stage = "JOURNAL_RECOVER"
            val record = requireNotNull(journal.recover())
            stage = "CSR_PERSIST"
            runCatching {
                    csrJournal.record(record.batchId, csr.value.copyBytes())
                    journal.transition(record, RkpJournalState.CSR_PREPARED)
                }
                .getOrElse {
                    journal.quarantineCurrent()
                    return failure(request.requestId)
                }
            activeRequestId = request.requestId
            stage = "RESPONSE"
            BridgeMessage.PublicKeyResponse(
                request.requestId,
                PublicBytes.of(csr.value.copyBytes(), BridgeLimits.MAX_FRAME_BYTES),
                BrokerBatchId.of(record.batchId.copyBytes()),
                Hash32.of(record.identity.hash()),
                record.entries.map { entry ->
                    BrokerKeyMetadata(
                        entry.order,
                        Hash32.of(entry.handle.copyBytes()),
                        Hash32.of(entry.copyPublicHash()),
                        Hash32.of(entry.copySpkiHash()),
                    )
                },
            )
        } catch (error: RuntimeException) {
            SystemLogger.warning(
                "RKA donor provisioning failed: stage=$stage type=${error.javaClass.simpleName}"
            )
            failure(request.requestId)
        }
    }

    private fun rejected(
        requestId: RequestId,
        stage: String,
        outcome: BrokerOutcome<*>,
    ): BridgeMessage.Error {
        val type =
            when (outcome) {
                is BrokerOutcome.Failure -> outcome.error.javaClass.simpleName
                BrokerOutcome.SelfCallBypass -> "SelfCallBypass"
                is BrokerOutcome.Success -> "UnexpectedSuccess"
            }
        SystemLogger.warning("RKA donor provisioning rejected: stage=$stage type=$type")
        return failure(requestId)
    }

    private fun certify(request: BridgeMessage.CertificationRequest): BridgeMessage {
        val batchBytes = request.batchId.copyBytes()
        val binding = request.activationBindingHash.copyBytes()
        val keys = request.keyMetadata()
        val certification =
            try {
                RkpCertification(
                    request.requestId.value,
                    RkpBatchId.from(batchBytes),
                    keys.map {
                        RkpCertifiedKey(
                            it.order,
                            org.matrix.TEESimulator.rka.journal.RkpOpaqueHandle.from(
                                it.handle.copyBytes()
                            ),
                            it.publicKeyHash.copyBytes(),
                            it.spkiHash.copyBytes(),
                            it.chainHash.copyBytes(),
                            it.certificateCount,
                        )
                    },
                    request.profileEpoch,
                    binding,
                )
            } finally {
                keys.forEach(BrokerCertificationMetadata::close)
            }
        val exact =
            if (activeRequestId == request.requestId) {
                journal.certifyCurrent(certification)
            } else {
                journal.quarantineCurrent()
                false
            }
        if (!exact) {
            activeRequestId = null
            activeCancellation = null
            return failure(request.requestId)
        }
        activeRequestId = null
        activeCancellation = null
        return BridgeMessage.CertificationAck(
            request.requestId,
            BrokerBatchId.of(batchBytes),
            Hash32.of(binding),
        )
    }

    private fun failure(requestId: RequestId): BridgeMessage.Error =
        BridgeMessage.Error(requestId, BridgeErrorCode.POLICY_REJECTED, Hash32.of(ByteArray(32)))
}
