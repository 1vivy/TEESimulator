package org.matrix.TEESimulator.rka.bridge

import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.rka.broker.AttestationChallenge
import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.RkpKeyCount
import org.matrix.TEESimulator.rka.journal.DurableIrpcKeyBatchGenerator
import org.matrix.TEESimulator.rka.journal.FileHalCsrJournal
import org.matrix.TEESimulator.rka.journal.FileRkpJournalStore
import org.matrix.TEESimulator.rka.journal.RkpBatchId
import org.matrix.TEESimulator.rka.journal.RkpCertification
import org.matrix.TEESimulator.rka.journal.RkpCertifiedKey
import org.matrix.TEESimulator.rka.journal.RkpJournal
import org.matrix.TEESimulator.rka.journal.RkpJournalState

object DonorProvisioningRuntime {
    private val started = AtomicBoolean()
    private val root = Path.of("/data/adb/teesimulator-rka/state")
    private val client by lazy(IrpcClient::android)
    private val journal by lazy { RkpJournal(FileRkpJournalStore.production(root)) }
    private val csrJournal by lazy { FileHalCsrJournal(root) }
    private var activeRequestId: RequestId? = null

    fun initializeLifecycle() {
        if (!started.compareAndSet(false, true)) return
        Thread(
                {
                    while (!Thread.currentThread().isInterrupted) {
                        when (val accepted = BrokerBridgeFactory.acceptDonor(::dispatch)) {
                            is BridgeResult.Success -> accepted.value.close()
                            is BridgeResult.Failure ->
                                SystemLogger.warning("RKA donor bridge exchange failed: ${accepted.error}")
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
            is BridgeMessage.Cancel -> {
                activeRequestId = null
                val handles = message.brokerHandles()
                val exact =
                    try {
                        if (handles.isEmpty()) {
                            journal.quarantineCurrent()
                            true
                        } else {
                            journal.quarantineHandles(handles.map(Hash32::copyBytes))
                        }
                    } finally {
                        handles.forEach(Hash32::close)
                    }
                if (exact) BridgeMessage.Cancel(message.requestId) else failure(message.requestId)
            }
            else -> failure(message.requestId)
        }

    private fun provision(request: BridgeMessage.PublicKeyRequest): BridgeMessage {
        val challenge =
            AttestationChallenge.parse(request.challenge.copyBytes()) as? BrokerOutcome.Success
                ?: return failure(request.requestId)
        activeRequestId = null
        val deadline = BrokerDeadline.at(BridgeLimits.DEADLINE_MILLIS)
        val cancellation = BrokerCancellation.active()
        val generator = DurableIrpcKeyBatchGenerator(client, journal)
        val count =
            RkpKeyCount.parse(request.keyCount) as? BrokerOutcome.Success
                ?: return failure(request.requestId)
        val generated =
            generator.generate(count.value, deadline, cancellation)
                as? BrokerOutcome.Success ?: return failure(request.requestId)
        val batch = generated.value
        val csr =
            client.generateCertificateRequest(batch, challenge.value, deadline, cancellation)
                as? BrokerOutcome.Success
                ?: return failure(request.requestId).also { journal.quarantineCurrent() }
        val record = requireNotNull(journal.recover())
        runCatching {
                csrJournal.record(record.batchId, csr.value.copyBytes())
                journal.transition(record, RkpJournalState.CSR_PREPARED)
            }
            .getOrElse {
                journal.quarantineCurrent()
                return failure(request.requestId)
            }
        activeRequestId = request.requestId
        return BridgeMessage.PublicKeyResponse(
            request.requestId,
            PublicBytes.of(csr.value.copyBytes(), BridgeLimits.MAX_FRAME_BYTES),
            BrokerBatchId.of(record.batchId.copyBytes()),
            record.entries.map { entry ->
                BrokerKeyMetadata(
                    entry.order,
                    Hash32.of(entry.handle.copyBytes()),
                    Hash32.of(entry.copyPublicHash()),
                    Hash32.of(entry.copySpkiHash()),
                )
            },
        )
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
            return failure(request.requestId)
        }
        activeRequestId = null
        return BridgeMessage.CertificationAck(
            request.requestId,
            BrokerBatchId.of(batchBytes),
            Hash32.of(binding),
        )
    }

    private fun failure(requestId: RequestId): BridgeMessage.Error =
        BridgeMessage.Error(
            requestId,
            BridgeErrorCode.POLICY_REJECTED,
            Hash32.of(ByteArray(32)),
        )
}
