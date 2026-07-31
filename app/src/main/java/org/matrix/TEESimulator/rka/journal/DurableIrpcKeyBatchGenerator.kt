package org.matrix.TEESimulator.rka.journal

import org.matrix.TEESimulator.rka.broker.BrokerCancellation
import org.matrix.TEESimulator.rka.broker.BrokerDeadline
import org.matrix.TEESimulator.rka.broker.BrokerOutcome
import org.matrix.TEESimulator.rka.broker.IrpcClient
import org.matrix.TEESimulator.rka.broker.IrpcKeyBatch
import org.matrix.TEESimulator.rka.broker.RkpKeyCount

class DurableIrpcKeyBatchGenerator(
    private val client: IrpcClient,
    private val journal: RkpJournal,
) {
    fun generate(
        count: RkpKeyCount,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
    ): BrokerOutcome<IrpcKeyBatch> {
        val identity =
            when (val resolved = client.resolveIdentity(deadline, cancellation)) {
                is BrokerOutcome.Success -> resolved.value
                is BrokerOutcome.Failure -> return resolved
                BrokerOutcome.SelfCallBypass -> return BrokerOutcome.SelfCallBypass
            }
        val intent = journal.begin(count, RkpIrpcIdentity.from(identity))
        val outcome = client.generateKeyBatch(count, identity, deadline, cancellation)
        if (outcome is BrokerOutcome.Success) {
            val entries =
                journal.deriveEntries(
                    intent,
                    outcome.value.publicKeys().zip(outcome.value.spkiPublicKeys()),
                )
            outcome.value.retainForJournal(entries.map { it.handle.copyBytes() }) { clear ->
                journal.record(intent, entries, clear)
            }
        } else {
            journal.quarantine(intent)
        }
        return outcome
    }

    fun batchRecordedBeforeCsr(
        count: RkpKeyCount,
        deadline: BrokerDeadline,
        cancellation: BrokerCancellation,
        csrEffect: (IrpcKeyBatch) -> Unit,
    ): BrokerOutcome<IrpcKeyBatch> {
        val outcome = generate(count, deadline, cancellation)
        if (outcome is BrokerOutcome.Success) csrEffect(outcome.value)
        return outcome
    }
}
