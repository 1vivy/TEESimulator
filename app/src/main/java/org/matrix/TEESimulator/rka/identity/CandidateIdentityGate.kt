package org.matrix.TEESimulator.rka.identity

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

fun interface CandidateIdentityAuthority {
    fun snapshot(uid: Int, epoch: Long): AuthoritativeIdentity
}

class IdentityAdmission
internal constructor(internal val uid: Int, internal val snapshot: CandidateIdentitySnapshot) {
    internal val state = AtomicReference(State.FRESH)

    internal enum class State {
        FRESH,
        EXPOSING,
        EXPOSED,
        FAILED,
    }

    fun epoch() = snapshot.epoch

    fun identityHash() = snapshot.identityHash()

    fun aaidDer() = snapshot.aaidDer()

    override fun toString() = "IdentityAdmission(epoch=${snapshot.epoch}, identityHash=<redacted>)"
}

class PendingCandidateResponse<T>(private val value: T, private val destroyAction: (T) -> Unit) {
    private val destroyed = AtomicBoolean()

    internal fun value() = value

    internal fun destroy() {
        if (destroyed.compareAndSet(false, true)) runCatching { destroyAction(value) }
    }
}

sealed class IdentityExposure<out T> {
    data class Exposed<T>(val value: T) : IdentityExposure<T>()

    data class Rejected(val error: IdentityError) : IdentityExposure<Nothing>()
}

class CandidateIdentityGate(
    private val binderCallingUid: () -> Int,
    private val authority: CandidateIdentityAuthority,
) {
    private val epochs = AtomicLong()

    fun admitRemote(): IdentityAdmission {
        val uid = binderCallingUid()
        val epoch = epochs.incrementAndGet()
        return IdentityAdmission(uid, capture(uid, epoch))
    }

    fun revalidateForRemote(admission: IdentityAdmission): Boolean =
        admission.state.get() == IdentityAdmission.State.FRESH &&
            runCatching {
                    capture(admission.uid, admission.snapshot.epoch)
                        .sameIdentity(admission.snapshot)
                }
                .getOrDefault(false)

    fun <T> expose(
        admission: IdentityAdmission,
        pending: PendingCandidateResponse<T>,
        deleteOrQuarantine: () -> Unit,
    ): IdentityExposure<T> {
        if (
            !admission.state.compareAndSet(
                IdentityAdmission.State.FRESH,
                IdentityAdmission.State.EXPOSING,
            )
        ) {
            pending.destroy()
            if (admission.state.get() != IdentityAdmission.State.EXPOSED) {
                return IdentityExposure.Rejected(IdentityError.IDENTITY_DRIFT)
            }
            return IdentityExposure.Rejected(IdentityError.STALE_ADMISSION)
        }
        val stable =
            runCatching {
                    capture(admission.uid, admission.snapshot.epoch)
                        .sameIdentity(admission.snapshot)
                }
                .getOrDefault(false)
        return if (stable) {
            admission.state.set(IdentityAdmission.State.EXPOSED)
            IdentityExposure.Exposed(pending.value())
        } else {
            pending.destroy()
            runCatching(deleteOrQuarantine)
            admission.state.set(IdentityAdmission.State.FAILED)
            IdentityExposure.Rejected(IdentityError.IDENTITY_DRIFT)
        }
    }

    private fun capture(uid: Int, epoch: Long): CandidateIdentitySnapshot {
        val raw = authority.snapshot(uid, epoch)
        if (raw.uid != uid)
            throw CandidateIdentityException(IdentityError.PACKAGE_MANAGER_INCONSISTENT)
        return CandidateIdentityCanonicalizer.canonicalize(
            raw.androidUser,
            raw.uid,
            raw.packages,
            epoch,
        )
    }
}
