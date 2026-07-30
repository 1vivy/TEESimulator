package org.matrix.TEESimulator.rka.broker

import android.os.DeadObjectException
import android.os.RemoteException
import android.os.ServiceSpecificException
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeoutException

enum class BrokerServiceKind {
    IRPC,
    KEYMINT,
}

sealed class BrokerServiceFailure {
    data object IrpcFailed : BrokerServiceFailure()

    data object IrpcInvalidMac : BrokerServiceFailure()

    data object IrpcProductionKeyInTestRequest : BrokerServiceFailure()

    data object IrpcTestKeyInProductionRequest : BrokerServiceFailure()

    data object IrpcInvalidEek : BrokerServiceFailure()

    data object IrpcRemoved : BrokerServiceFailure()

    class Oem(val code: Int) : BrokerServiceFailure() {
        override fun equals(other: Any?): Boolean = other is Oem && code == other.code

        override fun hashCode(): Int = code

        override fun toString(): String = "Oem(code=$code)"
    }
}

sealed class BrokerError {
    class UnsupportedIrpcVersion(val version: Int) : BrokerError() {
        override fun equals(other: Any?): Boolean =
            other is UnsupportedIrpcVersion && version == other.version

        override fun hashCode(): Int = version

        override fun toString(): String = "UnsupportedIrpcVersion(version=$version)"
    }

    class InvalidBoundary(val boundary: Boundary) : BrokerError() {
        enum class Boundary {
            CHALLENGE_LENGTH,
            KEY_COUNT,
            CAPABILITY,
        }

        override fun equals(other: Any?): Boolean =
            other is InvalidBoundary && boundary == other.boundary

        override fun hashCode(): Int = boundary.hashCode()

        override fun toString(): String = "InvalidBoundary(boundary=$boundary)"
    }

    class ServiceMissing(val service: BrokerServiceKind) : BrokerError() {
        override fun equals(other: Any?): Boolean =
            other is ServiceMissing && service == other.service

        override fun hashCode(): Int = service.hashCode()

        override fun toString(): String = "ServiceMissing(service=$service)"
    }

    class AccessDenied(val service: BrokerServiceKind) : BrokerError() {
        override fun equals(other: Any?): Boolean =
            other is AccessDenied && service == other.service

        override fun hashCode(): Int = service.hashCode()

        override fun toString(): String = "AccessDenied(service=$service)"
    }

    class ServiceDead(val service: BrokerServiceKind) : BrokerError() {
        override fun equals(other: Any?): Boolean = other is ServiceDead && service == other.service

        override fun hashCode(): Int = service.hashCode()

        override fun toString(): String = "ServiceDead(service=$service)"
    }

    class ServiceRejected(val service: BrokerServiceKind, val failure: BrokerServiceFailure) :
        BrokerError() {
        override fun equals(other: Any?): Boolean =
            other is ServiceRejected && service == other.service && failure == other.failure

        override fun hashCode(): Int = 31 * service.hashCode() + failure.hashCode()

        override fun toString(): String = "ServiceRejected(service=$service, failure=$failure)"
    }

    class OemFailure(val service: BrokerServiceKind) : BrokerError() {
        override fun equals(other: Any?): Boolean = other is OemFailure && service == other.service

        override fun hashCode(): Int = service.hashCode()

        override fun toString(): String = "OemFailure(service=$service)"
    }

    class Capacity(val service: BrokerServiceKind) : BrokerError() {
        override fun equals(other: Any?): Boolean = other is Capacity && service == other.service

        override fun hashCode(): Int = service.hashCode()

        override fun toString(): String = "Capacity(service=$service)"
    }

    data object Cancelled : BrokerError()

    data object DeadlineExceeded : BrokerError()
}

sealed class BrokerOutcome<out T> {
    class Success<T>(val value: T) : BrokerOutcome<T>()

    class Failure(val error: BrokerError) : BrokerOutcome<Nothing>() {
        override fun toString(): String = "Failure(error=$error)"
    }

    data object SelfCallBypass : BrokerOutcome<Nothing>()
}

internal object BrokerFailureMapper {
    fun map(service: BrokerServiceKind, throwable: Throwable): BrokerOutcome.Failure {
        val error = if (throwable is ExecutionException) throwable.cause ?: throwable else throwable
        return BrokerOutcome.Failure(
            when (error) {
                is UnsupportedIrpcVersionException ->
                    BrokerError.UnsupportedIrpcVersion(error.version)
                is SecurityException -> BrokerError.AccessDenied(service)
                is NoSuchElementException -> BrokerError.ServiceMissing(service)
                is DeadObjectException,
                is RemoteException -> BrokerError.ServiceDead(service)
                is ServiceSpecificException ->
                    BrokerError.ServiceRejected(service, mapServiceCode(service, error.errorCode))
                is InterruptedException,
                is CancellationException -> BrokerError.Cancelled
                is RejectedExecutionException -> BrokerError.Capacity(service)
                is TimeoutException -> BrokerError.DeadlineExceeded
                else -> BrokerError.OemFailure(service)
            }
        )
    }

    private fun mapServiceCode(service: BrokerServiceKind, code: Int): BrokerServiceFailure =
        when (service) {
            BrokerServiceKind.IRPC ->
                when (code) {
                    1 -> BrokerServiceFailure.IrpcFailed
                    2 -> BrokerServiceFailure.IrpcInvalidMac
                    3 -> BrokerServiceFailure.IrpcProductionKeyInTestRequest
                    4 -> BrokerServiceFailure.IrpcTestKeyInProductionRequest
                    5 -> BrokerServiceFailure.IrpcInvalidEek
                    6 -> BrokerServiceFailure.IrpcRemoved
                    else -> BrokerServiceFailure.Oem(code)
                }
            BrokerServiceKind.KEYMINT -> BrokerServiceFailure.Oem(code)
        }
}

internal class UnsupportedIrpcVersionException(val version: Int) : RuntimeException()
