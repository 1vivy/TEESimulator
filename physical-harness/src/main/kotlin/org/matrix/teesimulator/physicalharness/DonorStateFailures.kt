package org.matrix.teesimulator.physicalharness

sealed class DonorStateCorruptionException(message: String) : RuntimeException(message) {
    class AuthenticationFailed : DonorStateCorruptionException("state authentication failed")

    class InvalidMacOutput : DonorStateCorruptionException("invalid state MAC output")

    class Truncated : DonorStateCorruptionException("state file is truncated")

    class TrailingData : DonorStateCorruptionException("state file has trailing data")

    class InvalidUtf8 : DonorStateCorruptionException("state file contains invalid UTF-8")

    class UnknownTag : DonorStateCorruptionException("state file contains an unknown tag")

    class UnsupportedEnvelope : DonorStateCorruptionException("unsupported state file envelope")

    class LimitExceeded : DonorStateCorruptionException("state file exceeds a safety limit")
}

sealed class DonorStateQuarantineException(message: String) : RuntimeException(message) {
    class InvalidRecord : DonorStateQuarantineException("invalid durable state record")

    class DuplicateRecord : DonorStateQuarantineException("duplicate durable state identity")

    class DanglingReference : DonorStateQuarantineException("dangling durable state reference")

    class ImpossibleState : DonorStateQuarantineException("impossible durable state combination")

    class NonCanonicalOrder : DonorStateQuarantineException("non-canonical durable state order")
}
