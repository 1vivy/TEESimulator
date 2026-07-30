package org.matrix.teesimulator.rka

import java.util.Base64

enum class DeviceRole {
    DONOR,
    CANDIDATE,
}

class DeviceSerial private constructor(val role: DeviceRole, val value: String) {
    companion object {
        fun parse(role: DeviceRole, value: String): DeviceSerial =
            DeviceSerial(role, RkaLimits.requireDeviceSerial(value))
    }
}

object RkaLimits {
    const val ROLE_CONFIG_BYTES = 4 * 1024
    const val PROFILE_BYTES = 64 * 1024
    const val FRAME_BYTES = 2 * 1024 * 1024
    const val REQUEST_CHUNK_BYTES = 1024 * 1024
    const val OPERATION_INPUT_BYTES = 2 * 1024 * 1024
    const val FIXTURE_NONCE_BYTES = 16
    const val FIXTURE_NONCE_BASE64URL_CHARS = 22
    const val SESSION_BINDING_BYTES = 32
    const val REQUEST_ID_BYTES = 16
    const val CHALLENGE_BYTES = 128
    const val PHYSICAL_CHALLENGE_BYTES = 32
    const val CERTIFICATE_COUNT = 8
    const val CERTIFICATE_BYTES = 87_384
    const val CERTIFICATE_AGGREGATE_BYTES = 699_072
    const val LOGICAL_NAME_BYTES = 128
    const val PROFILE_ID_BYTES = 64
    const val DEVICE_SERIAL_BYTES = 128
    const val REQUESTS_PER_SESSION = 64
    const val DIRECT_ENDPOINTS = 4
    const val DEADLINE_SECONDS = 120
    const val CONNECT_TIMEOUT_SECONDS = 5
    const val READ_TIMEOUT_SECONDS = 5
    const val WRITE_TIMEOUT_SECONDS = 10
    const val FRAME_TIMEOUT_SECONDS = 30

    private val profileId = Regex("[A-Za-z0-9._-]{1,64}")
    private val deviceSerial = Regex("[A-Za-z0-9._:-]{1,128}")
    private val fixtureNonce = Regex("[A-Za-z0-9_-]{22}")

    fun requireProfileId(value: String): String {
        require(value.encodeToByteArray().size <= PROFILE_ID_BYTES)
        require(profileId.matches(value))
        return value
    }

    fun requireDeviceSerial(value: String): String {
        require(value.encodeToByteArray().size <= DEVICE_SERIAL_BYTES)
        require(deviceSerial.matches(value))
        return value
    }

    fun requireDistinctSerials(donor: DeviceSerial, candidate: DeviceSerial) {
        require(donor.role == DeviceRole.DONOR)
        require(candidate.role == DeviceRole.CANDIDATE)
        require(donor.value != candidate.value)
    }

    fun requireFixtureNonce(value: String): ByteArray {
        require(value.length == FIXTURE_NONCE_BASE64URL_CHARS)
        require(fixtureNonce.matches(value))
        return Base64.getUrlDecoder().decode("$value==").also {
            require(it.size == FIXTURE_NONCE_BYTES)
        }
    }

    fun requireRoleConfig(value: ByteArray): ByteArray =
        value.also { require(it.size <= ROLE_CONFIG_BYTES) }

    fun requireProfile(value: ByteArray): ByteArray =
        value.also { require(it.size <= PROFILE_BYTES) }

    fun requireEndpointCount(value: Int): Int = value.also { require(it in 0..DIRECT_ENDPOINTS) }

    fun requireRequestCount(value: Int): Int = value.also { require(it in 0..REQUESTS_PER_SESSION) }

    fun requireOperationInput(value: Int): Int =
        value.also { require(it in 0..OPERATION_INPUT_BYTES) }

    fun requireDeadline(establishedUnixMillis: ULong, deadlineUnixMillis: ULong): ULong =
        deadlineUnixMillis.also {
            require(it >= establishedUnixMillis)
            require(it - establishedUnixMillis <= DEADLINE_SECONDS.toULong() * 1_000u)
        }
}
