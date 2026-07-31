package org.matrix.TEESimulator.rka.broker

interface ProvisioningObservationSource {
    val activeBaseUrl: String
    val rolloutId: Int
    val buildFingerprint: String
    val rkpdVersion: String
    val apexVersion: String
    val packageVersion: String
    val provisioningConfig: String
    val failureWindowStartMillis: Long
    val failureCount: Int
    val dataBudgetWindowStartMillis: Long
    val dataBudgetBytes: Long
    val defaultTeeIrpcIdentity: String
}

class ProvisioningSnapshot
private constructor(
    val activeBaseUrl: String,
    val rolloutId: Int,
    val buildFingerprint: String,
    val rkpdVersion: String,
    val apexVersion: String,
    val packageVersion: String,
    val provisioningConfig: String,
    val failureWindowStartMillis: Long,
    val failureCount: Int,
    val dataBudgetWindowStartMillis: Long,
    val dataBudgetBytes: Long,
    val defaultTeeIrpcIdentity: String,
) {
    companion object {
        private const val MAX_OBSERVATION_CHARS = 4096

        fun capture(source: ProvisioningObservationSource): ProvisioningSnapshot =
            ProvisioningSnapshot(
                activeBaseUrl = bounded("activeBaseUrl", source.activeBaseUrl),
                rolloutId = nonNegative("rolloutId", source.rolloutId),
                buildFingerprint = bounded("buildFingerprint", source.buildFingerprint),
                rkpdVersion = bounded("rkpdVersion", source.rkpdVersion),
                apexVersion = bounded("apexVersion", source.apexVersion),
                packageVersion = bounded("packageVersion", source.packageVersion),
                provisioningConfig = bounded("provisioningConfig", source.provisioningConfig),
                failureWindowStartMillis =
                    nonNegative("failureWindowStartMillis", source.failureWindowStartMillis),
                failureCount = nonNegative("failureCount", source.failureCount),
                dataBudgetWindowStartMillis =
                    nonNegative("dataBudgetWindowStartMillis", source.dataBudgetWindowStartMillis),
                dataBudgetBytes = nonNegative("dataBudgetBytes", source.dataBudgetBytes),
                defaultTeeIrpcIdentity =
                    bounded("defaultTeeIrpcIdentity", source.defaultTeeIrpcIdentity),
            )

        private fun bounded(name: String, value: String): String {
            require(value.isNotEmpty() && value.length <= MAX_OBSERVATION_CHARS) {
                "$name must contain 1..$MAX_OBSERVATION_CHARS characters"
            }
            return value
        }

        private fun nonNegative(name: String, value: Long): Long {
            require(value >= 0) { "$name must be non-negative" }
            return value
        }

        private fun nonNegative(name: String, value: Int): Int {
            require(value >= 0) { "$name must be non-negative" }
            return value
        }
    }
}
