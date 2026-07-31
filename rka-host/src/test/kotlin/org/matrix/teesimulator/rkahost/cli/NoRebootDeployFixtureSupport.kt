package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files

internal data class DeployResult(val exitCode: Int, val stdout: String, val stderr: String)

internal enum class FixtureMutation {
    INCOMPATIBLE_CANDIDATE,
    FAIL_DONOR_DEPLOY,
    FAIL_CANDIDATE_DEPLOY,
    FAIL_CANDIDATE_NETWORK,
    MISMATCH_CANDIDATE_PIN,
    AFTER_STOP,
    AFTER_UNMOUNT,
    ACTIVE_HASH,
    ACTIVE_METADATA,
    ACTIVE_COPY,
    CORRUPT_REMOTE_ARCHIVE,
    CORRUPT_REMOTE_SOURCE,
    WEBUI_WRONG_OWNER,
    WEBUI_AMBIGUOUS_OWNER,
    WEBUI_MISSING_OWNER,
}

internal data class ModuleSnapshot(
    val bytes: ByteArray,
    val permissions: Set<java.nio.file.attribute.PosixFilePermission>,
    val modifiedMillis: Long,
)

internal fun applyFixtureMutation(
    environment: MutableMap<String, String>,
    value: FixtureMutation?,
) {
    when (value) {
        null -> Unit
        FixtureMutation.INCOMPATIBLE_CANDIDATE ->
            environment["RKA_FAKE_INCOMPATIBLE"] = "CANDIDATE_B"
        FixtureMutation.FAIL_DONOR_DEPLOY -> environment["RKA_FAKE_FAIL_DEPLOY"] = "DONOR_A"
        FixtureMutation.FAIL_CANDIDATE_DEPLOY -> environment["RKA_FAKE_FAIL_DEPLOY"] = "CANDIDATE_B"
        FixtureMutation.FAIL_CANDIDATE_NETWORK ->
            environment["RKA_FAKE_FAIL_NETWORK"] = "CANDIDATE_B"
        FixtureMutation.MISMATCH_CANDIDATE_PIN ->
            environment["RKA_FAKE_MISMATCH_SERIAL"] = "CANDIDATE_B"
        FixtureMutation.AFTER_STOP -> environment["RKA_FAKE_FAULT"] = "after-stop"
        FixtureMutation.AFTER_UNMOUNT -> environment["RKA_FAKE_FAULT"] = "after-unmount"
        FixtureMutation.ACTIVE_HASH -> environment["RKA_FAKE_FAULT"] = "active-hash"
        FixtureMutation.ACTIVE_METADATA -> environment["RKA_FAKE_FAULT"] = "active-metadata"
        FixtureMutation.ACTIVE_COPY -> environment["RKA_FAKE_FAULT"] = "active-copy"
        FixtureMutation.CORRUPT_REMOTE_ARCHIVE ->
            environment["RKA_FAKE_CORRUPT_ARCHIVE_SERIAL"] = "DONOR_A"
        FixtureMutation.CORRUPT_REMOTE_SOURCE ->
            environment["RKA_FAKE_CORRUPT_SOURCE_SERIAL"] = "DONOR_A"
        FixtureMutation.WEBUI_WRONG_OWNER -> environment["RKA_FAKE_WEBUI_OWNER"] = "wrong"
        FixtureMutation.WEBUI_AMBIGUOUS_OWNER -> environment["RKA_FAKE_WEBUI_OWNER"] = "ambiguous"
        FixtureMutation.WEBUI_MISSING_OWNER -> environment["RKA_FAKE_WEBUI_OWNER"] = "missing"
    }
}

internal fun Fixture.hasCompleteAttemptReceipts(expectedAttempts: Int): Boolean =
    transactionPaths().all { paths ->
        paths.size == expectedAttempts &&
            paths.all {
                Files.isRegularFile(it.resolve("source.receipt")) &&
                    Files.isRegularFile(it.resolve("mount-views.receipt")) &&
                    Files.isRegularFile(it.resolve("webui-owner.receipt")) &&
                    Files.isRegularFile(it.resolve("installed"))
            }
    }

internal fun Fixture.hasAndroidWebViewOwnershipFacts(expectedAttempts: Int): Boolean =
    transactionPaths().all { paths ->
        paths.size == expectedAttempts &&
            paths.all { transaction ->
                val facts =
                    Files.readAllLines(transaction.resolve("webui-owner.receipt")).associate {
                        it.substringBefore('=') to it.substringAfter('=')
                    }
                facts["manager_pid"] == "201" &&
                    facts["manager_uid"] == "10123" &&
                    facts["manager_process"] == "me.weishu.kernelsu" &&
                    facts["renderer_pid"] == "301" &&
                    facts["renderer_uid"] == "99001" &&
                    facts["renderer_process"] == "com.google.android.webview:sandboxed_process0" &&
                    facts["provider_package"] == "com.google.android.webview" &&
                    facts["hosting_record"]?.startsWith(
                        "com.google.android.webview/org.chromium.content.app.SandboxedProcessService"
                    ) == true
            }
    }

internal fun Fixture.hasDistinctMountViewFacts(expectedAttempts: Int): Boolean =
    transactionPaths().all { paths ->
        paths.size == expectedAttempts &&
            paths.all { transaction ->
                val facts = Files.readAllLines(transaction.resolve("mount-views.receipt"))
                val namespaces = facts.map { it.substringAfter('=').substringBefore('|') }
                val inodes = facts.drop(1).map { it.substringAfter('|') }
                facts.map { it.substringBefore('=') } ==
                    listOf("init", "ksud", "manager", "webui", "broker", "sidecar") &&
                    namespaces.toSet().size == 6 &&
                    inodes.toSet().size == 1
            }
    }

private fun Fixture.transactionPaths() =
    listOf("DONOR_A", "CANDIDATE_B").map { serial ->
        val transactions =
            devices.resolve(serial).resolve("root/data/adb/teesimulator-rka/deploy-transactions")
        Files.list(transactions).use { it.toList() }
    }

internal const val fixtureManifestCommand =
    "sha256sum module.prop rka-control.sh rka-runtime.manifest rka-sidecar rka-supervisor.sh sepolicy.probes sepolicy.rule webroot/index.html > META-INF/rka-artifacts.sha256"

internal val fixtureSupervisor =
    """#!/bin/sh
state=/data/adb/teesimulator-rka
case "${'$'}{1-}" in
  start)
    mkdir -p "${'$'}state/run/pids"
    printf 'RUNNING\n' > "${'$'}state/run/supervisor.state"
    printf '401 401 1\n' > "${'$'}state/run/pids/broker.pid"
    printf '501 501 1\n' > "${'$'}state/run/pids/sidecar.pid"
    profile_sha=${'$'}(/usr/bin/sha256sum "${'$'}RKA_DIRECT_PROFILE_PATH" | /usr/bin/awk '{print ${'$'}1}')
    epoch=${'$'}(/usr/bin/sed -n '3s/^profile_epoch=//p' "${'$'}RKA_DIRECT_PROFILE_PATH")
    pin=${'$'}(/usr/bin/sed -n '5s/^peer_spki_sha256=//p' "${'$'}RKA_DIRECT_PROFILE_PATH")
    pin_sha=${'$'}(printf %s "${'$'}pin" | /usr/bin/xxd -r -p | /usr/bin/sha256sum | /usr/bin/awk '{print ${'$'}1}')
    printf 'version=1\nprofile_sha256=%s\nprofile_epoch=%s\npeer_pin_sha256=%s\ntransport=DIRECT\n' "${'$'}profile_sha" "${'$'}epoch" "${'$'}pin_sha" > "${'$'}state/run/direct-profile.receipt"
    ;;
  stop)
    rm -rf "${'$'}state/run/pids"
    printf 'STOPPED\n' > "${'$'}state/run/supervisor.state"
    [ "${'$'}{RKA_FAKE_FAULT:-}" != after-stop ] || exit 1
    ;;
  status)
    current=${'$'}(cat "${'$'}state/run/supervisor.state" 2>/dev/null || printf STOPPED)
    printf 'state=%s\nlegacy=STOPPED\n' "${'$'}current"
    if [ -d "${'$'}state/run/pids" ]; then printf 'broker=RUNNING\nsidecar=RUNNING\n'; else printf 'broker=STOPPED\nsidecar=STOPPED\n'; fi
    ;;
  *) exit 2 ;;
esac
"""

internal val fixtureGit =
    """#!/bin/bash
set -eu
case " ${'$'}* " in
  *" status "*) exit 0 ;;
  *" verify-commit "*) exit 0 ;;
  *" rev-parse "*) printf '%s\n' '6cb0fbf9f6c51d09f0b7df5206291a9815bd6555' ;;
  *" cat-file "*) exit 0 ;;
  *" diff "*) exit 0 ;;
  *) exit 1 ;;
esac
"""
