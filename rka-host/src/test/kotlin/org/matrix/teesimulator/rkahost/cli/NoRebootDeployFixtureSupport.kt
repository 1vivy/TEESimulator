package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files

internal data class DeployResult(val exitCode: Int, val stdout: String, val stderr: String)

internal enum class KernelProfile(val fixtureName: String) {
    LEGACY("legacy"),
    KSU_NEXT_DUAL("ksu-next-dual"),
}

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
    TLS12_ONLY,
    ZYGOTE_WRONG_PARENT,
    ZYGOTE_INVALID_IDENTITY,
    ZYGOTE_AMBIGUOUS,
    ZYGOTE_MISSING,
    NEXT_APPID_ZERO,
    NEXT_APPID_AMBIGUOUS,
    NEXT_PACKAGES_MALICIOUS,
    NEXT_COMPONENT_WRONG,
    NEXT_SIGNING_WRONG,
    NEXT_HELP_DRIFT,
    NEXT_BINARY_DRIFT,
    NEXT_VERSION_DRIFT,
    NEXT_APPID_ERROR,
    NEXT_UID_MISMATCH,
    NEXT_BOOT_DRIFT,
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
        FixtureMutation.TLS12_ONLY -> Unit
        FixtureMutation.ZYGOTE_WRONG_PARENT -> environment["RKA_FAKE_ZYGOTE"] = "wrong-parent"
        FixtureMutation.ZYGOTE_INVALID_IDENTITY ->
            environment["RKA_FAKE_ZYGOTE"] = "invalid-identity"
        FixtureMutation.ZYGOTE_AMBIGUOUS -> environment["RKA_FAKE_ZYGOTE"] = "ambiguous"
        FixtureMutation.ZYGOTE_MISSING -> environment["RKA_FAKE_ZYGOTE"] = "missing"
        FixtureMutation.NEXT_APPID_ZERO -> environment["RKA_FAKE_NEXT_MUTATION"] = "appid-zero"
        FixtureMutation.NEXT_APPID_AMBIGUOUS ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "appid-ambiguous"
        FixtureMutation.NEXT_PACKAGES_MALICIOUS ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "packages-malicious"
        FixtureMutation.NEXT_COMPONENT_WRONG ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "component-wrong"
        FixtureMutation.NEXT_SIGNING_WRONG ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "signing-wrong"
        FixtureMutation.NEXT_HELP_DRIFT -> environment["RKA_FAKE_NEXT_MUTATION"] = "help-drift"
        FixtureMutation.NEXT_BINARY_DRIFT -> environment["RKA_FAKE_NEXT_MUTATION"] = "binary-drift"
        FixtureMutation.NEXT_VERSION_DRIFT ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "version-drift"
        FixtureMutation.NEXT_APPID_ERROR -> environment["RKA_FAKE_NEXT_MUTATION"] = "appid-error"
        FixtureMutation.NEXT_UID_MISMATCH -> environment["RKA_FAKE_NEXT_MUTATION"] = "uid-mismatch"
        FixtureMutation.NEXT_BOOT_DRIFT -> environment["RKA_FAKE_NEXT_MUTATION"] = "boot-drift"
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
                    facts["renderer_parent_pid"] == "700" &&
                    facts["zygote_pid"] == "700" &&
                    facts["zygote_name"] == "webview_zygote" &&
                    facts["zygote_uid"] == "1053" &&
                    facts["zygote_command"] == "webview_zygote" &&
                    facts["hosting_record"]?.startsWith(
                        "com.google.android.webview/org.chromium.content.app.SandboxedProcessService"
                    ) == true
            }
    }

internal fun Fixture.hasTls13ProbeReceipts(expectedAttempts: Int): Boolean =
    transactionPaths().all { paths ->
        paths.size == expectedAttempts &&
            paths.all { transaction ->
                val facts =
                    Files.readAllLines(transaction.resolve("direct-probe.receipt")).associate {
                        it.substringBefore('=') to it.substringAfter('=')
                    }
                facts["version"] == "1" &&
                    facts["protocol"] == "TLSv1.3" &&
                    facts["observed_spki_sha256"]?.matches(Regex("[0-9a-f]{64}")) == true &&
                    facts["observed_spki_sha256"] == facts["expected_spki_sha256"]
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

internal fun fixtureGit(sourceSha: String) =
    """#!/bin/bash
set -eu
case " ${'$'}* " in
  *" status "*) exit 0 ;;
  *" verify-commit "*) exit 0 ;;
  *" rev-parse "*) printf '%s\n' '$sourceSha' ;;
  *" cat-file "*) exit 0 ;;
  *" diff "*) exit 0 ;;
  *) exit 1 ;;
esac
"""
