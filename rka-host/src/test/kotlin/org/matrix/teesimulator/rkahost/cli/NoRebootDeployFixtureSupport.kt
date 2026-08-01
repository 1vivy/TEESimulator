package org.matrix.teesimulator.rkahost.cli

import java.nio.file.Files

internal data class DeployResult(val exitCode: Int, val stdout: String, val stderr: String)

internal enum class CandidateManagerMode(val cliValue: String) {
    AUTHORIZED_HEADLESS("authorized_headless")
}

internal enum class KernelProfile(
    val fixtureName: String,
    val firstInstall: Boolean = false,
    val systemOpenSsl: Boolean = true,
    val candidateManagerMode: CandidateManagerMode? = null,
) {
    LEGACY("legacy"),
    LEGACY_FIRST_INSTALL("legacy", firstInstall = true),
    KSU_NEXT_DUAL("ksu-next-dual", candidateManagerMode = CandidateManagerMode.AUTHORIZED_HEADLESS),
    KSU_NEXT_DUAL_UNTYPED("ksu-next-dual"),
    KSU_NEXT_FIRST_INSTALL(
        "ksu-next-dual",
        firstInstall = true,
        candidateManagerMode = CandidateManagerMode.AUTHORIZED_HEADLESS,
    ),
    KSU_NEXT_FIRST_INSTALL_NO_OPENSSL(
        "ksu-next-dual",
        firstInstall = true,
        systemOpenSsl = false,
        candidateManagerMode = CandidateManagerMode.AUTHORIZED_HEADLESS,
    ),
}

internal enum class FixtureMutation {
    INCOMPATIBLE_CANDIDATE,
    FAIL_DONOR_DEPLOY,
    FAIL_CANDIDATE_DEPLOY,
    FAIL_CANDIDATE_NETWORK,
    DONOR_WLAN_CANDIDATE_TUN,
    NETWORK_SIDE_SWAP,
    TUN_SUFFIX,
    TUN_MULTIPLE,
    TUN_SPECIAL,
    TUN_UNSPECIFIED,
    TUN_LINK_LOCAL,
    TUN_MULTICAST,
    TUN_BROADCAST,
    TUN_WHITESPACE,
    TUN_MALFORMED,
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
    DIRECT_PROBE_UNAVAILABLE,
    DIRECT_PROBE_STALE,
    ZYGOTE_WRONG_PARENT,
    ZYGOTE_INVALID_IDENTITY,
    ZYGOTE_AMBIGUOUS,
    ZYGOTE_MISSING,
    NEXT_APPID_ZERO,
    NEXT_APPID_AMBIGUOUS,
    NEXT_APPID_MISSING,
    NEXT_PACKAGES_MALICIOUS,
    NEXT_COMPONENT_WRONG,
    NEXT_ACTIVITY_WRONG,
    NEXT_SIGNING_WRONG,
    NEXT_HELP_DRIFT,
    NEXT_BINARY_DRIFT,
    NEXT_VERSION_DRIFT,
    NEXT_APPID_ERROR,
    NEXT_UID_MISMATCH,
    NEXT_BOOT_DRIFT,
    NEXT_PROBE_HASH_MISMATCH,
    NEXT_PROBE_CLEANUP_FAILURE,
    NEXT_CANDIDATE_SHELL_RESTRICTED,
    NEXT_PROBE_STAGE_TRUNCATED,
    NEXT_PROBE_MATERIALIZE_NONZERO,
    NEXT_PROBE_PARENT_SYMLINK,
    NEXT_ANDROID_SHELL_PARSER,
    NEXT_MATCH_WHITESPACE,
    NEXT_MATCH_NEWLINE,
    NEXT_MATCH_METACHAR,
    NEXT_MATCH_MALFORMED,
    NEXT_MATCH_EXTRA,
    NEXT_LEGACY_USER_ID,
    NEXT_UID_SOURCE_ZERO,
    NEXT_UID_SOURCE_MULTIPLE,
    NEXT_UID_SOURCE_WRONG_MODULO,
    NEXT_UID_SOURCE_MALFORMED,
    NEXT_UID_SOURCE_EXTRA,
    NEXT_UID_SOURCE_WHITESPACE,
    NEXT_UID_SOURCE_METACHAR,
    NEXT_UID_SOURCE_MISMATCH,
    NEXT_LAYOUT_ONE_PARENT,
    NEXT_LAYOUT_FILE,
    NEXT_LAYOUT_SYMLINK,
    NEXT_LAYOUT_HIDDEN_MOUNT,
    ARCHIVE_METADATA_MISSING,
    ARCHIVE_METADATA_DUPLICATE_PATH,
    ARCHIVE_METADATA_TRAVERSAL,
    ARCHIVE_METADATA_OVERSIZE,
    ARCHIVE_ARTIFACT_METADATA_TAMPERED,
    ARCHIVE_SOURCE_METADATA_MISMATCH,
    AFTER_METADATA,
    AFTER_INSTALL,
    INSTALL_ONLY_MODULES_PARENT,
    INSTALL_ONLY_UPDATE_PARENT,
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
        FixtureMutation.DONOR_WLAN_CANDIDATE_TUN ->
            environment["RKA_FAKE_IP_MODE"] = "donor-wlan-candidate-tun"
        FixtureMutation.NETWORK_SIDE_SWAP -> environment["RKA_FAKE_IP_MODE"] = "network-side-swap"
        FixtureMutation.TUN_SUFFIX -> environment["RKA_FAKE_IP_MODE"] = "suffix"
        FixtureMutation.TUN_MULTIPLE -> environment["RKA_FAKE_IP_MODE"] = "multiple"
        FixtureMutation.TUN_SPECIAL -> environment["RKA_FAKE_IP_MODE"] = "special"
        FixtureMutation.TUN_UNSPECIFIED -> environment["RKA_FAKE_IP_MODE"] = "unspecified"
        FixtureMutation.TUN_LINK_LOCAL -> environment["RKA_FAKE_IP_MODE"] = "link-local"
        FixtureMutation.TUN_MULTICAST -> environment["RKA_FAKE_IP_MODE"] = "multicast"
        FixtureMutation.TUN_BROADCAST -> environment["RKA_FAKE_IP_MODE"] = "broadcast"
        FixtureMutation.TUN_WHITESPACE -> environment["RKA_FAKE_IP_MODE"] = "whitespace"
        FixtureMutation.TUN_MALFORMED -> environment["RKA_FAKE_IP_MODE"] = "malformed"
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
        FixtureMutation.TLS12_ONLY -> environment["RKA_FAKE_TLS_PROTOCOL"] = "TLS1.2"
        FixtureMutation.DIRECT_PROBE_UNAVAILABLE ->
            environment["RKA_FAKE_PROBE_STATUS"] = "unavailable"
        FixtureMutation.DIRECT_PROBE_STALE -> environment["RKA_FAKE_PROBE_STATUS"] = "stale"
        FixtureMutation.ZYGOTE_WRONG_PARENT -> environment["RKA_FAKE_ZYGOTE"] = "wrong-parent"
        FixtureMutation.ZYGOTE_INVALID_IDENTITY ->
            environment["RKA_FAKE_ZYGOTE"] = "invalid-identity"
        FixtureMutation.ZYGOTE_AMBIGUOUS -> environment["RKA_FAKE_ZYGOTE"] = "ambiguous"
        FixtureMutation.ZYGOTE_MISSING -> environment["RKA_FAKE_ZYGOTE"] = "missing"
        FixtureMutation.NEXT_APPID_ZERO -> environment["RKA_FAKE_NEXT_MUTATION"] = "appid-zero"
        FixtureMutation.NEXT_APPID_AMBIGUOUS ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "appid-ambiguous"
        FixtureMutation.NEXT_APPID_MISSING ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "appid-missing"
        FixtureMutation.NEXT_PACKAGES_MALICIOUS ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "packages-malicious"
        FixtureMutation.NEXT_COMPONENT_WRONG ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "component-wrong"
        FixtureMutation.NEXT_ACTIVITY_WRONG ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "activity-wrong"
        FixtureMutation.NEXT_SIGNING_WRONG ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "signing-wrong"
        FixtureMutation.NEXT_HELP_DRIFT -> environment["RKA_FAKE_NEXT_MUTATION"] = "help-drift"
        FixtureMutation.NEXT_BINARY_DRIFT -> environment["RKA_FAKE_NEXT_MUTATION"] = "binary-drift"
        FixtureMutation.NEXT_VERSION_DRIFT ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "version-drift"
        FixtureMutation.NEXT_APPID_ERROR -> environment["RKA_FAKE_NEXT_MUTATION"] = "appid-error"
        FixtureMutation.NEXT_UID_MISMATCH -> environment["RKA_FAKE_NEXT_MUTATION"] = "uid-mismatch"
        FixtureMutation.NEXT_BOOT_DRIFT -> environment["RKA_FAKE_NEXT_MUTATION"] = "boot-drift"
        FixtureMutation.NEXT_PROBE_HASH_MISMATCH ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "probe-hash-mismatch"
        FixtureMutation.NEXT_PROBE_CLEANUP_FAILURE ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "probe-cleanup-failure"
        FixtureMutation.NEXT_CANDIDATE_SHELL_RESTRICTED ->
            environment["RKA_FAKE_PROTECTED_PUSH_DENIED"] = "CANDIDATE_B"
        FixtureMutation.NEXT_PROBE_STAGE_TRUNCATED ->
            environment["RKA_FAKE_UPLOAD_FAULT"] = "truncate"
        FixtureMutation.NEXT_PROBE_MATERIALIZE_NONZERO ->
            environment["RKA_FAKE_UPLOAD_FAULT"] = "remote-nonzero"
        FixtureMutation.NEXT_PROBE_PARENT_SYMLINK ->
            environment["RKA_FAKE_UPLOAD_FAULT"] = "symlink-parent"
        FixtureMutation.NEXT_ANDROID_SHELL_PARSER ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "android-shell-parser"
        FixtureMutation.NEXT_MATCH_WHITESPACE ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "match-whitespace"
        FixtureMutation.NEXT_MATCH_NEWLINE ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "match-newline"
        FixtureMutation.NEXT_MATCH_METACHAR ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "match-metachar"
        FixtureMutation.NEXT_MATCH_MALFORMED ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "match-malformed"
        FixtureMutation.NEXT_MATCH_EXTRA -> environment["RKA_FAKE_NEXT_MUTATION"] = "match-extra"
        FixtureMutation.NEXT_LEGACY_USER_ID ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "legacy-userid"
        FixtureMutation.NEXT_UID_SOURCE_ZERO ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-zero"
        FixtureMutation.NEXT_UID_SOURCE_MULTIPLE ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-multiple"
        FixtureMutation.NEXT_UID_SOURCE_WRONG_MODULO ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-wrong-modulo"
        FixtureMutation.NEXT_UID_SOURCE_MALFORMED ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-malformed"
        FixtureMutation.NEXT_UID_SOURCE_EXTRA ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-extra"
        FixtureMutation.NEXT_UID_SOURCE_WHITESPACE ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-whitespace"
        FixtureMutation.NEXT_UID_SOURCE_METACHAR ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-metachar"
        FixtureMutation.NEXT_UID_SOURCE_MISMATCH ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "uid-source-mismatch"
        FixtureMutation.NEXT_LAYOUT_ONE_PARENT ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "layout-one-parent"
        FixtureMutation.NEXT_LAYOUT_FILE -> environment["RKA_FAKE_NEXT_MUTATION"] = "layout-file"
        FixtureMutation.NEXT_LAYOUT_SYMLINK ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "layout-symlink"
        FixtureMutation.NEXT_LAYOUT_HIDDEN_MOUNT ->
            environment["RKA_FAKE_NEXT_MUTATION"] = "layout-hidden-mount"
        FixtureMutation.ARCHIVE_METADATA_MISSING,
        FixtureMutation.ARCHIVE_METADATA_DUPLICATE_PATH,
        FixtureMutation.ARCHIVE_METADATA_TRAVERSAL,
        FixtureMutation.ARCHIVE_METADATA_OVERSIZE,
        FixtureMutation.ARCHIVE_ARTIFACT_METADATA_TAMPERED,
        FixtureMutation.ARCHIVE_SOURCE_METADATA_MISMATCH -> Unit
        FixtureMutation.AFTER_METADATA -> environment["RKA_FAKE_FAULT"] = "after-metadata"
        FixtureMutation.AFTER_INSTALL -> environment["RKA_FAKE_FAULT"] = "after-install"
        FixtureMutation.INSTALL_ONLY_MODULES_PARENT ->
            environment["RKA_FAKE_FAULT"] = "install-only-modules-parent"
        FixtureMutation.INSTALL_ONLY_UPDATE_PARENT ->
            environment["RKA_FAKE_FAULT"] = "install-only-update-parent"
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
                    facts["profile_sha256"]?.matches(Regex("[0-9a-f]{64}")) == true &&
                    facts["profile_epoch"] == "7" &&
                    facts["peer_pin_sha256"]?.matches(Regex("[0-9a-f]{64}")) == true &&
                    facts["transport"] == "DIRECT"
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
    pin=${'$'}(/usr/bin/sed -n '7s/^peer_spki_sha256=//p' "${'$'}RKA_DIRECT_PROFILE_PATH")
    pin_sha=${'$'}(printf %s "${'$'}pin" | /usr/bin/xxd -r -p | /usr/bin/sha256sum | /usr/bin/awk '{print ${'$'}1}')
    printf 'version=1\nprofile_sha256=%s\nprofile_epoch=%s\npeer_pin_sha256=%s\ndial_mode=DONOR_DIALS\ntransport=DIRECT\n' "${'$'}profile_sha" "${'$'}epoch" "${'$'}pin_sha" > "${'$'}state/run/direct-profile.receipt"
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
