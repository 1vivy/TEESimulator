# Donor-backed RKA beta guide

This beta gives TEESimulator-RS a renewable, donor-backed RKP path. One donor
phone serves one or more candidate phones concurrently. Every device uses the
same role-neutral module ZIP; the pairing profile assigns roles at runtime.

Each candidate has its own identity, its own pinned TLS trust, its own paired
activation record, and its own isolated lease and key namespace. The donor tells
candidates apart by a lookup, not by anything on the wire: it maps the verified
TLS peer SPKI plus the selected profile through a pairing catalog to a candidate
identity. One authenticated TLS credential maps to exactly one candidate, and
duplicate pins are rejected when a pairing is admitted to the catalog, using a
constant-time comparison.

> [!IMPORTANT]
> The multi-candidate paths are covered by automated tests only. Physical
> hardware validation has so far exercised one donor with one candidate. See the
> [beta release notes](RKA_BETA_RELEASE_NOTES.md) for the exact unvalidated list.

TEESimulator-RS is a root module, not an application APK. The release ZIP is
installed through KernelSU. Its WebUI extends the existing TEESimulator-RS
surface with paired-runtime, provisioning, lease, and recovery controls, and
shows one status card per candidate.

## What is persisted

1. The donor asks Android Remote Key Provisioning for one fresh certified RKP
   key.
2. The candidate generates a fresh EC P-256 synthetic-lease key.
3. The candidate sends that bounded key material to the donor over pinned,
   mutually authenticated TLS 1.3.
4. The donor imports it into TEE KeyMint as an `ATTEST_KEY`, certifies it beneath
   the RKP key, deletes the temporary imported KeyMint blob, and returns the
   certificate chain.
5. The candidate verifies the key match, attestation extension, chain edges,
   validity, profile epoch, and peer identity before atomically storing the
   lease.

Those steps run per candidate. The lease private key and certificate chain are
then local to that candidate. App key generation, signing, and attestation do not
require a live donor connection. The current beta issues seven-day leases;
reconnect the donor and the candidate to renew.

## How concurrency actually works

Each candidate is served by its own actor, so one candidate's slow network does
not block another. All of that work then funnels through a single donor-wide
fair round-robin scheduler that runs **exactly one physical TEE command at a
time**. This buys fair interleaving and non-blocking network progress. It does
not buy parallel TEE throughput.

Fixed quotas:

| Scope | Limit |
| --- | --- |
| Paired candidates in the catalog | 32 |
| Live sessions, donor-wide | 4 |
| Keys per candidate | 4 |
| Keys donor-wide | 16 |
| Live operations per candidate | 1 |
| Physical TEE commands in flight | 1 |

A handle belonging to another candidate is rejected exactly like an unknown
handle. A candidate disconnecting quarantines only that candidate. Broker or
KeyMint death on the donor affects all candidates.

## Beta requirements

- One rooted arm64 donor device plus one or more rooted arm64 candidate devices,
  all with KernelSU and Zygisk.
- The donor has working TEE KeyMint and working Google RKP.
- Each candidate has working native TEE EC P-256 key generation and signing.
- Every device has exactly one active, globally scoped Wi-Fi IPv4 address, and
  the donor can route directly to each candidate on TCP 37373.
- A Linux host with ADB platform tools, Bash, Python 3, JDK 21, and a clean clone
  of the exact signed release tag.
- The Release ZIP and its adjacent `.source-sha` asset.

ADB serials may be USB serials or network ADB endpoints. They are only the
management channel. The paired data plane is direct Wi-Fi and does not use
`adb forward`, `adb reverse`, or an ADB byte relay.

## Before installation

The module ID is `tricky_store`. It cannot coexist with another installed
TrickyStore or TEESimulator module using that ID. Installing this beta is an
in-place upgrade and retains the familiar configuration path. Back up the
existing directory first if you may want to roll back:

```bash
adb -s <DEVICE> shell su -c \
  'tar -C /data/adb -czf /data/local/tmp/tricky-store-backup.tgz tricky_store'
adb -s <DEVICE> pull /data/local/tmp/tricky-store-backup.tgz
```

The Release ZIP is recommended. The Debug ZIP has the same RKA behavior but
contains additional diagnostics and an internal service APK for debug loading;
the ZIP itself is still installed as a root module.

## Normal module installation

Install the same Release ZIP on the donor and on every candidate in KernelSU
Manager, then reboot each phone once. A reboot is the normal module activation
path because Zygisk and the keystore interception layer must load in the correct
process context.

After that normal activation, run the guarded paired deploy below once. It
reuses the identical ZIP while assigning roles, establishing transport trust,
and activating the direct profiles without another reboot.

The repository also has a guarded `--no-reboot` deployer for development and
recovery. It was used for the physical beta demonstration. It supports only the
exact KernelSU layouts that pass its preflight; an unsupported root-manager
layout fails before uploading the archive.

## Bind and deploy

Work from a clean clone of the release tag. Download the Release ZIP and its
`.source-sha` into the same directory. Do not rename only one of them.

`--candidate` and `--profile` may repeat, and they pair positionally: the first
`--candidate` takes the first `--profile`, the second takes the second, and so
on. Bind one candidate for a single pairing, or several for a multi-candidate
donor.

```bash
./gradlew :rka-host:installDist
export PATH="$PWD/rka-host/build/install/rka-host/bin:$PATH"
export RKA_RUNTIME_DIR="$PWD/.rka-beta"

rka-host device-pair bind \
  --donor <DONOR_ADB_SERIAL> \
  --candidate <CANDIDATE_A_ADB_SERIAL> \
  --profile tests/fixtures/profile-candidate-a.json \
  --candidate <CANDIDATE_B_ADB_SERIAL> \
  --profile tests/fixtures/profile-candidate-b.json

scripts/rka-with-device-pair.sh \
  --pair "$RKA_RUNTIME_DIR/device-pair.json" -- \
  scripts/rka-deploy.sh \
  --pair-fd-env RKA_DEVICE_PAIR_FD \
  --zip "$PWD/<RELEASE_ZIP>" \
  --network direct-auto \
  --no-reboot \
  --evidence "$RKA_RUNTIME_DIR/deploy-receipt.json"
```

`device-pair.json` is now `schema_version` 2 and carries a `candidates` array.
The v1 reader is retained, so an existing single-candidate descriptor still
loads.

The deployer installs the same archive on every device, assigns `DONOR` to the
donor and `CANDIDATE` to each candidate, creates fresh transport identities,
pins their certificates, discovers the Wi-Fi endpoints, writes the direct
profiles, starts the runtime, and performs one TLS 1.3 reachability check per
candidate.

The donor holds one profile per candidate at
`profiles/direct.d/<candidate>.conf`. Each candidate device keeps its existing
single `profiles/direct.conf`, so nothing changes from a candidate's own point
of view. Donor-side runtime paths are indexed by candidate:

```text
run/sockets/broker-<candidate>.sock
run/pids/sidecar-<candidate>.pid
run/pids/broker-<candidate>.pid
run/direct-profile-<candidate>.receipt
run/supervisor-<candidate>.state
```

Durable donor state lives under `candidates/<candidate-identity-hash>/`.
Migration from the older single-candidate layout happens once and atomically:
validate, stage, fsync, atomic rename, then commit a manifest. Legacy state is
retained. Automatic deletion of legacy state is disabled by default and requires
an explicit opt-in.

Do not repeatedly run a separate TCP probe against a live candidate listener.
The standard deployer already performs the bounded direct-path check.

## Donor RKP properties

Correct production ROMs normally provide these properties. On a development
ROM that omitted them, set them on the donor before provisioning:

```bash
adb -s <DONOR_ADB_SERIAL> shell su -c \
  'setprop remote_provisioning.hostname remoteprovisioning.googleapis.com'
adb -s <DONOR_ADB_SERIAL> shell su -c \
  'setprop remote_provisioning.enable_rkpd true'
```

These `setprop` values are runtime state. Reapply them after a donor reboot when
the ROM does not set them from init. They are not required on a candidate.

## Provision and issue the lease

Open the TEESimulator-RS WebUI in KernelSU on each device.

1. On the donor, refresh status. The WebUI renders one status card per paired
   candidate. Confirm `Donor`, `Paired`, `Ready`, and `Running`, and find the
   card for the candidate you are provisioning.
2. Press **Provision donor lease** on that candidate's card. Copy the displayed
   one-time confirmation token into the confirmation field and submit it. The
   lease controls on each card are gated independently.
3. Keep the donor's RKA supervisor running. The current donor opaque-blob
   resolver is process-local, so do not restart the donor runtime between
   steps 2 and 4.
4. On that candidate, refresh status and press **Issue / renew candidate lease**.
   Confirm the action with its one-time token.
5. Refresh the candidate. Confirm `synthetic lease: Active`, `lease next: Empty`,
   and a future lease-valid-until time.

Repeat steps 1 through 5 for each further candidate.

Provisioning does not replace or clear an existing Android RKP lease. It asks
for one additional fresh key for the RKA issuance transaction.

The on-device control interface takes an optional candidate selector:

```text
webui ACTION NONCE [CONFIRMATION] [--candidate CANDIDATE]
```

All 18 existing action verbs are unchanged. Omit `--candidate` for a donor with
a single paired candidate.

## Select applications

On each candidate, add an explicit `?` entry for each application that should
use that candidate's synthetic lease:

```text
io.github.vvb2060.keyattestation?
com.example.app?
```

`?` keeps that candidate's native hardware-backed application key and patches
its attestation chain with its own active synthetic lease. Updating `target.txt`
does not require a new donor provision, a new pairing, or a reboot, and it does
not affect any other candidate.

Existing aliases keep their old certificate chain. In a key-attestation app,
request a new key/alias after activating the lease. If the app caches its last
result, clear only the app's test key or app data; do not clear the RKA lease.

## Offline verification

After a candidate reports an active lease, disconnect the donor from the
candidate network or stop only the donor RKA runtime. Generate a new challenged
EC P-256, SHA-256 signing key in a selected app on that candidate and perform one
signature.

Expected behavior:

- the candidate operation succeeds with the donor offline;
- the application key's public key remains the candidate's native key;
- the returned chain is rooted through the stored synthetic lease;
- unlisted applications and StrongBox remain on their normal platform path.

A phone reboot is not required to observe a newly issued lease. Reboot is only
the normal first-install activation step. A fresh attestation alias is required
when the test application otherwise displays an older cached chain.

## Renewal

Each candidate's lease is renewed on its own, before that candidate's displayed
expiry:

1. Put the donor and the candidate on the same routed Wi-Fi network.
2. Ensure the donor can reach that candidate on TCP 37373.
3. Reapply the two donor properties if the development ROM lost them.
4. On the donor, provision one fresh donor lease from that candidate's status
   card.
5. Without restarting the donor RKA runtime, use **Issue / renew candidate
   lease** on the candidate.
6. Confirm that candidate's lease epoch increased and `lease next` returned to
   `Empty`.

Repeat for each candidate that needs renewal. A candidate keeps using its
current lease until the replacement is fully validated and atomically activated,
and renewing one candidate does not disturb another's lease.

## Recovery and rollback

The WebUI can stop/start only the RKA runtime and can restart `keystore2` or
`rkpd` without rebooting the phone. Use the narrow recovery buttons before
considering a full device reboot. On the donor, re-check the two RKP properties
after any recovery on a ROM with missing defaults.

Failure is scoped differently depending on what broke. A candidate that
disconnects quarantines only that candidate; the others keep working. Death of
the donor broker or of KeyMint affects every candidate.

To roll back, install the previous module ZIP through KernelSU and reboot. Roll
back each device you changed. If necessary, restore the configuration backup
only after stopping the module. Never copy lease state, transport secrets, or
trust files between candidates or between different pairings. Legacy
single-candidate state is retained after migration, and automatic deletion of it
is disabled by default, so a rollback still has the old state to fall back on
unless you explicitly opted into deletion.

## Known beta limits

- The multi-candidate paths are covered by automated tests only and have not yet
  been exercised on physical hardware. Physical validation so far used one donor
  and one candidate.
- Serving several candidates does not make the TEE faster. Exactly one physical
  TEE command runs at a time, donor-wide; the scheduler only interleaves fairly.
- `direct-auto` currently supports the proven Wi-Fi topology only. Tailscale is
  suitable as an ADB management path, but automatic Tailscale data-plane
  selection is not part of this beta.
- Wi-Fi addresses may change under DHCP. Re-run the signed pairing deploy after
  an address change; a reserved DHCP lease is recommended.
- Donor provisioning and candidate issuance must use one uninterrupted donor
  broker lifetime because opaque KeyMint blob resolution is process-local.
- Renewal is manual. There is no background scheduler in this beta.
- The persistent lease path is explicitly selected with `?` entries and is
  limited to TEE EC P-256/SHA-256 signing attestations.
- Physical validation covers arm64 KernelSU/Zygisk devices. Other root managers
  remain supported by the original local module path but are not RKA-beta
  validated.

## Verify downloaded assets

Download `SHA256SUMS` with the ZIPs and run:

```bash
sha256sum -c SHA256SUMS
git tag -v <RELEASE_TAG>
```

The GitHub release is marked as a prerelease. The stable `update.json` feed is
not changed by this beta.
