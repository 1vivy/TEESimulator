# Two-device RKA beta guide

This beta gives TEESimulator-RS a renewable, donor-backed RKP path. Phone A is
the donor. Phone B is the candidate. Both use the same role-neutral module ZIP;
the pairing profile assigns their roles at runtime.

TEESimulator-RS is a root module, not an application APK. The release ZIP is
installed through KernelSU. Its WebUI extends the existing TEESimulator-RS
surface with paired-runtime, provisioning, lease, and recovery controls.

## What is persisted

1. Phone A asks Android Remote Key Provisioning for one fresh certified RKP key.
2. Phone B generates a fresh EC P-256 synthetic-lease key.
3. The candidate sends that bounded key material to the donor over pinned,
   mutually authenticated TLS 1.3.
4. Phone A imports it into TEE KeyMint as an `ATTEST_KEY`, certifies it beneath
   the RKP key, deletes the temporary imported KeyMint blob, and returns the
   certificate chain.
5. Phone B verifies the key match, attestation extension, chain edges, validity,
   profile epoch, and peer identity before atomically storing the lease.

The lease private key and certificate chain are then local to Phone B. App key
generation, signing, and attestation do not require a live donor connection.
The current beta issues seven-day leases; reconnect both phones to renew.

## Beta requirements

- Two rooted arm64 Android devices with KernelSU and Zygisk.
- Phone A has working TEE KeyMint and working Google RKP.
- Phone B has working native TEE EC P-256 key generation and signing.
- Both phones have exactly one active, globally scoped Wi-Fi IPv4 address and
  can route directly from Phone A to Phone B on TCP 37373.
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

Install the same Release ZIP on both phones in KernelSU Manager and reboot each
phone once. A reboot is the normal module activation path because Zygisk and the
keystore interception layer must load in the correct process context.

After that normal activation, run the guarded paired deploy below once. It
reuses the identical ZIP while assigning roles, establishing transport trust,
and activating the direct profile without another reboot.

The repository also has a guarded `--no-reboot` deployer for development and
recovery. It was used for the physical beta demonstration. It supports only the
exact KernelSU layouts that pass its preflight; an unsupported root-manager
layout fails before uploading the archive.

## Bind and deploy the pair

Work from a clean clone of the release tag. Download the Release ZIP and its
`.source-sha` into the same directory. Do not rename only one of them.

```bash
./gradlew :rka-host:installDist
export PATH="$PWD/rka-host/build/install/rka-host/bin:$PATH"
export RKA_RUNTIME_DIR="$PWD/.rka-beta"

rka-host device-pair bind \
  --donor <PHONE_A_ADB_SERIAL> \
  --candidate <PHONE_B_ADB_SERIAL> \
  --profile tests/fixtures/profile-candidate.json

scripts/rka-with-device-pair.sh \
  --pair "$RKA_RUNTIME_DIR/device-pair.json" -- \
  scripts/rka-deploy.sh \
  --pair-fd-env RKA_DEVICE_PAIR_FD \
  --zip "$PWD/<RELEASE_ZIP>" \
  --network direct-auto \
  --no-reboot \
  --evidence "$RKA_RUNTIME_DIR/deploy-receipt.json"
```

The deployer installs the same archive on both devices, assigns `DONOR` to
Phone A and `CANDIDATE` to Phone B, creates fresh transport identities, pins
their certificates, discovers both Wi-Fi endpoints, writes the direct profiles,
starts the runtime, and performs one TLS 1.3 reachability check.

Do not repeatedly run a separate TCP probe against the live candidate listener.
The standard deployer already performs the bounded direct-path check.

## Donor RKP properties

Correct production ROMs normally provide these properties. On a development
ROM that omitted them, set them on Phone A before provisioning:

```bash
adb -s <PHONE_A_ADB_SERIAL> shell su -c \
  'setprop remote_provisioning.hostname remoteprovisioning.googleapis.com'
adb -s <PHONE_A_ADB_SERIAL> shell su -c \
  'setprop remote_provisioning.enable_rkpd true'
```

These `setprop` values are runtime state. Reapply them after a donor reboot when
the ROM does not set them from init. They are not required on Phone B.

## Provision and issue the lease

Open the TEESimulator-RS WebUI in KernelSU on each device.

1. On Phone A, refresh status. Confirm `Donor`, `Paired`, `Ready`, and `Running`.
2. Press **Provision donor lease**. Copy the displayed one-time confirmation
   token into the confirmation field and submit it.
3. Keep Phone A's RKA supervisor running. The current donor opaque-blob resolver
   is process-local, so do not restart the donor runtime between steps 2 and 4.
4. On Phone B, refresh status and press **Issue / renew candidate lease**.
   Confirm the action with its one-time token.
5. Refresh Phone B. Confirm `synthetic lease: Active`, `lease next: Empty`, and a
   future lease-valid-until time.

Provisioning does not replace or clear an existing Android RKP lease. It asks
for one additional fresh key for the RKA issuance transaction.

## Select applications

On Phone B, add an explicit `?` entry for each application that should use the
synthetic lease:

```text
io.github.vvb2060.keyattestation?
com.example.app?
```

`?` keeps the candidate's native hardware-backed application key and patches
its attestation chain with the active synthetic lease. Updating `target.txt`
does not require a new donor provision, a new pair, or a reboot.

Existing aliases keep their old certificate chain. In a key-attestation app,
request a new key/alias after activating the lease. If the app caches its last
result, clear only the app's test key or app data; do not clear the RKA lease.

## Offline verification

After Phone B reports an active lease, disconnect Phone A from the candidate
network or stop only the donor RKA runtime. Generate a new challenged EC P-256,
SHA-256 signing key in a selected app on Phone B and perform one signature.

Expected behavior:

- the candidate operation succeeds with Phone A offline;
- the application key's public key remains the candidate's native key;
- the returned chain is rooted through the stored synthetic lease;
- unlisted applications and StrongBox remain on their normal platform path.

A phone reboot is not required to observe a newly issued lease. Reboot is only
the normal first-install activation step. A fresh attestation alias is required
when the test application otherwise displays an older cached chain.

## Renewal

Renew before the displayed expiry:

1. Put both phones on the same routed Wi-Fi network.
2. Ensure Phone A can reach Phone B on TCP 37373.
3. Reapply the two donor properties if the development ROM lost them.
4. On Phone A, provision one fresh donor lease.
5. Without restarting the donor RKA runtime, use **Issue / renew candidate
   lease** on Phone B.
6. Confirm Phone B's lease epoch increased and `lease next` returned to `Empty`.

The candidate keeps using the current lease until the replacement is fully
validated and atomically activated.

## Recovery and rollback

The WebUI can stop/start only the RKA runtime and can restart `keystore2` or
`rkpd` without rebooting the phone. Use the narrow recovery buttons before
considering a full device reboot. On the donor, re-check the two RKP properties
after any recovery on a ROM with missing defaults.

To roll back, install the previous module ZIP through KernelSU and reboot. If
necessary, restore the configuration backup only after stopping the module.
Never copy candidate lease state, transport secrets, or trust files between
different pairs.

## Known beta limits

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
