# TEESimulator-RS donor-backed RKA beta 1

This prerelease adds a persistent, donor-backed Remote Key Provisioning path to
the existing TEESimulator-RS module and KernelSU WebUI. One donor phone can serve
several candidate phones concurrently.

## Highlights

- One role-neutral module ZIP for every phone.
- Runtime pairing assigns one device as donor and one or more devices as
  candidates.
- Each candidate has its own identity, pinned TLS trust, paired activation
  record, and isolated lease and key namespace.
- The public v2 wire protocol did not change. Candidate routing is an internal
  lookup: the donor maps the verified TLS peer SPKI plus the selected profile
  through a pairing catalog to a candidate identity. There is no candidate field
  on the wire. The 21 canonical v2 golden vectors and 6 v1 hash pins are
  byte-identical.
- One authenticated TLS credential maps to exactly one candidate. Duplicate pins
  are rejected at catalog admission with a constant-time comparison.
- Fresh Android RKP provisioning on the donor without replacing its existing
  lease inventory.
- Candidate-owned synthetic `ATTEST_KEY` certified through the donor's TEE and
  genuine RKP chain.
- Atomic candidate lease persistence with a seven-day validity window and
  epoch-based renewal, per candidate.
- Offline candidate attestation and signing after issuance; the donor does not
  need to remain connected for application operations.
- Explicit `target.txt` `?` routing, so more apps can use the same active lease
  without re-pairing or contacting the donor.
- The donor reads one profile per candidate from
  `profiles/direct.d/<candidate>.conf`, and its on-device runtime paths are
  candidate-indexed. Each candidate device keeps its existing single
  `profiles/direct.conf`, so candidate phones are unchanged from their own
  perspective.
- Host CLI `rka-host device-pair bind` accepts repeating `--candidate` and
  `--profile` flags that pair positionally. `device-pair.json` is now
  `schema_version` 2 with a `candidates` array; the v1 reader is retained.
- On-device control accepts an optional `--candidate CANDIDATE` selector. All 18
  existing action verbs are unchanged.
- The donor WebUI renders one pairing-status card per candidate. Donor RKP
  provisioning is candidate-scoped and bound to that candidate's current broker
  generation; each candidate renews its own lease from its local WebUI. A
  multi-candidate donor's network form is read-only because addresses are updated
  per candidate through the host bind/deploy workflow. Protected actions retain
  one-time-token confirmation.
- Durable state moved to `candidates/<candidate-identity-hash>/`. Migration from
  the old single-candidate layout is one-time and atomic: validate, stage, fsync,
  atomic rename, commit manifest. Legacy state is retained, and automatic legacy
  deletion is disabled by default and requires an explicit opt-in.
- Existing local keybox behavior and KernelSU Action button retained; the added
  WebUI exposes RKA controls in the same module.
- Mutual TLS 1.3, exact certificate/SPKI trust, bounded frames, replay rejection,
  request correlation, and fail-closed state publication.
- Direct Wi-Fi pairing automation on TCP 37373 with no ADB forwarding in the
  RKA data path.

## Concurrency, stated plainly

Each candidate is served by its own actor, and all work funnels through a single
donor-wide fair round-robin scheduler that runs exactly one physical TEE command
at a time. This buys fair interleaving and non-blocking network progress. It does
**not** buy parallel TEE throughput.

Quotas: 32 paired candidates in the catalog; 4 live sessions donor-wide; 4 keys
per candidate and 16 donor-wide; 1 live operation per candidate; 1 physical TEE
command in flight.

Isolation: a handle belonging to another candidate is rejected exactly like an
unknown handle. A candidate disconnect quarantines only that candidate. Broker or
KeyMint death affects all candidates.

## Validated scope

> [!IMPORTANT]
> The multi-candidate behavior described above is proven by the automated test
> suites only. It has **not** been physically validated on hardware. Only one
> donor paired with one candidate has ever been exercised on real phones.

Automated coverage: the Rust workspace, Android unit tests, protocol golden
vectors, host CLI tests, Python supervisor/relay tests, and headless Playwright
WebUI tests.

### Physical beta result (one donor, one candidate)

The release candidate was exercised on two physical rooted Android devices over
direct Wi-Fi. The donor obtained a fresh Google RKP key. The candidate received
and persisted a five-certificate synthetic lease chain, then renewed it from
epoch 1 to epoch 2. Candidate network counters changed during issuance while both
ADB forward and reverse tables remained empty. The stored lease continued to
serve fresh candidate attestations with the donor unavailable.

The validation used subsystem restarts where needed and did not require a phone
reboot. Normal end-user module installation still requires the usual KernelSU
install and reboot so Zygisk loads the interception path.

### Unvalidated on hardware

The following are covered by automated tests only and have not yet been
exercised on physical hardware. Reproducing them needs at least three rooted
arm64 devices.

- Concurrent TEE contention from two candidates against one real KeyMint device.
- Concurrent pinned TLS to two candidate phones.
- Seven-day lease persistence across reboot on multiple candidates.
- Real `keystore2` interception with two live candidate UIDs.
- Multi-candidate deploy and rollback on real devices.
- Donor `binderDied` under multi-candidate load.
- The sealed device-pair descriptor handoff carrying two candidates.

## Assets

- `TEESimulator-RS-*-Release.zip` — recommended beta module.
- `TEESimulator-RS-*-Debug.zip` — diagnostic module with debug-only logging.
- `TEESimulator-RS-*-Release.zip.source-sha` — source commit bound to the
  Release archive and required by the guarded no-reboot deployer.
- `SHA256SUMS` — checksums for all published binary/receipt assets.

Both ZIPs are root-module installers. Neither is a standalone Android APK.

## Upgrade notes

The module ID remains `tricky_store`. Installing this prerelease upgrades an
existing TrickyStore/TEESimulator installation in place and avoids a second
colliding module. Back up `/data/adb/tricky_store` before testing. The existing
configuration and KernelSU Action button remain; the added WebUI exposes RKA
controls without creating a second module.

Use the [RKA beta guide](RKA_BETA_GUIDE.md) for exact installation, pairing,
provisioning, app-selection, offline-demo, renewal, and rollback instructions.

## Known limitations

- First beta is physically validated on arm64 KernelSU/Zygisk only, and only for
  one donor with one candidate. Multi-candidate operation is covered by
  automated tests only; it is not yet exercised on physical hardware.
- Serving several candidates does not increase TEE throughput. Exactly one
  physical TEE command runs at a time, donor-wide.
- Automatic data-plane discovery currently requires direct routed Wi-Fi on every
  participating device; Tailscale may still be used for ADB management.
- DHCP address changes require re-pairing unless addresses are reserved.
- The donor broker must stay alive between provisioning and candidate issuance
  because the current opaque KeyMint-blob resolver is process-local.
- Renewal is manual and should happen before the seven-day lease expires.
- Candidate lease routing is opt-in through explicit `?` targets and covers TEE
  EC P-256/SHA-256 signing attestation, not StrongBox or arbitrary KeyMint calls.
- Each candidate must have a functional native TEE signing backend; the
  synthetic lease does not repair a broken local KeyMint implementation.
- Donor broker or KeyMint death affects every paired candidate, not just one.

This is a beta prerelease. Do not deploy it as the only attestation path on a
device you cannot recover through root/ADB.
