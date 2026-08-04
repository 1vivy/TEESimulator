# TEESimulator-RS two-device RKA beta 1

This prerelease adds a persistent, donor-backed Remote Key Provisioning path to
the existing TEESimulator-RS module and KernelSU WebUI.

## Highlights

- One role-neutral module ZIP for both phones.
- Runtime pairing assigns Phone A as donor and Phone B as candidate.
- Fresh Android RKP provisioning on the donor without replacing its existing
  lease inventory.
- Candidate-owned synthetic `ATTEST_KEY` certified through the donor's TEE and
  genuine RKP chain.
- Atomic candidate lease persistence with a seven-day validity window and
  epoch-based renewal.
- Offline candidate attestation and signing after issuance; the donor does not
  need to remain connected for application operations.
- Explicit `target.txt` `?` routing, so more apps can use the same active lease
  without re-pairing or contacting the donor.
- Existing local keybox behavior and KernelSU Action button retained; the added
  WebUI exposes RKA controls in the same module.
- Mutual TLS 1.3, exact certificate/SPKI trust, bounded frames, replay rejection,
  request correlation, and fail-closed state publication.
- Direct Wi-Fi pairing automation on TCP 37373 with no ADB forwarding in the
  RKA data path.

## Physical beta result

The release candidate was exercised on two physical rooted Android devices over
direct Wi-Fi. Phone A obtained a fresh Google RKP key. Phone B received and
persisted a five-certificate synthetic lease chain, then renewed it from epoch 1
to epoch 2. Candidate network counters changed during issuance while both ADB
forward and reverse tables remained empty. The stored lease continued to serve
fresh candidate attestations with the donor unavailable.

The validation used subsystem restarts where needed and did not require a phone
reboot. Normal end-user module installation still requires the usual KernelSU
install and reboot so Zygisk loads the interception path.

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

- First beta is physically validated on arm64 KernelSU/Zygisk only.
- Automatic data-plane discovery currently requires direct routed Wi-Fi on both
  devices; Tailscale may still be used for ADB management.
- DHCP address changes require re-pairing unless addresses are reserved.
- The donor broker must stay alive between provisioning and candidate issuance
  because the current opaque KeyMint-blob resolver is process-local.
- Renewal is manual and should happen before the seven-day lease expires.
- Candidate lease routing is opt-in through explicit `?` targets and covers TEE
  EC P-256/SHA-256 signing attestation, not StrongBox or arbitrary KeyMint calls.
- Phone B must have a functional native TEE signing backend; the synthetic lease
  does not repair a broken local KeyMint implementation.

This is a beta prerelease. Do not deploy it as the only attestation path on a
device you cannot recover through root/ADB.
