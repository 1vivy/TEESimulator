# TEESimulator – API36 safety fork

This history-preserving GPLv3 fork is developing a narrowly scoped Android
16/API36 compatibility probe around the upstream TEESimulator injector.
The current release state is **probe-only and default-inert**. It makes no
claim that live insertion is compatible or safe.

Boot and module-action lifecycles do not invoke the injector or the preserved
`app_process` bootstrap. No keybox, private key, target list, or SELinux policy
is bundled. Installing this development branch on a device is not part of the
documented gate workflow.

## Safety gates

`scripts/verify.sh` is G0. It checks tests, shell parsing, source/provenance,
forbidden material, module contents, an arm64 release build, and repeatability.

`scripts/probe-api36.sh` is G1. It is a host-side read-only probe: no device
file transfer or creation, tracing, injection, key creation, property change,
or service restart. It prints identifier-free `PASS` or `STOP` lines. Any
`STOP` forbids injection.

The expected device shape is recorded without a fingerprint or identifier in
`profiles/api36-arm64-qcom-default-v1.conf`.

G2 requires a native default-attestation baseline and a controlled keystore2
restart/recovery rehearsal. G2 tooling is not implemented in the current
probe-only state. Consequently, no live insertion is authorized.

## Deliberate exclusions

StrongBox and AVF are pass-through-only and must never be targeted. Android
remote provisioning CSR/certification APIs are outside scope. The external
`MhmRdd/google-rkp-sw@8a74e55` repository is documentation context only: it is
not included, invoked, or a build dependency.

The upstream injector and bootstrap source remain in history and in the source
tree for compatibility work, but inert lifecycle scripts do not call them.
See `PROVENANCE.md` and `THIRD_PARTY_NOTICES.md`.
