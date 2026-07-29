# RKA Implementation Handoff

Implementation reference for a zero-context agent starting from a clean clone.
This document contains implementation truth only. Where any internal note
disagrees with the source tree, the source tree wins; such contradictions are
called out explicitly.

## Implementation bootstrap

Obtain the source with exactly:

```
git clone --depth 1 --single-branch --branch api36-insertion https://github.com/1vivy/TEESimulator.git
```

Sequencing guard: this command is valid only after the delivery commit
containing this document has been pushed to remote branch `api36-insertion`.
Do not assume any pre-push tip already contains this document; verify the
fetched tree includes `docs/RKA_IMPLEMENTATION_HANDOFF.md` before relying on
it.

History boundary: earlier commits on the remote contain blobs that were later
deleted from the tree (keybox material). Those blobs are not part of any
current-source contract described here, and they remain reachable only
through history. The clone flags above bound the local repository to the tip
of `api36-insertion` and to that branch alone, so no deleted blob is fetched.

Do not run `git fetch --unshallow`, `git fetch` for other refs or tags, or
`git clone` without these flags until the remote history has been sanitized.
Any command that deepens or widens the ref set crosses the boundary and pulls
the deleted material into the local object store. If an operation
fundamentally requires history (for example `git log -S` or `git blame` past
the tip), treat it as out of scope for the clean-room workflow.

All contracts in this document are verifiable from the single-branch tip
alone; no history access is required for any acceptance command.

## Task

Continue the two-phone remote KeyMint attestation (RKA) work in this
repository: finish the host-to-fixture transport migration, resolve the
physical donor-side signing boundary, complete gate G2, then run physical
deployment, transport QA, and the final remote KeyMint proof, in that order.

## Context (technical scope)

Two Android phones are paired over a mutually authenticated TLS 1.3 channel:

- Phone A ("donor") holds all private-key material in its own hardware-backed
  Android Keystore and serves normalized key-lifecycle and signing operations.
- Phone B ("target") intercepts selected KeyMint calls from one approved
  fixture package and routes them to the donor as opaque, pair-bound handles.

A host machine orchestrates both phones over adb. A paired fixture APK
(`rka-fixture`) runs on each phone in either `DONOR` or `TARGET` role and is
the host's on-device command surface. Three safety gates (G0/G1/G2) control
what is authorized. The Magisk-module entry points are default-inert; no live
insertion is authorized by the documented gates.

Roles are bound by deployment, not by the wire protocol, which is
role-agnostic. All device identity is parameterized: serials via
`--serial-a/--serial-b`, models via `--expected-model-a/--expected-model-b`,
donor endpoint via `--donor-endpoint host:port`, module directory via
`--module-dir`.

## Relevant files

Module graph (`settings.gradle.kts` includes all five):

| Module | Kind | Depends on | Purpose |
|---|---|---|---|
| `two-phone` | JVM Kotlin 21 library | bcpkix (test scope only) | Normalized wire protocol, public profiles, dispatcher, in-memory backend |
| `physical-harness` | Android library (minSdk 36) | `:two-phone`, bcpkix | Donor service, donor keystore backend, durable state, TLS server, fixture runtime support |
| `rka-fixture` | Android application (min/target 36) | `:physical-harness`, `:two-phone` | On-device fixture APK: command provider, attestation core, roles, profile install |
| `stub` | Android library (compileOnly stubs) | — | Framework stubs for compilation |
| `app` | Android application (min 29/target 36, arm64-v8a, CMake) | `:stub`, `:two-phone`, `:physical-harness`, bcpkix | Root-side target: binder interception, KeyMint shim, two-phone client |

Root `build.gradle.kts` wires ktfmt (`format` task, `kotlinLangStyle`).
Build entry points used by gates: `:app:testDebugUnitTest`, `:two-phone:test`,
`:physical-harness:test` (JVM task, not `testDebugUnitTest`),
`:physical-harness:ktfmtCheck`, `:physical-harness:lintDebug`,
`:physical-harness:assembleRelease`, `:rka-fixture:testDebugUnitTest`,
`:rka-fixture:ktfmtCheck`, `:rka-fixture:lintDebug`,
`:rka-fixture:assembleRelease` (depends on task `signFixtureReleaseApk` ->
`scripts/sign-fixture-release-apk.sh`), `:app:zipRelease`. Release signing is
externalized; no Gradle `signingConfigs` exist.

## Current state

Status taxonomy: `IMPLEMENTED+TESTED` / `IMPLEMENTED+UNVERIFIED` /
`BLOCKED` / `NOT STARTED` / `NOT-YET-MIGRATED`.

| Subsystem | Status |
|---|---|
| Wire protocol, profiles, dispatcher (`two-phone`) | IMPLEMENTED+TESTED |
| Fixture provider, staging, replay, attestation core (`rka-fixture`) | IMPLEMENTED+TESTED (device surface); physical accept-sign BLOCKED |
| Donor service, state, keystore backend, TLS server (`physical-harness`) | IMPLEMENTED+TESTED |
| Target interception policy, KeyMint shim, two-phone client (`app`) | IMPLEMENTED+TESTED (JVM); live insertion NOT AUTHORIZED |
| Host orchestration (`scripts/two_phone_*.py`) | IMPLEMENTED+TESTED vs fakes; fixture transport NOT-YET-MIGRATED |
| G0 (`scripts/verify.sh`) | IMPLEMENTED+GREEN |
| G1 (`scripts/probe-api36.sh`) | IMPLEMENTED+GREEN |
| G2 (`scripts/gate-g2.py`) | SCAFFOLDED; BLOCKED on physical boundary |
| Physical deployment/preflight, transport QA, final RKA proof | NOT STARTED |

### Two-phone wire protocol (`two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/`)

`Protocol.kt`:

- `ProtocolVersion { V1 }`; `Method { GENERATE, IMPORT, GET_METADATA, DELETE,
  BEGIN, UPDATE_AAD, UPDATE, FINISH, ABORT }`.
- `PairIdentity(targetPin, donorPin)`; `CallerIdentity(uid,
  signingCertificateDigest, attestationApplicationIdDigest)`. Producers emit
  the two digests as lowercase-hex SHA-256, but the fields are raw `String`
  and the type does not enforce that format.
- `CanonicalBody`: max 64 fields, name <= 128 B, value <= 1 MiB, body <=
  2 MiB; fields sorted by name; `writeInt(count)` then per field
  `writeInt(nameLen) + name + writeInt(valueLen) + value`, big-endian.
- `RequestId`: exactly 16 bytes. Session id =
  `sha256(canonical("two-phone-v1", targetPin, donorPin, clientNonce,
  serverNonce))`; both nonces exactly 32 B.
- Sequences start at `0uL`, increment by 1, `SequenceOverflow` at
  `ULong.MAX_VALUE`. `ProtocolException` subclasses: `OldSession`,
  `SequenceDuplicate`, `SequenceGap`, `SequenceOverflow`, `RequestIdReuse`,
  `InvalidBodyHash`, `DeadlineExceeded`, `WrongPair`, `WrongCaller`.
- Completed request ids replay their cached response; a reused id with a
  different fingerprint is rejected.

`NormalizedWireCodec.kt`:

- `MAGIC=0x54504b31`, `VERSION_V1=1`, `REQUEST_FRAME=1`, `RESPONSE_FRAME=2`,
  `SUCCESS_OUTCOME=1`, `ERROR_OUTCOME=2`, `MAX_FRAME_BYTES=2_097_152`.
- Bounds: session/nonce/payloadHash 32 B; identity <= 1024 B; challenge
  1..128 B; handle binding <= 1024 B; operation input <= 1 MiB; public key <=
  64 KiB; certificate <= 256 KiB; <= 16 certificates.
- Request payload tags `0x1001..0x1009` (GENERATE..ABORT); result tags
  `0x2001, 0x2003..0x2009` (no import result); error tags `0x3001..0x300f`;
  key-state tags 1..7; algorithm/curve/digest/purpose spec tags all `1`.
- `payloadHash` = SHA-256 over `u16(payloadTag) || payload bytes`.
- Frame header: `magic(i32) + version(u16) + frameType(u8) + method(u16) +
  payloadTag(u16, requests only)`. Transport framing is a 4-byte big-endian
  length prefix (`WireCodecIo.kt`, `BoundedWireFrameIo.kt`); clean EOF is only
  legal before the first prefix byte.

`WireModels.kt`: `WireKeyHandle(id: UUID, binding)`,
`WireOperationHandle(id, keyId, binding)`; fixed enums
`WireKeyAlgorithm.EC`, `WireEcCurve.P256`, `WireDigest.SHA256`,
`WireKeyPurpose.SIGN`; request payloads carry caller-supplied UUIDs
(`generationId`/`deletionId`/`operationId`) and op steps as `ULong`;
`WireErrorCode` (15 values): `UNSUPPORTED_METHOD, MALFORMED_REQUEST,
INVALID_ARGUMENT, DEADLINE_EXCEEDED, WRONG_SESSION, WRONG_CALLER, WRONG_PAIR,
SEQUENCE_ERROR, REQUEST_ID_REUSE, INVALID_HANDLE, INVALID_STATE,
DONOR_UNAVAILABLE, INTERNAL_ERROR, REPLAY_CONFLICT,
INVALID_OPERATION_HANDLE`; `WireOutcome.Success(payload)` /
`WireOutcome.Error(code)`.

`DonorTransportHelloCodec.kt`: client hello body 40 B
(`CLIENT_MAGIC=0x54444348`, version 1, flags 0, 32 B nonce); server hello
body 72 B (`SERVER_MAGIC=0x54445348`, + echoed client nonce + fresh 32 B
server nonce). Hello exceptions: `InvalidNonce`, `InvalidLength`,
`InvalidMagic`, `UnsupportedVersion`, `InvalidFlags`, `Truncated`,
`TrailingData`.

`WireDonorBackend.kt` interface (exact): `generate(BackendGenerate):
BackendGeneratedKey`, `metadata(handle, caller): WireKeyMetadata`,
`delete(BackendDelete)`, `begin(handle, spec, caller): WireOperationHandle`,
`update(op, input, caller): ByteArray`, `finish(op, input, caller):
ByteArray`, `abort(op, caller)`, `close()`. Backend failures are raised as
`WireBackendFailure(code, cause?)`.

`WireDonorDispatcher.kt` validation-to-error order: closed dispatcher ->
`DONOR_UNAVAILABLE`; session mismatch -> `WRONG_SESSION`; payload/method/hash
or codec failure -> `MALFORMED_REQUEST`; deadline outside
`[now, now + DEADLINE_SECONDS]` -> `DEADLINE_EXCEEDED`; request id reused with
different fingerprint -> `REQUEST_ID_REUSE`; sequence mismatch/exhaustion ->
`SEQUENCE_ERROR`; IMPORT -> `UNSUPPORTED_METHOD`; `UPDATE_AAD` is deliberately
unsupported: the operation is aborted, marked terminal, and
`UNSUPPORTED_METHOD` is returned and cached; any op-step backend failure
triggers best-effort abort, marks the operation terminal, caches the failure
outcome. Authenticated replay fingerprint domain is
`"wire-donor-authenticated-request-v1"`. `close()` is idempotent and clears
all operation ledgers before best-effort backend close.

`InMemoryWireDonorBackend.kt`: donor-exception mapping (`WrongCaller ->
WRONG_CALLER`, `WrongPair -> WRONG_PAIR`, `CopiedHandle -> INVALID_HANDLE` or
`INVALID_OPERATION_HANDLE` by call site, `InvalidState -> INVALID_STATE`);
mutation journal keyed by `WireMutationKey(targetPin, donorPin, caller
digests, kind in {GENERATE, DELETE}, id)` plus payload-hash match.

`TargetResponseCorrelator.kt`: one-shot pending registration; duplicate,
unsolicited, wrong-session, wrong-method, and wrong-request-id responses are
rejected.

`Routing.kt` (`SecurityLevel`, `RouteDecision`, `RoutingPolicy`,
`DonorTransport`, `FakePinnedTransport`, `KeyMintSecurityLevelRoutingSeam`,
`InMemoryTargetStore`, `TargetCoordinator`) ships in the main source set but
is unused by production callers; it is exercised only from tests.

Tests (`two-phone/src/test/...`): `NormalizedWireCodecTest` (layout, tags,
hash binding, defensive copies), `WireDonorDispatcherTest` (validation,
sequence/replay, restart reconstruction, terminal semantics, concurrency),
`WireDonorBackendTest` / `WireDonorBackendReviewTest` (delegation, failure
translation, shared-store ownership, cleanup), `WireDonorDispatcherFactoryTest`
(session derivation, close-once), `TargetResponseCorrelatorTest`,
`PublicProfileCodecTest`, `PublicProfileMutationTest` (exact exception per
mutation), `TwoPhoneFoundationTest` (canonical body, session derivation,
donor state machine, routing seam).

### Public profiles and SPKI pinning

`PublicProfileModels.kt` / `PublicProfiles.kt`:

- `FixturePackageIdentity(packageName, versionCode, signerDigest[32])`;
  package name must match `[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+`, versionCode > 0.
- `ProfileEndpoint(address[4|16] non-multicast, port 1..65535)`.
- `ProvisionedTargetIdentity` / `ProvisionedDonorIdentity(alias,
  certificateDer, pin)`; alias `[A-Za-z0-9._-]{1,128}`.
- `TargetPublicProfile`: fixtureIdentity, donorEndpoint, donorTrustChainDer,
  donorPin, targetIdentity, version V1, maxOperations, deadlineSeconds.
- `DonorPublicProfile`: pairIdentity, targetIdentityCertificateDer,
  targetTrustChainDer, targetPin, donorIdentity, bindEndpoint, version V1,
  same bounds.
- `PublicProfileLimits.MAX_OPERATIONS = 1`, `DEADLINE_SECONDS = 120`;
  `requireBounds` rejects any profile carrying different values.

`PublicProfileCodec.kt` / `PublicProfileBinary.kt`:
`MAX_PROFILE_BYTES = 1_048_576`; magics `0x54505031` (target) / `0x44505031`
(donor); header `magic(i32) + version(u16)`; fields `tag(u16) + length(i32) +
value` in strict tag order (target: FIXTURE_PACKAGE, FIXTURE_VERSION,
FIXTURE_SIGNER, DONOR_ENDPOINT, DONOR_TRUST_CHAIN, DONOR_PIN, TARGET_ALIAS,
TARGET_CERTIFICATE, TARGET_PIN, MAX_OPERATIONS, DEADLINE_SECONDS; donor:
PAIR_TARGET_PIN, PAIR_DONOR_PIN, TARGET_CERTIFICATE, TARGET_TRUST_CHAIN,
TARGET_PIN, DONOR_ALIAS, DONOR_CERTIFICATE, DONOR_PIN, BIND_ENDPOINT,
MAX_OPERATIONS, DEADLINE_SECONDS); certificate chains 2..8 certs, each
1..65536 B; empty field values rejected; `decodeTargetFixtureIdentity` reads
the fixture prefix for bootstrap.

`PublicProfileCertificates.kt`: certificates must DER round-trip exactly;
SPKI must re-parse and round-trip; chains must verify signatures and end in a
self-signed CA root. `SpkiPin.kt`: canonical form `sha256/<base64>` (51
chars); pin = SHA-256 over SPKI bytes.

Profile exceptions (`PublicProfileFailures.kt`): 18 `PublicProfileException`
subclasses from `InvalidMagic` through `InvalidBounds`; store-layer
`PublicProfileStoreException` (`OversizedBlob`, `UnexpectedLength`,
`RootOwnershipRequired`, `InvalidOwner`, `InvalidMode`).

Storage: `TargetPublicProfileStore.FILE_PATH =
/data/adb/tricky_store/two-phone-target-v1.bin`, required uid 0, required mode
0600; donor store file `two-phone-donor-v1.bin` under the app
`noBackupFilesDir`. `AtomicPublicProfileFile` writes via
start -> prepare -> finish/fail; oversized blobs rejected; interrupted writes
preserve the previous content.

### Fixture APK (`rka-fixture/src/main/kotlin/org/matrix/teesimulator/rkafixture/`)

Provider entry contract (`FixtureCommandProvider.kt`,
`FixtureProviderProtocol.kt`, `AndroidManifest.xml`):

- Authority `org.matrix.teesimulator.rkafixture.commands`; `exported=true`,
  `grantUriPermissions=false`, guarded by `android.permission.DUMP`.
- Caller authorization is shell-only: UID == `Process.SHELL_UID` and
  attributed package `com.android.shell` must belong to that UID; otherwise
  `UNAUTHORIZED_UID` / `UNVERIFIED_ATTRIBUTION`.
- Exact routes (regex `/v1/(request|execute)/([A-Za-z0-9_-]{22})`):
  - `content://org.matrix.teesimulator.rkafixture.commands/v1/request/{nonce}`
    `openFile` mode `"w"` (upload a request);
  - `content://org.matrix.teesimulator.rkafixture.commands/v1/execute/{nonce}`
    `openFile` mode `"r"` (read the response);
  - `delete()` is accepted only on request routes (cleanup);
  - `call(...)` throws `UnsupportedOperationException("call is unsupported")`;
    `query/insert/update/getType` are unsupported.
  - Any `/vN/` route with N != 1 -> `UNSUPPORTED_VERSION`.
- No broadcast receiver is declared; the provider stream is the only command
  surface.
- Provider error codes (surfaced as `FileNotFoundException(code.name)`):
  `UNAUTHORIZED_UID`, `UNVERIFIED_ATTRIBUTION`, `CROSS_USER_ADDRESS`,
  `INVALID_AUTHORITY`, `INVALID_ROUTE`, `UNSUPPORTED_VERSION`, `INVALID_MODE`,
  `INVALID_NONCE`, `MALFORMED_REQUEST`, `OVERSIZED_REQUEST`,
  `DUPLICATE_UPLOAD`, `UPLOAD_TIMEOUT`, `UPLOAD_INTERRUPTED`,
  `MISSING_REQUEST`, `DUPLICATE_EXECUTE`.

Command model (`FixtureCommand.kt`, `FixtureCommandParser.kt`,
`FixtureCommandResponse.kt`):

- Action constants (`FixtureCommandAction`):
  `org.matrix.teesimulator.rkafixture.v1.PROVISION`, `.START`, `.STATUS`,
  `.ATTEST_SIGN`, `.STOP`. Envelope `VERSION = 1`.
- Request body: strict UTF-8 JSON, regex-enforced key order, <= 1 MiB.
  Shapes: `attest-sign` `{version, command, nonce, challenge, metadata}`;
  `provision` `{..., profile, ...}`; `start` `{..., profileId, ...}`; short
  forms `status` / `stop` carry no extra fields. Metadata must be one of
  `{"roles":[]}`, `{"roles":["DONOR"]}`, `{"roles":["TARGET"]}`,
  `{"roles":["DONOR","TARGET"]}`.
- Limits: nonce exactly 16 B; challenge exactly 32 B; profile <= 1 MiB;
  metadata <= 256 UTF-8 B; profileId `[A-Za-z0-9._-]{1,64}`; extra field
  names are forbidden.
- Parser rejection order: `UNAUTHORIZED_CALLER` -> `UNSUPPORTED_VERSION` ->
  `FORBIDDEN_FIELD` -> nonce `INVALID_FIELD`/`OVERSIZED_FIELD` ->
  `INVALID_METADATA` -> role errors (`MISSING_ROLE`, `ROLE_CONFLICT`,
  `UNKNOWN_ROLE`) -> per-command required/forbidden fields ->
  `UNKNOWN_COMMAND` -> `REPLAYED_NONCE` (checked last).
- Responses: success `{"version":1,"status":"ok","command":"<provision|start|
  status|attest-sign|stop>"}`; `attest-sign` adds `"chain"`, `"payload"`,
  `"signature"`. Failure `{"version":1,"status":"error","code":"..."}` with
  mapping: command/provider/role enum names verbatim;
  `InvalidChallenge -> INVALID_CHALLENGE`; `KeyStoreOperation ->
  KEYSTORE_<CATEGORY>_<numericCode>`; `AliasCleanup -> ALIAS_CLEANUP`;
  `WrongRole -> WRONG_ROLE`; `InvalidSigningIdentity ->
  INVALID_SIGNING_IDENTITY`; response > 1 MiB -> `OVERSIZED_RESPONSE`;
  anything else -> `INTERNAL_FAILURE`.

Staging and replay (`FixtureRequestStaging.kt`, `FixtureReplayTombstones.kt`,
`FixtureStagedRequestRecovery.kt`, `FixtureRequestFiles.kt`,
`FixtureApplication.kt`):

- Staging directory: `File(noBackupFilesDir, "fixture-command-v1")`.
- Upload `<nonce>.upload` -> bounded write + fsync -> atomic rename to
  `<nonce>.ready` on commit; abort deletes the temp file.
- `consume(nonce)` waits for ready, executes once, appends a tombstone,
  deletes the ready file; a second consume -> `DUPLICATE_EXECUTE`.
- Upload TTL 30 000 ms; execute wait default 5 000 ms; expired uploads are
  cleaned up.
- Tombstones: `fixture-command-v1.replayed` (temp sibling `.tmp`),
  newline-separated 22-char base64url nonces, bounded to 128 tokens with
  oldest evicted; in-memory replay/expiry rings are also 128.
- Crash recovery: `.upload` files are discarded; `.ready` files survive only
  if the nonce is canonical, unexpired, the payload nonce matches the
  filename, and the nonce is not already tombstoned.

Attestation core (`FixtureAttestationCore.kt`,
`AndroidFixtureAttestationKeyStore.kt`, `FixtureKeyStoreDiagnostic.kt`):

- Key alias `rka_fixture_v1_` + base64url(16 random bytes);
  `KeyGenParameterSpec(alias, PURPOSE_SIGN)`,
  `ECGenParameterSpec("secp256r1")`, `DIGEST_SHA256`,
  `setUserAuthenticationRequired(false)`,
  `setAttestationChallenge(<32 B>)`.
- Sign: `SHA256withECDSA` over a random 32 B payload; result = certificate
  chain DER list + payload + signature; the alias is deleted in `finally`
  (cleanup failure -> `ALIAS_CLEANUP`).
- Keystore error mapping: `KeyStoreException` in the cause chain ->
  `PROVIDER_FAILURE` with its numeric code; `KeyPermanentlyInvalidatedException`
  -> `KEY_INVALIDATED`, code `0`; `InvalidAlgorithmParameterException` ->
  `UNSUPPORTED_PARAMETERS`, code `0`; `SecurityException` -> `PERMISSION`,
  code `0`; `ProviderException` -> `PROVIDER_FAILURE`, code `0`; otherwise
  `UNKNOWN`, code `0`. Rendered on the wire as
  `KEYSTORE_<CATEGORY>_<code>`; this is the exact producer of
  `KEYSTORE_KEY_INVALIDATED_0`. Categories `ATTESTATION_UNAVAILABLE` and
  `ALIAS_COLLISION` are declared but never produced.

Roles (`FixtureRoleGate.kt`, `FixtureRoleProfile.kt`,
`FixtureProfileInstaller.kt`):

- Roles are exactly `DONOR` and `TARGET`; the donor startup gate (installed
  globally by `FixtureApplication.onCreate`) permits only `DONOR`.
- Profile install: `DONOR` -> donor public-profile store
  (`noBackupFilesDir/two-phone-donor-v1.bin`); `TARGET` -> the root-owned
  target store. Target identity = package name + longVersionCode + SHA-256 of
  the sole signing certificate.

### Donor service (`physical-harness/src/main/kotlin/org/matrix/teesimulator/physicalharness/`)

Lifecycle (`DonorService.kt`, `DonorServiceController.kt`,
`DonorServiceCommand.kt`, `DonorServiceStartDispatcher.kt`,
`DonorStartupGate.kt`, `DonorForegroundTransition.kt`, `DonorServiceClose.kt`,
`AndroidManifest.xml`):

- Manifest: `.DonorService`, `exported=false`,
  `foregroundServiceType="specialUse"` with
  `android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE`, `process=":donor"`.
- Actions `org.matrix.teesimulator.physicalharness.action.START` / `.STOP`;
  extras `EXTRA_PROFILE_ID`, `EXTRA_ACTIVE_ROLES`. `onStartCommand` gates
  START through `DonorStartupGates.runWhenAuthorized` (default gate refuses
  with `MissingActivation`), dispatches, and always returns
  `START_NOT_STICKY`; any runtime exception triggers
  `stopSelfResult(startId)`.
- Foreground: channel `donor_service` (`IMPORTANCE_LOW`), specialUse
  foreground type. `onDestroy` -> `controller.closeOrTerminate()` +
  `stopForeground(STOP_FOREGROUND_REMOVE)`.
- Foreground machine: `Inactive | Starting(attempt) | Active |
  Stopping(attempt, hadForeground)`; start decisions `Rejected | Ready |
  Start | Wait`; removal decisions `Cancelled | Wait | Stop`.
- Close path: stop accepting commands, bump command version, close attempt
  with 5 000 ms deadline, wait for `CLOSED | INCOMPLETE`; `closeOrTerminate`
  escalates exactly once to process termination.

Runtime ownership (`DonorRuntimeOwner.kt`, `DonorRuntimeHolder.kt`,
`DonorRuntimeCallCoordinator.kt`, `DonorRuntimeDependencies.kt`,
`DonorProcessHolder.kt`, `PhysicalDonorProcess.kt`,
`PhysicalDonorDispatcherFactory.kt`):

- Owner states `STOPPED | STARTING | RUNNING | STOPPING | STOP_FAILED`.
- Start validates the profile id, loads `DonorProfile`, and compares the
  active fingerprint with `MessageDigest.isEqual`: identical -> already
  running; different -> `ConflictingProfile`; any transitional state ->
  `Unavailable`. Startup order: open donor TLS identity -> get/create the
  process-wide `PhysicalDonorProcess` -> resolve caller -> create and start
  the pinned TLS server -> `RUNNING`. Failures route through
  `closeFailedCandidate` (back to `STOPPED`, or `STOP_FAILED` with the close
  failure suppressed onto the original).
- Stop uses a 5 s deadline; incomplete close -> `STOP_FAILED` +
  `Unavailable`; stop may be retried from `STOP_FAILED`.
- `DonorRuntimeCallCoordinator` serializes start/stop under a
  `ReentrantLock` and reports truthful dispositions (`CONFIRMED_STOPPED` /
  `MAY_BE_ACTIVE` / `Incomplete`).
- `DonorProcessHolder` and `DonorRuntimeHolder` are process-wide singletons;
  failed creations are not cached. `PhysicalDonorProcess.init` runs
  `repository.recover()`. `PhysicalDonorDispatcherFactory.create(pair,
  clientNonce, serverNonce, expectedCaller)` bridges to
  `WireDonorDispatcher.create`.

Durable state (`DonorStateModels.kt`, `DonorStateCodec.kt`,
`DonorStateBlobStore.kt`, `DonorStateSecurityBootstrap.kt`,
`AuthenticatedDonorStateStore.kt`, `AndroidKeyStoreHandleMac.kt`,
`HandleAuthenticator.kt`):

- `DonorStateSnapshot(revision, keys, mutations)` with `DurableKeyRecord` and
  `DurableMutationRecord`; limits: 65 535 records, alias <= 255 B, challenge
  <= 128 B, public key <= 64 KiB, certificate <= 256 KiB, <= 16 certs, scope
  <= 1024 B; key spec fixed to EC/P256/SHA256/SIGN; at most one PREPARED
  mutation; alias must equal `DonorKeyAliasPolicy.aliasFor(keyId)`.
- Codec envelope: `MAGIC=0x54445331`, VERSION 1, FLAGS 0, `revision(i64)`,
  `bodyLength(i32)`, body, 32 B MAC; MAC domain `"teesim-state-file-v1"`;
  body canonical-sorted; `MAX_FILE_BYTES = 32 MiB`.
- Blob `donor-state-v1.bin` in `noBackupFilesDir` via an atomic-file facade
  (`.bak` / `.new`).
- HMAC key alias `teesim_state_mac_v1` (HmacSHA256, 256-bit, SIGN|VERIFY,
  trusted environment required, no user auth, not StrongBox).
- Bootstrap: state without MAC -> `UnverifiableState`; MAC/aliases without
  state -> `InconsistentArtifacts`; first boot writes an authenticated empty
  revision-0 snapshot; rollback deletes only the newly created MAC key. Any
  integrity failure quarantines the repository globally.
- Handle authenticator domains `"teesim-key-handle-v1"` /
  `"teesim-operation-handle-v1"`; session ids exactly 32 B.

Key lifecycle (`DonorLifecycleRepository*.kt`, `DonorLifecycleGeneration.kt`,
`DonorLifecycleDeletion.kt`, `DonorLifecycleRecovery.kt`,
`DonorKeyAliasPolicy.kt`, `DonorProfile.kt`, `DonorConfigSource.kt`):

- Alias `teesim_donor_key_v1_<uuid-without-dashes>`; ownership by prefix.
- Key states `CREATING | ACTIVE | SUPERSEDED | DELETE_PENDING | DELETED |
  QUARANTINED` (ABSENT is never persisted).
- Generation: replay by `(mutation id, payload hash)`; prepare `CREATING`,
  supersede a same-logical ACTIVE key, persist PREPARED, then reconcile
  against the keystore (Absent -> generate; Verified -> adopt existing;
  Rejected or exact-metadata mismatch -> quarantine); key-id allocation
  retries <= 16.
- Deletion: ACTIVE/SUPERSEDED -> `DELETE_PENDING` + prepared mutation;
  reconcile (absent -> commit; rejected -> quarantine; verified exact ->
  `deleteIfExact`); replayed deletes append a committed mutation only.
- Recovery pass order: verify all ACTIVE/SUPERSEDED keys exactly ->
  reconcile the single CREATING key -> the single DELETE_PENDING key ->
  `recoverDeleted` for DELETED keys.
- `DonorProfile`: profileId `[A-Za-z0-9._-]{1,64}`; bind address IPv4/IPv6
  non-multicast, port 1..65535; fingerprint domain
  `"TEESimulator\0donor-profile\0v1"` over profile id, bind address/scope,
  port, both pins, identity cert, and anchors. `DonorConfigSource` requires
  the stored donor alias to equal the TLS identity alias and drops the leaf
  from the stored trust chain.

Keystore backend (`AndroidKeyStoreBackend.kt`,
`PlatformAndroidKeyStoreBackend.kt`, `DurableAndroidKeyStore.kt`,
`AndroidKeystoreDonor.kt`, `AndroidKeystoreDonorCoordinator.kt`,
`AndroidKeyAttestationVerifier.kt`, `CallerIdentityCanonicalizer.kt`,
`AndroidOwnCallerIdentityResolver.kt`):

- Interface: `aliases()`, `containsAlias(alias)`, `generate(alias,
  challenge)`, `metadata(alias)`, `delete(alias)`, `begin(alias)`.
- Platform generation: EC P-256, PURPOSE_SIGN, SHA-256,
  `setAttestationChallenge(copy)`, `setUserAuthenticationRequired(false)`,
  `setIsStrongBoxBacked(false)`, under a mutation lock; `begin` initializes
  `SHA256withECDSA`; `GeneralSecurityException | IOException |
  ProviderException` -> `AndroidKeystoreDonorException.BackendFailure`.
  There is no special case for invalidated keys: they surface as generic
  `BackendFailure` (wire `DONOR_UNAVAILABLE`).
- Attestation verifier: trusted-environment level for both attestation and
  keymaster fields; extension OID `1.3.6.1.4.1.11129.2.1.17` present exactly
  once; EC P-256; challenge 1..128 B and request-matching; tag 709
  (ATTESTATION_APPLICATION_ID) explicit and equal to the caller's DER;
  attested public key equals the generated public key.
- Caller identity: packages under the own UID plus signer sets canonicalized
  to DER; wire digests are lowercase-hex SHA-256 of the signer set and of the
  attestation-application-id DER.
- Donor API errors: `WrongCaller`, `InvalidAlias`, `InvalidChallenge`,
  `AliasAlreadyExists`, `KeyNotFound`, `OperationNotFound`,
  `AttestationRejected`, `BackendFailure`.

Wire backend and TLS server (`AndroidWireDonorBackend.kt`,
`WireBackendFailureMapping.kt`, `PinnedMutualTlsDonorServer.kt`,
`PinnedJsseServerContext.kt`, `AndroidKeyStoreDonorTlsServerIdentity.kt`,
`PlatformDonorTlsServerIdentityBackend.kt`, `DonorTargetTrustStore.kt`,
`SocketDeadlineScheduler.kt`):

- `AndroidWireDonorBackend`: session id must be 32 B (else
  `DONOR_UNAVAILABLE`); closed backend -> `DONOR_UNAVAILABLE`; caller
  mismatch -> `WRONG_CALLER`; operation spec must be SIGN/SHA256 (else
  `INVALID_ARGUMENT`); `close()` aborts all live operations.
- Failure mapping (exact): `ReplayConflict -> REPLAY_CONFLICT`;
  `InvalidHandle -> INVALID_HANDLE`; `InvalidState -> INVALID_STATE`;
  `GlobalQuarantine | Unavailable | RevisionExhausted -> DONOR_UNAVAILABLE`;
  `WrongCaller -> WRONG_CALLER`; `InvalidAlias | InvalidChallenge ->
  INVALID_ARGUMENT`; `OperationNotFound -> INVALID_OPERATION_HANDLE`;
  `KeyNotFound | AliasAlreadyExists | AttestationRejected | BackendFailure ->
  DONOR_UNAVAILABLE`; `HandleAuthenticatorException -> caller-supplied code`;
  `IllegalArgumentException -> INVALID_ARGUMENT`; else `INTERNAL_ERROR`.
- TLS server: TLSv1.3 only, `needClientAuth=true`, accept `soTimeout=1000`
  ms; each session re-checks the negotiated protocol, client certificate
  validity, and `expectedTargetPin` against the peer leaf SPKI; hello exchange
  issues a fresh 32 B server nonce; frame loop deadlines read 5 s / write
  10 s / frame 30 s; caps 64 requests and 8 MiB response bytes per session;
  close uses `tryLockUntil(deadline)` and reports closed only when acceptor,
  workers, and the deadline scheduler have all terminated.
- Donor TLS identity: fixed alias `teesim_donor_tls_server_v1`; EC P-256,
  SHA-256, SIGN-only, no user auth, not StrongBox, null attestation
  challenge; subject `CN=TEESimulator Donor TLS v1`; validity `now-1d ..
  now+20y`; random nonzero 16 B serial; validation requires trusted
  environment, non-exportable EC key, valid chain and leaf, P-256 parameters,
  and a sign/verify probe; optional pin match on open.
- Target trust store: PKCS12 containing the profile anchors under stable
  names `target-anchor-%04d`; the JSSE context pins the donor leaf to
  `expectedDonorPin` and builds PKIX trust from those anchors.

### Target interception (`app/src/main/java/org/matrix/TEESimulator/`)

Entry (`App.kt`): SDK Q..R -> legacy `KeystoreInterceptor`; SDK S+ ->
`Keystore2Interceptor`; providers installed, configuration loaded, Bouncy
Castle swapped in, then `Looper.loop()`. Interception is inert until
`tryRunKeystoreInterceptor()` succeeds; without an approved profile the
policy stays platform-only.

Binder hook (`interception/core/BinderInterceptor.kt`,
`interception/keystore/AbstractKeystoreInterceptor.kt`): hook parcels are
`[txId][target][code][flags][uids/pids][optional pidfd][payload]`; pre/post
codes 1/2; result codes `1=Skip`, `2=Continue`, `3=OverrideReply`,
`4=OverrideData`, `5=ContinueAndSkipPost`; backdoor transaction code
`0xdeadbeef` with register/unregister codes 1/2 and origin-death transaction
sentinel `-1`. Injection probes the backdoor, injects the native library if
absent, retries up to 5 times, exits 1 on repeated failure, exits 0 on
service death.

Policy (`interception/policy/FixtureInterceptionPolicy.kt`,
`AndroidFixturePackageResolver.kt`,
`InstalledTargetProfileApprovedFixtureSource.kt`): root UID 0 and the daemon
PID are hard-bypassed. A request is evaluated only when the security level is
exactly `TRUSTED_ENVIRONMENT`, the method is `GENERATE_KEY` or
`CREATE_OPERATION`, and an approved stored target profile resolves to an
installed package whose uid, packageName, versionCode, and signer set match
exactly (the signer set must be exactly one SHA-256 digest taken from
`signingInfo.signingCertificateHistory`, not mere chain compatibility).
`decide` returns `REMOTE` only for EC + P256 + SHA256 + SIGN; everything else
is `PLATFORM`. There is no fallback: remote failure propagates and never
routes to platform.

KeyMint shim (`interception/keystore/shim/KeyMintSecurityLevelInterceptor.kt`,
`OperationInterceptor.kt`, `RemoteSigningOperationBinder.kt`,
`SoftwareOperation.kt`, `interception/keystore/Keystore2Interceptor.kt`,
`ListEntriesHandler.kt`):

- Recognized method families: `generateKey`, `createOperation`, `importKey`.
- Remote generate fabricates a `KeyEntryResponse`, caches it in
  `generatedKeys`, and returns metadata only.
- Remote `createOperation` is used only for `Domain.KEY_ID` aliases that were
  previously generated remotely and whose full request shape still satisfies
  policy; otherwise control continues to the platform.
- `RemoteSigningOperationBinder` (remote `IKeystoreOperation.Stub`):
  `update` forwards; `updateAad` aborts then throws `RemoteException`;
  `finish` aborts when the caller supplies a signature and otherwise
  forwards; `abort` forwards; origin death calls `abortFromOwnerDeath()`
  exactly once.
- `OriginProcessDeathLease` is pidfd-backed and one-shot: a main-looper FD
  watcher spawns a daemon thread for the death callback.
  `ActiveOperationCall` applies sticky owner-death cancellation across
  operations.
- Only the TEE security level is registered; StrongBox is never queried.
  `listEntries(Batched)` merges generated descriptors, sorts by alias, and
  truncates at `RESPONSE_SIZE_LIMIT = 358 400`.
- `OperationInterceptor` only logs and removes itself on finish/abort; its
  `UPDATE_AAD_TRANSACTION` / `UPDATE_TRANSACTION` constants are unused.

Two-phone client (`twophone/TargetSessionManager.kt`,
`TargetSessionManagerHolder.kt`, `TargetSessionTypes.kt`,
`TargetTlsConnection.kt`, `PinnedJsseTargetClientContext.kt`,
`TargetTlsClientIdentityModels.kt`,
`AndroidKeyStoreTargetTlsClientIdentity.kt`,
`PlatformTargetTlsClientIdentityBackend.kt`,
`AndroidTargetPublicProfileAtomicFileFacade.kt`,
`RemoteNormalizedKeyLifecycle.kt`, `RemoteOperationLeaseLedger.kt`,
`ActiveOperationCall.kt`):

- Session states `DISCONNECTED -> CONNECTING -> CONNECTED -> CLOSING ->
  CLOSED`; close is idempotent; one in-flight exchange; profile bounds
  `maxOperations == 1` and `deadlineSeconds == 120` are enforced in the
  constructor; there is no reconnect backoff (the next call reconnects);
  cancellation polls at <= 50 ms granularity.
- TLS: TLS 1.3 with HTTPS endpoint identification; the donor leaf SPKI is
  pinned against `profile.donorPin`; the client hello nonce must be echoed in
  the server hello; responses correlate through `TargetResponseCorrelator`.
- Client identity: fixed alias `teesim_target_tls_client_v1` (subject
  `CN=TEESimulator Target TLS v1`), owner UID 0, trusted environment,
  non-exportable EC P-256 key, sign/verify probe; the opened pin must match
  `profile.targetIdentity`.
- `TargetSessionManagerHolder` is a singleton keyed by
  `(FixturePackageIdentity, WireCallerIdentity)`; mismatches raise
  `IdentityMismatch`, a missing profile raises `MissingProfile`.
- `RemoteNormalizedKeyLifecycle`: `KEY_SPEC = EC/P256/SHA256/SIGN`,
  `OPERATION_SPEC = SIGN/SHA256`; generate uses
  `SHA-256(logicalName)` as `logicalNameHash`; begin sends step 0;
  update/finish/abort send `step + 1` relative to the previous step and
  require the response step to match; finish
  requires a non-empty signature; owner death first tries
  `session.cancelActiveOperation`, then falls back to a typed owner-death
  abort request.
- `RemoteOperationLeaseLedger` is a placeholder allocator only (no expiry,
  release, or death integration); it ships in the main source set but has no
  production caller and is retained for tests.

Legacy upstream surfaces (present, not part of the two-phone path):
`interception/keystore/KeystoreInterceptor.kt` (SDK Q/R software
attestation), `pki/KeyBoxManager.kt` + `KeyBox.kt` (XML keybox loading from
`/data/adb/tricky_store`), `attestation/AttestationBuilder.kt`,
`AttestationPatcher.kt`, `DeviceAttestationService.kt`,
`pki/CertificateGenerator.kt`, `CertificateHelper.kt`.
`config/ConfigurationManager.kt`: root `/data/adb/tricky_store`; `target.txt`
package modes (`!` = GENERATE, `?` = PATCH, bare = AUTO, `[file.xml]` keybox
scopes); `security_patch.txt`; `tee_status.txt`. `pki/XmlParser.kt` is
unreferenced. Native-bridge AIDL under `app/src/main/cpp/aidl/`
(`IRemoteOperationControl`, `RemoteOperationDisposition`,
`RemoteOperationError`, `RemoteOperationReply`) is definition-only with no
Kotlin implementation.

### Host orchestration (`scripts/two_phone_*.py`)

Types and state (`two_phone_types.py`, `two_phone_state.py`):

- `Command`: `preflight | provision | start | attest-sign | status | stop |
  recover`. `RunConfig(adb, serial_a, serial_b, model_a, model_b, endpoint,
  state_file, deadline_seconds, module_dir, profiles)`; all device values are
  CLI-supplied; `parse_endpoint` rejects shell-unsafe input as
  `INVALID_ARGUMENT` before any adb invocation.
- State file (default path `$XDG_STATE_HOME/teesimulator/two-phone-run-v1.json`,
  fallback `~/.local/state/teesimulator/two-phone-run-v1.json`; the default is
  defined in `scripts/two_phone_run.py` and passed into
  `scripts/two_phone_state.py`, which implements the mechanics): JSON
  `{"version":1,"state","fingerprint","profileFingerprint",
  "activeOperation"}`; sibling lock `<state>.lock`; absent -> `CLEAN`;
  invalid/oversized -> `STALE_STATE`; atomic temp-file + `os.replace` writes.

adb wrapper (`two_phone_adb.py`): every device call is
`adb -s <serial> shell ...`. Verbs used: `getprop ro.product.model`;
`/system/bin/toybox nc -z -w 5 <host> <port>`; the fixture command (see
mismatch below); controller start
`su 0 sh -c 'exec "$1/daemon" "$1" >/dev/null 2>&1 &' sh <module_dir>`;
`pidof TEESimulator`; `su 0 kill -TERM <pid>`; `su 0 stop keystore2` /
`su 0 start keystore2`; `pidof keystore2`; `service list`;
`su 0 cat /proc/<pid>/maps`.

Run ordering (`two_phone_lifecycle.py`, locked by
`tests/test_two_phone_run.py`):

1. `preflight`: read both models, compare to expectations; no injection;
   state `CLEAN`.
2. `provision`: model check -> `PROVISION` to phone A (role DONOR, profile
   bytes) -> write `PROVISIONED` with config and profile fingerprints and
   `activeOperation=false`. No `nc`/`su` in this phase.
3. `start`: load compatible state -> `ATTEST_SIGN` to phone B (TARGET,
   random 32 B challenge) first -> `START` to phone A (DONOR, profileId) ->
   reachability check from B to the donor endpoint (`nc`) -> `PROVISION` to
   phone B (target profile) -> `START` to phone B (TARGET, donor profileId)
   -> start the controller daemon on B -> state `RUNNING`.
4. `attest-sign`: only from `RUNNING`; sets then resets `activeOperation`; a
   concurrent operation is rejected with `OPERATION_LIMIT`.
5. `status`: fixture `STATUS` to B; reports the current state.
6. `stop` / `recover`: run cleanup; both idempotent; `recover` rewrites the
   state file from the cleanup receipt.

Rollback: any `RunError` or `KeyboardInterrupt` during a transition runs
exactly one cleanup pass (`two_phone_cleanup.py`) in this order: `STOP`
target on B -> close controller on B -> `STOP` donor on A (if provisioned) ->
restart keystore2 on B -> native proof probe. The first error is recorded;
later errors are ignored; the run is clean iff there were no errors. Exit
codes: 0 success; 130 on `CANCELLED`; 1 on all typed failures.

Attestation verification (`two_phone_attestation.py`): trust anchors PEM or
DER, 1..8 unique, each <= 87 384 B; `verify_native_proof` requires a 32 B
challenge, chain signature verification, self-signed root, leaf EC P-256 with
ECDSA/SHA-256, attestation extension OID `1.3.6.1.4.1.11129.2.1.17`,
tee-environment fields equal to 1, origin tag 702 == generated, and strict
DER (noncanonical, oversized, and trailing-data forms rejected).

G2 rehearsal (`two_phone_g2.py`, CLI `gate-g2.py`): requires a clean or
fingerprint-compatible state; verify model B; baseline (`STOP` target + close
controller + stable keystore snapshot); native proof #1; snapshot; restart
keystore2 (<= 2 attempts); wait for a new stable snapshot (pid changed,
services ready, hook absent); native proof #2; the two challenges must
differ; cleanup always runs; final state written with profile fingerprint
`"g2"`. Verdict JSON fields: `version`, `gate:"G2"`,
`verdict:"PASS"|"STOP"`, `attempts`, `proofs`, `pidChanged`,
`servicesReady`, `hookAbsent`, `cleanup`, optional `code`. Exit 130 only for
`CANCELLED`; `PASS` only when no typed failure occurred.

### Gates

- G0 `scripts/verify.sh` (IMPLEMENTED+GREEN), in order: (1) pytest/unittest
  suite; (2) `:app:testDebugUnitTest :two-phone:test :two-phone:ktfmtCheck
  :physical-harness:test :physical-harness:ktfmtCheck
  :physical-harness:lintDebug :physical-harness:assembleRelease`; (3) the
  `:rka-fixture` test/ktfmt/lint/assembleRelease set; (4) shell parse check;
  (5) license/provenance presence + ancestry check; (6) `g0-guards.sh
  source` scan; (7) `clean :two-phone:build :app:zipRelease` with package
  scan and `action.sh` member check; (8) reproducibility re-zip comparison;
  (9) dirty-worktree check. Source guards reject: bundled `keybox.xml`,
  secret/RKP material, device identifiers, raw Binder references in
  `two-phone` and `physical-harness/src`, target-custody tokens (a lone
  `SpkiPin` reference is the allowed exception). Package guards reject zip
  members named `keybox.xml`, `target.txt`, `sepolicy.rule`, or containing
  NUL/newline (`invalid-package-input` / `unsafe-package-content`).
- G1 `scripts/probe-api36.sh` + `probe-api36-lib.sh` (IMPLEMENTED+GREEN):
  usage exactly `<serial> <profile>`; read-only (no transfer, tracing,
  injection, key creation, property change, or service restart); prints
  identifier-free `PASS`/`STOP` lines plus JSON. Checks: SDK 36, ABI
  arm64-v8a, SELinux enforcing, AVB green, KeyMint default instance present,
  keystore2 pid/start/maps stability, keystore SELinux context, binder route,
  no competing hook strings in maps, controlled-restart tools, KeyMint AIDL
  version/hash allowlist (`n:40hex(,n:40hex)*`), ELF build-id/dependency
  chain, KernelSU domain, module directory context/permissions-or-absent, no
  matching AVC denials. The expected profile lives at
  `profiles/api36-arm64-qcom-default-v1.conf` (includes `MAX_OPERATIONS=1`,
  `DEADLINE_SECONDS=120`).
- G2 `scripts/gate-g2.py` (SCAFFOLDED, BLOCKED): the tooling exists and is
  contract-tested against fakes; it is not green because of the physical
  boundary below. The README sentence "G2 tooling is not implemented" is
  stale: tooling is implemented; physical acceptance is blocked.
- Snapshot gate `scripts/verify-snapshot.sh`: clones to a temp directory,
  forbids `.git` and internal evidence directories in the manifest, runs G0
  inside the clone, and rejects source drift (`snapshot-drift`) and clone
  manifest mismatch (`snapshot-mismatch`).

### Build, sign, provenance

- `scripts/bootstrap-fixture-signer.sh <state-dir>`: creates a 0700 state
  directory outside the repo containing `fixture-signer.p12` (PKCS12,
  RSA-3072, `CN=TEESimulator Fixture Signing`) and 0600 password files;
  refuses prompt-capable keytool invocations (`INTERACTION_REQUIRED`).
- Environment contract (`scripts/fixture-signing-lib.sh`):
  `TEESIM_FIXTURE_KEYSTORE`, `TEESIM_FIXTURE_STORE_PASSWORD_FILE`,
  `TEESIM_FIXTURE_KEY_ALIAS`, `TEESIM_FIXTURE_KEY_PASSWORD_FILE`; build tools
  resolve from the repo SDK `build-tools/36.0.0`, then `$ANDROID_HOME`, then
  PATH; the APK signer digest is read via `apksigner verify --verbose
  --print-certs`; the GPG signer may be pinned by `TEESIM_AGENT_GPG_KEY`.
- `scripts/sign-fixture-release-apk.sh`: normalizes zip ordering/timestamps,
  `zipalign -f 4`, `apksigner sign --min-sdk-version 36
  --v1-signing-enabled false --v2-signing-enabled true
  --v3-signing-enabled true --v4-signing-enabled false`, then verifies.
- `scripts/create-fixture-provenance.sh <apk> <out>`: writes
  `artifact_sha256`, `schema_version`, `signer_certificate_sha256`,
  `source_sha256` (hash over tracked + untracked sources, excluding internal
  evidence directories).
- `scripts/sign-fixture-provenance.sh`: detached ASCII-armored signature via
  `gpg --detach-sign --armor --pinentry-mode loopback`;
  `scripts/verify-fixture-provenance.sh`: `gpg --verify` plus signer
  fingerprint equality (`PROVENANCE_SIGNER_MISMATCH`).
- `scripts/verify-fixture-apk.sh`: expected artifact SHA-256 and signer
  certificate SHA-256 must match (`ARTIFACT_MISMATCH` / `SIGNER_MISMATCH`).
- `module/action.sh` and `module/service.sh` are inert by design: they write
  a status file under `$MODDIR/state/` and exit (1 and 0 respectively);
  neither invokes the injector or bootstrap. `module/customize.sh` enforces
  install-time shape only (boot-mode install, KernelSU version gate, exact
  arm64, exact SDK 36; extracts `daemon`, `service.apk` or `classes.dex`,
  `libTEESimulator.so`, and renames `libinject.so` to `inject`) and never
  starts injection.

## What was tried (technical failed mechanisms)

These mechanisms were evaluated and rejected; do not re-attempt them as
fixes:

- Broadcast-based fixture commands on the device side: the receiver-based
  transport was removed; the ContentProvider stream replaced it.
- `setUserAuthenticationRequired(false)` as a remedy for signing
  invalidation: not a fix; the keys already carry no user-auth requirement.
- Dropping the attestation challenge from the challenged-sign flow: invalid;
  it breaks the proof contract that G2 and the host verifier depend on.
- Keybox/hook targeting to work around donor-side signing: out of scope and
  forbidden by the routing boundary.
- Treating the signing failure as a transport problem (broadcast vs provider,
  host staleness): disproved; the provider stream, cleanup, and host
  orchestration all function; the failure is below them.

## Decisions

- Wire protocol is a fixed-schema, numeric-tagged, big-endian binary format
  with a 2 MiB frame cap; it is not Binder parcels, and raw Binder references
  are gate-rejected in protocol sources.
- Donor is the sole cryptographic custodian; the target stores only opaque
  pair-bound handles, public metadata, certificates, and reconciliation
  state; IMPORT stays rejected.
- `UPDATE_AAD` is deliberately unsupported in V1 (SIGN-only): it aborts the
  operation and returns a cached `UNSUPPORTED_METHOD`.
- Exactly one profile shape exists: `MAX_OPERATIONS=1`,
  `DEADLINE_SECONDS=120`, enforced on both encode/decode and session
  construction.
- ATTEST_KEY-style operations must execute in the donor app process so
  keystore2 derives the correct ATTESTATION_APPLICATION_ID for the caller.
- All durable state is authenticated (HMAC-SHA256, domain-separated) and any
  integrity failure quarantines globally rather than degrading.
- Host state is a single JSON document with fingerprint compatibility checks;
  every transition failure runs one bounded reverse cleanup.
- Release artifacts carry signed provenance (artifact hash + signer
  certificate hash + source hash) verified independently of the APK
  signature.

## Known seams and contradictions (source truth)

1. Fixture transport mismatch (first remaining implementation step). The
   device fixture exposes only the ContentProvider stream:
   `content://org.matrix.teesimulator.rkafixture.commands/v1/request/{nonce}`
   (write JSON), `.../v1/execute/{nonce}` (read JSON), `delete()` for
   cleanup; `call()` is unsupported and no broadcast receiver exists. The
   host still emits broadcasts: `scripts/two_phone_adb.py::fixture` builds
   `am broadcast --receiver-permission android.permission.DUMP -a
   org.matrix.teesimulator.rkafixture.v1.<ACTION> --ei version 1 --es nonce
   <b64url> --es metadata '{"roles":[...]}'` plus optional `--es profile` /
   `--es profileId` / `--es challenge`, and `scripts/two_phone_fixture.py::
   parse_fixture` expects a `Broadcast completed: result=..., data=...`
   line. The action strings match the device constants; the transport does
   not. Any internal note claiming the host migration is complete is stale;
   the source above is authoritative.
2. G2 wording: "G2 tooling not implemented" is stale; the gate is
   implemented and contract-tested but physically blocked (below).
3. Deleted broadcast-path sources (`FixtureCommandReceiver`, intent-adapter
   tests) no longer exist; do not reference them.
4. Unused/dead seams to leave alone unless deleting deliberately:
   `Routing.kt` route seam and `RemoteOperationLeaseLedger` (both ship in
   main source sets, are unused by production callers, and are exercised only
   from tests), `pki/XmlParser.kt`,
   `OperationInterceptor` update-transaction constants, provider
   `call/query/insert/update/getType`, native-bridge AIDL (definition-only),
   unreachable diagnostic categories `ATTESTATION_UNAVAILABLE` /
   `ALIAS_COLLISION`.

## Physical boundary: Phone B challenged signing (BLOCKED)

The donor-role challenged sign path on Phone B fails inside the Android
framework/keystore2 crypto operation, below every implemented layer:

- Call path: fixture `ATTEST_SIGN` -> `FixtureAttestationCore.attestAndSign`
  -> `AndroidFixtureAttestationKeyStore` sign -> `Signature.initSign` throws
  an invalid-key failure (`KeyPermanentlyInvalidatedException` / framework
  invalid-key conversion) -> diagnostic category `KEY_INVALIDATED` with
  numeric code `0` -> response
  `{"version":1,"status":"error","code":"KEYSTORE_KEY_INVALIDATED_0"}`.
- Boundary: the failure is not at key generation (challenged `generateKey`
  succeeds), not at `getKeyEntry`, not in the provider stream, not in host
  orchestration, and not in TLS. No usable challenged native proof can be
  produced on Phone B, so the G2 two-proof rehearsal cannot complete.
- Phone A completes the same challenged attest+sign flow successfully under
  the same host orchestration, isolating the boundary to the Phone B
  backend.
- Code-level consequence: `physical-harness` has no invalidated-key special
  case; such failures map to `BackendFailure -> DONOR_UNAVAILABLE` on the
  wire. No local software-signing fallback is permitted.
- This is a physical backend boundary, not a software completion claim: no
  amount of host-side or fixture-side code change within the current
  contracts removes it.

## Remaining implementation steps (exact order)

1. Migrate the host fixture transport to the provider stream protocol
   (NOT-YET-MIGRATED): rework `scripts/two_phone_adb.py::fixture`,
   `scripts/two_phone_fixture.py::parse_fixture` / `action`, and the fakes
   and assertions in `tests/test_two_phone_run.py` and
   `tests/test_gate_g2.py`. Target shape: write the request JSON to
   `content://org.matrix.teesimulator.rkafixture.commands/v1/request/<22-char
   nonce>` (mode `w`) via shell `content`/`exec-in`; read the response JSON
   from `.../v1/execute/<nonce>` (mode `r`); `content delete` the request
   URI for cleanup; parse the `{"version":1,"status":"ok|error",...}` body
   instead of a broadcast result line. The URI nonce and the body nonce must
   match (device recovery rule).
2. Resolve or reproduce the Phone B `KEYSTORE_KEY_INVALIDATED_0` boundary:
   device-side investigation of the `initSign` invalidation on the API-36
   donor backend (repro conditions, backend state, alternate-device
   confirmation). Contract-weakening workarounds are forbidden. This gates
   steps 3-6.
3. Complete G2 green: two consecutive `gate-g2.py` rehearsals `PASS` with
   fresh proofs, pid change, services ready, hook absent, and cleanup
   `CLEAN`.
4. Physical deployment/preflight: `:app` device install tasks,
   `module/customize.sh` shape gate, donor TLS identity provisioning
   (`AndroidKeyStoreDonorTlsServerIdentity`), `DonorProfile` /
   `DonorConfigSource` on device.
5. Transport QA: `PinnedMutualTlsDonorServer` against
   `TargetSessionManager` / `TargetTlsConnection` on real devices (hello
   codec, correlator, deadlines, orchestrator integration).
6. Final remote KeyMint/RKA proof and teardown: end-to-end remote
   generate/sign through `KeyMintSecurityLevelInterceptor` -> wire ->
   `AndroidWireDonorBackend` -> `AndroidKeyAttestationVerifier`, with caller
   identity from `CallerIdentityCanonicalizer` /
   `AndroidOwnCallerIdentityResolver`, followed by a teardown report.

## Acceptance criteria

- [ ] `python3 -m pytest tests/ -q` passes.
- [ ] `./scripts/verify.sh` (G0) passes, including the reproducibility
      re-zip and the dirty-worktree check.
- [ ] `./scripts/verify-snapshot.sh` passes against the committed tree.
- [ ] `./scripts/probe-api36.sh <serial> profiles/api36-arm64-qcom-default-v1.conf`
      prints `PASS` for both phones (read-only).
- [ ] Host fixture commands execute on device through the provider stream:
      `provision`, `start`, `status`, `attest-sign`, `stop` round-trip via
      the `content://` URIs with typed JSON responses.
- [ ] `python3 scripts/two_phone_run.py --help` and
      `python3 scripts/gate-g2.py --help` succeed; lifecycle ordering tests
      keep passing with the migrated transport.
- [ ] G2: two consecutive rehearsals `PASS` with distinct challenges and
      `CLEAN` cleanup receipts (blocked until the Phone B boundary is
      resolved).
- [ ] No committed file contains serials, IPs, signer hashes, nonce or
      challenge bytes, certificates, session ids, or local absolute paths.

## Constraints

- StrongBox and AVF are pass-through-only and must never be targeted.
  Android remote-provisioning CSR/certification APIs are out of scope. No
  software RKP. The external `google-rkp-sw` repository is documentation
  context only: never included, invoked, or a build dependency.
- No keybox, private key, target list, or SELinux policy is bundled;
  `module/keybox.xml` is gate-rejected, as are zip members named
  `keybox.xml`, `target.txt`, or `sepolicy.rule`.
- Boot and module entry points stay inert (`service.sh`, `action.sh` write
  status files only); `customize.sh` never starts injection; no live
  insertion is authorized until G2 is green.
- Interception exclusions: UID 0, the target daemon, non-fixture UIDs,
  non-TEE security levels, and any non-EC/P-256/SHA-256/SIGN request. No
  all-app proxy, no RSA/AES/HMAC routing, no import or wrapped import, no
  user-auth or device-local semantics.
- Wire/TLS: no raw Binder parcels; no private-key export; no permissive
  trust manager; TLS 1.3 only; no pin bypass; no caller fallback; no replay
  fallback; no local software-signing fallback; `UPDATE_AAD` unsupported in
  V1.
- Host: no hardcoded device identifiers; no `shell=True` or `eval`; the G1
  probe uses no mutating adb verbs; no replacement, resigning, uninstall, or
  data-clearing of the third-party attestation app; no persistent listeners
  after a run; no manual taps during acceptance.
- Keep the repository free of serials, IPs, signer hashes, nonce/challenge
  bytes, certificates, session ids, and local absolute paths; evidence of
  sensitive request data is retained as hashes only.
