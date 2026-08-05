# Normalized RKA protocol v1

Status: fixed implementation contract for the fixture-only donor-to-candidate
RKA route.

> [!IMPORTANT]
> **v1 is TEST-REFERENCE-ONLY.** Production speaks v2. This document is kept as
> a frozen reference for the v1 hash pins and golden vectors; it is not the
> protocol a shipped donor and candidate negotiate.

> [!NOTE]
> A donor may serve several candidates concurrently, but **candidate routing is
> never a wire field**. Neither v1 nor v2 carries a candidate identifier. The
> donor resolves the candidate by an internal lookup: it maps the verified TLS
> peer SPKI plus the selected profile through a pairing catalog to exactly one
> candidate identity. Because routing lives entirely off the wire, the frame
> layout, the 21 canonical v2 golden vectors, and the 6 v1 hash pins are
> byte-identical to before multi-candidate support.

RKA v1 is a normalized, big-endian, bounded request/response protocol. It is
independent of Binder and Android parcel layouts. The donor retains the Android
KeyStore alias, KeyMint key blob, private key, live operation, and every private
operation. The candidate receives only authenticated opaque handles, public
metadata, certificate chains, and operation results.

The protocol has exactly two transport kinds:

| Tag | Name | Meaning |
| ---: | --- | --- |
| `0x01` | `DIRECT_PINNED_TLS` | Production, direct candidate-to-donor TLS 1.3 with mutual authentication and exact SPKI pins. |
| `0x02` | `DIAGNOSTIC_USB_RELAY` | Diagnostic only, candidate-to-host pinned TLS followed by the typed USB provider adapter. |

Both implement one `RkaTransport` contract:

```text
open(activeProfile, sessionBinding) -> authenticated session
exchange(authenticated request frame) -> authenticated response frame
cancel(requestId) -> local cancellation signal
close() -> closed session
```

Routing, lifecycle, persistence, reconciliation, and error mapping consume only
this contract. Transport selection is part of the signed profile and session
binding. It cannot change during a session. The USB relay is never a production
fallback and never receives Binder parcels.

## Encoding rules

All integers are unsigned, network byte order (big-endian), and use their exact
declared width. Decoders must not narrow an integer before applying its bound.
`u8`, `u16`, `u32`, and `u64` occupy 1, 2, 4, and 8 bytes. `ULong.MAX_VALUE`
therefore encodes as eight `ff` bytes and must decode without sign extension.

`bytes8`, `bytes16`, and `bytes32` mean a `u8`, `u16`, or `u32` byte count
followed by exactly that many bytes. UTF-8 is strict: malformed sequences, NUL,
and non-shortest encodings are rejected. No padding, map, optional-field bitmap,
unknown extension, or trailing byte is permitted. A schema change requires a
new protocol version.

The authenticated channel and active profile bind:

- protocol version;
- pair/profile epoch;
- selected transport kind;
- candidate TLS SPKI SHA-256 pin;
- donor TLS SPKI SHA-256 pin for direct transport, or diagnostic-host TLS SPKI
  SHA-256 pin for diagnostic transport;
- donor build/device fingerprint hash;
- client nonce, server nonce, and session ID;
- request sequence and request ID;
- caller UID plus fixture package/signing identity hash;
- payload SHA-256;
- absolute deadline.

The TLS exporter/session transcript covers the same values. A frame that differs
from the authenticated profile or TLS transcript is rejected before method
dispatch. The diagnostic adapter additionally authenticates its typed provider
request, response, donor fingerprint, and request ID end to end.

## Fixed frame header

The header is exactly 322 bytes. `frameLength` includes header and payload.

| Offset | Size | Field | Required value or bound |
| ---: | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `RKA1` (`52 4b 41 31`). |
| 4 | 2 | `version` | `0x0001`. |
| 6 | 1 | `messageKind` | `0x01 REQUEST`, `0x02 RESPONSE`. |
| 7 | 1 | `transportKind` | `0x01 DIRECT_PINNED_TLS`, `0x02 DIAGNOSTIC_USB_RELAY`. |
| 8 | 1 | `method` | Method tag `0x01` through `0x07`. |
| 9 | 2 | `error` | Typed error tag; requests must use `0x0000 OK`. |
| 11 | 1 | `flags` | Must be zero in v1. |
| 12 | 2 | `headerLength` | `0x0142` (322). |
| 14 | 4 | `frameLength` | `322..2,097,152`; must equal received bytes. |
| 18 | 8 | `profileEpoch` | Active nonzero monotonic pair/profile epoch. |
| 26 | 8 | `sequence` | Frame ordinal `1..128`; a response is the ordinal immediately after its request. The unsigned-max vector verifies decoding only and is rejected by dispatch. |
| 34 | 8 | `deadlineUnixMillis` | Absolute deadline, no more than 120 seconds after authenticated session establishment. |
| 42 | 32 | `sessionId` | Cryptographically random session identifier. |
| 74 | 16 | `requestId` | Cryptographically random mutation/replay identifier. |
| 90 | 32 | `clientNonce` | Fresh candidate nonce. |
| 122 | 32 | `serverNonce` | Fresh donor or diagnostic-host nonce. |
| 154 | 32 | `candidateTlsPin` | SHA-256 of candidate TLS SPKI. |
| 186 | 32 | `peerTlsPin` | Donor TLS SPKI pin for direct; diagnostic-host TLS SPKI pin for diagnostic. |
| 218 | 32 | `donorFingerprint` | SHA-256 of the canonical donor fingerprint value. |
| 250 | 4 | `callerUid` | Exact unsigned fixture UID. |
| 254 | 32 | `callerIdentityHash` | SHA-256 of UTF-8 package name, one zero byte, and signing-certificate DER. |
| 286 | 32 | `payloadHash` | SHA-256 of the exact payload bytes, including zero-length payload. |
| 318 | 4 | `payloadLength` | Must equal `frameLength - 322`. |
| 322 | variable | `payload` | Fixed method schema below; no trailing bytes. |

Responses repeat all non-payload binding fields from the request except that
`sequence` advances by one. They may also differ in `messageKind`, `error`,
`payloadHash`, `payloadLength`, and `payload`. A non-`OK` response has an empty
payload; error details are local redacted logs, not protocol strings.

## Method and payload schemas

Method tags are fixed:

| Tag | Method | Request and response ownership |
| ---: | --- | --- |
| `0x01` | `GENERATE` | Donor creates and retains the key; returns public metadata and an opaque handle. |
| `0x02` | `GET_METADATA` | Donor returns current public metadata for a handle. |
| `0x03` | `DELETE` | Donor performs crash-safe deletion for an exact mutation. |
| `0x04` | `BEGIN` | Donor begins one live signing operation. |
| `0x05` | `UPDATE` | Donor consumes one ordered input chunk. |
| `0x06` | `FINISH` | Donor consumes final input, finishes, and returns the result. |
| `0x07` | `ABORT` | Donor terminates the live operation. |

The only v1 key shape is TEE, attested, EC P-256, purpose SIGN, digest SHA-256,
no user authentication, and no StrongBox. The enum tags used inside payloads
are `PURPOSE_SIGN=0x01`, `DIGEST_SHA256=0x01`, and `CURVE_P256=0x01`.

### `GENERATE` (`0x01`)

Request fields, in order:

| Type | Field | Bound |
| --- | --- | --- |
| `bytes16` | `logicalNameUtf8` | 1..128 UTF-8 bytes. This is a candidate logical name, never a donor alias. |
| `bytes16` | `attestationChallenge` | 1..128 bytes; physical fixture requires exactly 32. |
| 16 bytes | `mutationId` | Fresh opaque generation mutation ID. |
| `u8` | `purpose` | `0x01`. |
| `u8` | `digest` | `0x01`. |
| `u8` | `curve` | `0x01`. |

Response fields, in order:

| Type | Field | Bound |
| --- | --- | --- |
| 32 bytes | `keyHandle` | Authenticated opaque handle; contains no alias or blob. |
| `bytes16` | `publicKeySpki` | 1..2,048 DER bytes. |
| `u8` | `certificateCount` | 1..8. |
| repeated `bytes32` | `certificateDer` | Unique certificates, each 1..87,384 bytes; aggregate <=699,072 bytes. |

### `GET_METADATA` (`0x02`)

Request is one 32-byte `keyHandle`. Response is the complete `GENERATE`
response followed by `lifecycleRevision:u64`. Metadata never contains a donor
alias, key blob, private component, or local persistence path.

### `DELETE` (`0x03`)

Request is `keyHandle:32 bytes` followed by `mutationId:16 bytes`. Response is
`lifecycleRevision:u64`. Deletion occurs only after the handle, owner, epoch,
and mutation replay state are authenticated. An ambiguous mismatch never
deletes a donor key.

### `BEGIN` (`0x04`)

Request fields are `keyHandle:32 bytes`, `operationId:16 bytes`,
`purpose:u8=0x01`, and `digest:u8=0x01`. Response is one 32-byte authenticated
opaque `operationHandle`. Only one live operation exists per candidate session.

### `UPDATE` (`0x05`)

Request fields are `operationHandle:32 bytes`, `chunkIndex:u32` starting at
zero without gaps, and `input:bytes32` of 0..1,048,576 bytes. Response is
`output:bytes32` of 0..1,048,576 bytes. For signing, output is normally empty.
The cumulative UPDATE plus FINISH input is at most 2,097,152 bytes.

### `FINISH` (`0x06`)

Request fields are `operationHandle:32 bytes`, `input:bytes32`, and
`signature:bytes32`. `input` is 0..1,048,576 bytes and remains subject to the
2 MiB cumulative operation-input bound. The fixture SIGN route requires a
zero-length `signature`; v1 does not define VERIFY. Response is
`result:bytes32`, bounded by the frame limit.

### `ABORT` (`0x07`)

Request is one 32-byte `operationHandle`. Response is
`terminalState:u8=0x01` (`ABORTED`). Repeating the exact authenticated abort
returns the cached response. A changed replay is a conflict.

There is deliberately no `UPDATE_AAD`, `IMPORT`, raw-key operation, generic
algorithm parameter map, or vendor extension method.

## Session and sequencing state machine

```text
DISCONNECTED
  -> TLS_AUTHENTICATED       TLS 1.3, client authentication, exact pins
  -> HELLO_BOUND             version/epoch/transport/nonces/identity agree
  -> ACTIVE                  64 request/response pairs, one at a time
  -> DRAINING                close or terminal typed failure
  -> CLOSED
```

Any TLS, pin, profile, transport, nonce, session, fingerprint, caller identity,
payload-hash, or deadline mismatch transitions directly to `CLOSED` without
dispatch. `ACTIVE` accepts a new frame only when its sequence is the next
ordinal; a response immediately follows its request. An exact cached request
may repeat its older ordinal and returns its original cached response. A changed
replay, gap, duplicate uncached sequence, 65th request, expired deadline, or request
from a closed/previous session is rejected before backend execution. Session
IDs and both nonces are 32 bytes and are never reused after close.

Connect, read, write, and complete-frame timeouts are respectively 5, 5, 10,
and 30 seconds. The absolute session/request deadline is at most 120 seconds.
Timeout and transport failure after remote admission are fail-closed; no local,
software, PATCH, GENERATE, keybox, or mutation retry occurs.

## Replay contract

The replay key is `(profileEpoch, sessionId, requestId)`. The authenticated
request fingerprint is SHA-256 over the entire canonical request frame.

1. A new replay key with the next sequence dispatches exactly once, then
   atomically stores its request fingerprint and exact response.
2. The same replay key and byte-identical request returns the stored response
   without backend execution or counter increment.
3. The same replay key with any changed authenticated byte returns
   `REPLAY_CONFLICT`; backend execution count remains unchanged.
4. A replay from a retired epoch or old session returns `OLD_SESSION`, even if
   a request ID happens to match a previous session.
5. Ambiguous network loss never causes an automatic mutation retry. The caller
   may submit only the exact same canonical request to obtain cached resolution.

Replay records live for the authenticated reconciliation lifetime required by
the key mutation; they are not a license to resume a live operation after donor
process death.

## Donor key state machine

```text
ABSENT -> CREATING -> ACTIVE -> DELETE_PENDING -> DELETED
             |          |             |
             +----------+-------------+-> QUARANTINED
```

`GENERATE` creates `CREATING` state and becomes `ACTIVE` only after attestation,
public metadata, authenticated state, and audit mutation are durable. Recovery
either completes that exact mutation or reports a typed failure; it never
creates a second key. `DELETE` enters `DELETE_PENDING`, deletes only the exact
verified donor-owned key, commits the audit mutation, then becomes `DELETED`.
MAC, revision, owner, handle, or alias inconsistency becomes `QUARANTINED`.
Candidate-visible state never contains the internal alias.

## Donor operation state machine

```text
NONE -> BEGUN -> UPDATING -> FINISHED
          |         |
          +---------+-> ABORTED
          +---------+-> LOST
```

`BEGIN` is allowed only from `NONE` with an `ACTIVE` key and no other live
operation. Ordered UPDATE calls retain the operation on the donor. FINISH and
ABORT are terminal. Donor provider/process death changes every nonterminal
operation to `LOST`; a later call returns `INVALID_OPERATION_HANDLE`. Live
operations are never persisted, migrated, imported, or resumed.

## Typed errors

| Tag | Name | Required use |
| ---: | --- | --- |
| `0x0000` | `OK` | Successful response and every request header. |
| `0x0001` | `MALFORMED_FRAME` | Magic, length, reserved byte, hash, UTF-8, enum, or trailing-byte failure. |
| `0x0002` | `UNSUPPORTED_VERSION` | Version is not exactly 1. |
| `0x0003` | `FRAME_TOO_LARGE` | Declared or received frame exceeds 2 MiB. |
| `0x0004` | `FIELD_OUT_OF_RANGE` | A method field violates its exact bound or fixed value. |
| `0x0005` | `AUTH_FAILED` | TLS/session transcript or caller authentication fails. |
| `0x0006` | `PEER_PIN_MISMATCH` | Exact active-profile SPKI pin does not match. |
| `0x0007` | `TRANSPORT_MISMATCH` | Frame transport differs from profile/session transport. |
| `0x0008` | `OLD_SESSION` | Session is closed, unknown, or from a retired epoch. |
| `0x0009` | `SEQUENCE_ERROR` | New request ordinal is duplicate, zero, or has a gap. |
| `0x000a` | `REQUEST_LIMIT` | More than 64 requests in one session. |
| `0x000b` | `DEADLINE_EXCEEDED` | Absolute deadline is invalid or expired. |
| `0x000c` | `REPLAY_CONFLICT` | Authenticated request ID was reused with changed bytes. |
| `0x000d` | `DONOR_UNAVAILABLE` | Donor/diagnostic channel became unavailable; no fallback or mutation retry. |
| `0x000e` | `KEY_NOT_FOUND` | Authenticated handle names a deleted or absent key. |
| `0x000f` | `INVALID_KEY_HANDLE` | Key handle MAC, owner, epoch, or shape is invalid. |
| `0x0010` | `INVALID_OPERATION_HANDLE` | Operation is absent, terminal, lost, or belongs to another session. |
| `0x0011` | `OPERATION_ALREADY_LIVE` | Session already owns its single live operation. |
| `0x0012` | `INPUT_TOO_LARGE` | Chunk or cumulative operation input exceeds its bound. |
| `0x0013` | `ATTESTATION_REJECTED` | Donor public attestation metadata fails strict verification. |
| `0x0014` | `RKP_PROVENANCE_UNPROVEN` | Hardware KeyMint is shown but required RKPD correlation is absent. |
| `0x0015` | `BACKEND_ERROR` | Donor KeyStore/KeyMint returns a mapped non-secret failure. |
| `0x0016` | `CANCELLED` | Authenticated request was cancelled before a terminal backend result. |
| `0x0017` | `QUARANTINED` | Authenticated donor state fails integrity or owner checks. |
| `0x0018` | `PROFILE_EPOCH_ROLLBACK` | Profile epoch is older or retired. |
| `0x0019` | `INTERNAL_ERROR` | Fail-closed implementation invariant; no diagnostic text on wire. |

Errors are deterministic and never include aliases, handles, pins,
certificates, challenges, serials, addresses, or backend exception strings.

## Global fixed limits

| Item | Limit |
| --- | --- |
| Role/config text | 4 KiB |
| Authenticated profile | 64 KiB |
| Frame | 2 MiB, including the 322-byte header |
| Request chunk | 1 MiB |
| Total UPDATE plus FINISH input | 2 MiB |
| Fixture command nonce | 16 bytes, encoded as exactly 22 unpadded base64url characters |
| Client nonce, server nonce, session ID | 32 bytes each |
| Request ID and mutation/operation ID | 16 bytes |
| Attestation challenge | 1..128 bytes; physical fixture exactly 32 |
| Certificate chain | 1..8 unique DER certificates |
| Certificate size | 1..87,384 bytes each; aggregate <=699,072 |
| Logical name | 1..128 UTF-8 bytes |
| Profile ID | `[A-Za-z0-9._-]{1,64}` |
| Device serial | typed `DeviceSerial(role,value)`, `[A-Za-z0-9._:-]{1,128}`; donor and candidate differ |
| Requests per session | 64 |
| Live operation | One per candidate session |
| Direct endpoints | At most four provisioned endpoints |
| Absolute deadline | <=120 seconds after session establishment |
| Connect/read/write/frame timeout | 5/5/10/30 seconds |

Profiles contain no default or hardcoded IP. Endpoint discovery is read-only;
Tailscale is preferred when provisioned and available, then reachable LAN.

## Forbidden wire and persistence fields

Payload models use an explicit public-field allowlist. The following are
forbidden in requests, responses, profiles, candidate persistence, vectors,
logs, and evidence:

- raw or private keys;
- KeyMint opaque key blobs;
- donor AndroidKeyStore aliases or local paths;
- DICE chains, CDI, or UDS identity material;
- RKPD tokens, objects, payloads, or private state;
- host, candidate, or donor TLS private keys;
- arbitrary maps, captured Binder parcels, parcel bytes, or vendor blobs.

Opaque key and operation handles are protocol-owned authenticated identifiers,
not Android KeyMint blobs. RKA v1 does not call or impersonate
`IRemoteProvisioning` or `IRemotelyProvisionedComponent`.

The privacy and opacity boundary was checked against the immutable AOSP
`IRemotelyProvisionedComponent` contract at commit
`5688f7eb1e117ed26e642a695de300b7683acb87`; the URL returned HTTP 200 on
2026-07-30:

<https://android.googlesource.com/platform/hardware/interfaces/+/5688f7eb1e117ed26e642a695de300b7683acb87/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl>

That interface is a reference boundary only. It is not transported, invoked,
or exposed by RKA v1.

## Schema-valid golden vectors

Golden-vector hex files are lowercase, unspaced canonical encodings of
schema-valid binary frames.
`direct/lifecycle.hex` and `diagnostic/lifecycle.hex` each contain request and
response vectors for all seven methods. Their lifecycle payload bytes are
identical; only the bound transport and peer-pin fields differ.

Additional schema-valid vectors cover:

- changed authenticated replay and `REPLAY_CONFLICT`;
- exact replay through the replay-ledger test;
- `OLD_SESSION`;
- `ULong.MAX_VALUE` without signed narrowing.

Every schema-valid golden vector must pass full method-payload validation and
satisfy canonical decode-encode byte identity. Vector contents are public
synthetic values and contain no device identifiers or secrets.

## Framing-boundary probes

`framing-probes/exact-max-frame-prefix.hex` is not a golden vector or a
canonical method frame. No v1 method can legally fill a 2 MiB frame under the
per-method payload bounds. The probe supplies a framing-valid 322-byte header
for an exact 2 MiB frame plus deterministic zero payload solely to exercise the
transport framing limit. Framing-only decode must accept the materialized
2 MiB frame; full canonical decode must reject its schema-invalid payload.
