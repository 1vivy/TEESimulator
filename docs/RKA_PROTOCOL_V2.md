# Production RKA protocol v2

Status: frozen production contract. RKA v1 remains byte-immutable and
fixture-only.

RKA v2 is the module-owned direct donor/candidate protocol. It uses RFC 8949
deterministic CBOR. All maps have unsigned-integer keys in ascending numeric
order. Decoders reject duplicate, non-integer, unknown, indefinite-length, or
non-shortest keys/items before dispatch. A TLS stream record is
`u32be(payload_length) || canonical_cbor_map`; payload length is
`1..1,048,576` and nesting depth is at most 8.

No Binder parcel/object, Android alias, KeyMint/RKP key blob, private key,
transport secret, resumable operation object, or cross-UID grant is part of
this protocol. Handles and IDs are opaque random values and contain no alias,
UID, counter, blob, or device identifier.

## Frame

The common map is:

| Key | Field | Type |
| ---: | --- | --- |
| 0 | version | `2` |
| 1 | kind | frozen integer below |
| 2 | request ID | `bstr16` |
| 3 | session ID | `bstr32` |
| 4 | profile epoch | `u64` |
| 5 | shared sequence | `u32` |
| 6 | body | exact map for `kind` |
| 7 | transcript hash | `bstr32` |

Kinds are `1 HELLO`, `2 HELLO_ACK`, `10 GENERATE`, `11 GET`, `12 LIST`,
`13 DELETE`, `20 BEGIN`, `21 UPDATE_AAD`, `22 UPDATE`, `23 FINISH`, `24 ABORT`,
`30 RESULT`, and `31 ERROR`. Candidate sequence 0 is HELLO. Each sent frame
increments the shared session sequence once. A response copies the triggering
request ID. RESULT/ERROR body key 0 copies the triggering request kind.

## Request bodies

- HELLO:
  `{0:role(1 CANDIDATE),1:transport(1 DIRECT),2:profile_id_hash(bstr32),`
  `3:candidate_nonce(bstr32),4:capability_bitmap(0x0f)}`.
- GENERATE:
  `{0:candidate_identity,1:foreground_request,2:semi_unique_envelope}`.
- GET and DELETE: `{0:alias_handle(bstr16)}`.
- LIST: `{0:identity_hash(bstr32)}`.
- BEGIN:
  `{0:alias_handle(bstr16),1:purpose(2 SIGN),2:digest(4 SHA256),`
  `3:padding(0 NONE)}`.
- UPDATE_AAD and UPDATE:
  `{0:operation_handle(bstr16),1:chunk(bstr0..65536)}`.
- FINISH:
  `{0:operation_handle(bstr16),1:final_input(bstr0..65536)}`.
- ABORT: `{0:operation_handle(bstr16)}`.

Capability bits are 0 GENERATE, 1 GET/LIST/DELETE,
2 BEGIN/UPDATE_AAD/UPDATE/FINISH/ABORT, and 3 leaf proof. HELLO requires
exactly `0x0f`; reserved bits are invalid.

## Response bodies

- HELLO_ACK:
  `{0:accepted(bool),1:donor_nonce(bstr32),2:limits_hash(bstr32),`
  `3:donor_irpc_identity_hash(bstr32)}`.
- RESULT: `{0:request_kind,1:result_map}`.
- ERROR:
  `{0:request_kind,1:rka_error_code(u32),2:retryable(false),`
  `3:quarantined(bool),4:detail_hash(bstr32)}`.

Result maps are:

- GENERATE/GET:
  `{0:alias_handle,1:certificate_chain(array<bstr DER>),`
  `2:characteristics_hash,3:envelope,4:leaf_proof}`.
- LIST: `{0:entries(array<[alias_handle,identity_hash,state_u8]>)}` sorted by
  alias bytes.
- DELETE: `{0:deleted(bool)}`.
- BEGIN: `{0:operation_handle,1:max_chunk_bytes(65536)}`.
- UPDATE_AAD/UPDATE: `{0:consumed(u32),1:output(bstr)}`.
- FINISH: `{0:signature(bstr DER ECDSA),1:leaf_proof_hash(bstr32)}`.
- ABORT: `{0:aborted(bool)}`.

Leaf proof is
`{0:leaf_spki_hash,1:chain_set_hash,2:challenge_hash,3:aaid_hash,`
`4:envelope_hash,5:transcript_signature}`, with five `bstr32` hashes and a DER
ECDSA signature.

## Candidate identity and foreground request

Candidate identity is:

`{0:android_user(u32),1:uid(u32),2:packages(array),3:aaid_der(bstr),`
`4:identity_hash(bstr32),5:policy_lineage_hash(bstr32)}`.

Each package is
`[package_name(tstr),version_code(u64),current_signers(array<bstr DER>)]`.
Packages are sorted by package UTF-8 bytes. Current signer DER values are
sorted bytewise. Bounds are 16 packages, 255 UTF-8 name bytes, eight current
signers per package, 8 KiB per signer, and 128 KiB AAID DER.

The platform AAID contains packages, version codes, and current
`GET_SIGNATURES` signer certificate bytes only. Signing lineage never changes
AAID DER and appears only through module-policy `policy_lineage_hash`.
`identity_hash` omits map key 4.

Foreground request is:

`{0:security_level(1 TEE),1:algorithm(3 EC),2:curve(1 P256),`
`3:purpose(2 SIGN),4:digest(4 SHA256),5:attestation_challenge(bstr16..64),`
`6:alias_handle(bstr16),7:operation_handle(bstr16 optional after BEGIN),`
`8:input(bstr optional when applicable)}`.

Unknown enum values are invalid. Raw Android aliases and Binder/KeyMint
handles are forbidden.

## SemiUniqueRkpEnvelopeV1

This envelope exists only inside module-owned RKA v2 messages. It is never
inserted into the provisioning CSR, AOSP-equivalent POST body, or server
response bytes.

| Key | Field |
| ---: | --- |
| 0 | version `1` |
| 1 | candidate identity hash `bstr32` |
| 2 | AAID hash `bstr32` |
| 3 | profile epoch `u64` |
| 4 | candidate nonce `bstr32` |
| 5 | donor nonce `bstr32` |
| 6 | donor IRPC identity hash `bstr32` |
| 7 | ordered RKP public hashes, at most 20 `bstr32` |
| 8 | exact HAL CSR hash `bstr32` |
| 9 | exact server POST body hash `bstr32` |
| 10 | exact decoded server challenge hash `bstr32` |
| 11 | exact HTTPS response body hash `bstr32` |
| 12 | validated chain-set hash `bstr32` |
| 13 | donor monotonic start milliseconds `u64` |
| 14 | TTL seconds, exactly `120` |
| 15 | maximum uses, exactly `1` |
| 16 | successful FINISH count, `0..1` |

Keys 7 through 12 are omitted, never null, until their named phase. They form
a contiguous phase prefix and become immutable once present. BEGIN, UPDATE,
failed/lost operations, and ABORT do not increment the use count. Only a
FINISH that returns a signature increments it. One operation may be live per
handle. ABORT permits a fresh BEGIN; the first successful FINISH prevents any
later BEGIN.

## Hashes and transcripts

The ten literal ASCII/NUL domains are:

```text
TEESIM-RKA-V2/FRAME\0
TEESIM-RKA-V2/IDENTITY\0
TEESIM-RKA-V2/AAID\0
TEESIM-RKA-V2/PROFILE\0
TEESIM-RKA-V2/IRPC\0
TEESIM-RKA-V2/RKP-PUBLIC\0
TEESIM-RKA-V2/CHAIN-SET\0
TEESIM-RKA-V2/ENVELOPE\0
TEESIM-RKA-V2/LEAF-PROOF\0
TEESIM-RKA-V2/AUDIT\0
```

The exact deterministic-CBOR preimages are:

- identity: `IDENTITY_DOMAIN || identity_without_key_4`;
- AAID: `AAID_DOMAIN || aaid_der` (raw DER);
- challenge:
  `LEAF_PROOF_DOMAIN || {0:"challenge",1:attestation_challenge}`;
- policy lineage:
  `IDENTITY_DOMAIN || {0:"policy-lineage",1:ordered_lineage_entries}`;
- profile ID: `PROFILE_DOMAIN || {0:"profile-id",1:public_profile_map}`;
- limits: `PROFILE_DOMAIN || {0:"limits",1:frozen_limits_map}`;
- donor IRPC identity: `IRPC_DOMAIN || irpc_public_identity_map`;
- each RKP public hash: `RKP_PUBLIC_DOMAIN || exact_canonical_cose_key_bytes`;
- leaf SPKI: `RKP_PUBLIC_DOMAIN || leaf_subject_public_key_info_der`;
- characteristics:
  `PROFILE_DOMAIN || canonical_key_characteristics`;
- detail: `AUDIT_DOMAIN || {0:rka_error_code,1:redacted_detail_map}`;
- chain set:
  `CHAIN_SET_DOMAIN || ordered_array_of_ordered_der_chain_arrays`;
- envelope: `ENVELOPE_DOMAIN || envelope`;
- leaf proof: `LEAF_PROOF_DOMAIN || complete_leaf_proof`.

SHA-256 is used in every case. Four wire-byte hashes never decode or
re-encode: HAL CSR hashes exact HAL-returned CBOR bytes; server body hashes
exact AOSP-equivalent POST bytes; server challenge hashes exact decoded
challenge bytes; server response hashes exact HTTPS response body bytes.

`H_-1` is 32 zero bytes and
`H_i=SHA256(FRAME_DOMAIN || H_(i-1) || frame_i_without_key_7)`.
Frame key 7 is `H_i`. A RESULT leaf proof in frame `i` signs
`LEAF_PROOF_DOMAIN || envelope_hash || H_(i-1) || leaf_spki_hash ||`
`chain_set_hash` with ECDSA-P256/SHA-256 before the complete proof is encoded
and `H_i` is computed. Audit uses the equivalent chain
`A_i=SHA256(AUDIT_DOMAIN || A_(i-1) || audit_entry_i_without_hash)`.

## Auxiliary maps

`public_profile_map` is
`{0:profile_version(2),1:profile_epoch,2:donor_transport_spki_hash,`
`3:candidate_transport_spki_hash,4:canonical_endpoint_host,`
`5:port(1..65535),6:allowed_identity_hashes(sorted unique max16),`
`7:attestation_root_bundle_hash,8:policy_version(1)}`.

`irpc_public_identity_map` is
`{0:version_number(3),1:security_level(1 TEE),2:component_name(tstr1..255),`
`3:unique_id(tstr1..255),4:supported_eek_curve(1 P256),5:max_csr_keys(20)}`.

`canonical_key_characteristics` is
`{0:security_level(1),1:algorithm(3),2:curve(1),3:purposes([2]),`
`4:digests([4]),5:origin(0 GENERATED),6:no_auth_required(bool),`
`7:rollback_resistant(bool)}`.

`redacted_detail_map` is `{0:stage_u8,1:request_kind}`. Stages are
`1 FRAME`, `2 POLICY`, `3 SESSION`, `4 TRANSPORT`, `5 RKP`, `6 KEYMINT`,
`7 LIFECYCLE`, and `8 STORAGE`.

Lineage entries are sorted
`[package_name, signer_history(oldest-to-newest hashes)]`, at most 16 package
entries and 16 signer hashes, with no duplicates. Each signer hash is
`SHA256(IDENTITY_DOMAIN || signer_certificate_der)`.

Chain arrays preserve original IRPC-key order, contain at most 20 leaf-to-root
chains, at least two DER certificates per chain, at most 64 KiB per
certificate, and at most 512 KiB total.

## IDs, replay, limits, and errors

Candidate owns random session IDs, candidate nonces, request IDs, and
pre-GENERATE alias handles. Donor owns donor nonces and operation handles.
Every owner collision-checks both live and retained tombstone namespaces.

Tombstone keys are deterministic CBOR arrays:

- session: `[peer_spki_hash,profile_epoch,session_id]`;
- request:
  `[peer_spki_hash,profile_epoch,session_id,request_id,request_kind]`;
- operation:
  `[peer_spki_hash,profile_epoch,session_id,operation_handle]`.

Request tombstones persist atomically before non-idempotent dispatch;
operation tombstones persist before releasing an operation. Reuse, duplicate
tuple, or same request ID with a different kind is INVALID_REQUEST. Retention
is 24 hours or two profile epochs, whichever is longer, under donor monotonic
clock authority.

Limits are: one peer connection per role, four sessions, four remote keys, one
live operation per key, four total operations, 128 updates, 64 KiB per chunk,
1 MiB total operation input, 20 RKP keys/chains, 64 KiB per certificate, and
512 KiB returned chains. Deadlines are 5 s UDS, 10 s connect, 20 s HTTP,
30 s session idle, and 120 s total TTL.

Alias states are `1 ACTIVE`, `2 LOST`, `3 QUARANTINED`, and `4 DELETED`.
RKA errors are `1 INVALID_REQUEST`, `2 POLICY_REJECTED`,
`3 UNSUPPORTED_ALGORITHM`, `4 UNSUPPORTED_PURPOSE`, `5 UNSUPPORTED_DIGEST`,
`6 UNSUPPORTED_EC_CURVE`, `7 CAPACITY`, `8 STALE_HANDLE`, `9 TRANSPORT`,
`10 OPERATION_LOST`, and `11 QUARANTINED`.

Malformed/canonical/replay/sequence errors map to KeyMint INVALID_ARGUMENT;
policy rejection to Keystore2 PERMISSION_DENIED; capacity to
TOO_MANY_OPERATIONS; stale/deleted handles to INVALID_KEY_BLOB; pre-operation
peer/Binder death to SECURE_HW_COMMUNICATION_FAILED; live-operation death to
OPERATION_CANCELLED; and POST/hardware ambiguity to
SECURE_HW_COMMUNICATION_FAILED with quarantine. Pre-admission mismatch is
local PASS_THROUGH. No remote error may select candidate-local crypto.
