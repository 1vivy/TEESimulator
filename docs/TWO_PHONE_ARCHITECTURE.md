# Two-phone KeyMint virtualization architecture

## Milestone and custody boundary

This milestone is a host-only executable foundation. It does not connect to,
install on, stage files on, or mutate either phone. It does not claim that
cross-device Keystore2 virtualization is complete.

Donor A is the sole cryptographic custodian. The target stores only opaque,
pair-bound handles, public metadata, certificates, and reconciliation state.
Neither private key material nor the donor's internal logical name is a
protocol field or target-state field. Import is deliberately rejected by the
fake adapter: it will remain unsupported unless an implementation can preserve
the same non-exportable custody invariant.

Hardware `ATTEST_KEY` means a KeyMint key authorized to attest other keys; it
cannot arbitrary-sign caller-provided data. The future donor helper must run
inside the corresponding donor app process so stock Keystore2 derives the
matching `ATTESTATION_APPLICATION_ID` from that process's package and signing
identity. A privileged helper in an unrelated process would produce the wrong
application identity even if it could reach the same Keystore2 APIs.

## Protocol

The wire contract is normalized protocol version 1, never captured Binder
parcels. A transport interface hides mutually pinned TLS identities. Session
establishment binds the target/server pins, a 256-bit client nonce, and a
256-bit server nonce into a session ID.

`Envelope` and `CanonicalBody` remain the legacy host-foundation model;
`CanonicalBody` uses sorted name/value fields. The normalized V1 transport uses
the separate typed fixed-schema request and result payloads. Its fields have
explicit numeric tags, deterministic big-endian encoding, exact bounds, and a
hard 2 MiB frame cap. It does not encode Binder parcels or arbitrary field
names.

Target-to-donor requests have one exact unsigned 64-bit sequence beginning at
zero. Every request includes the protocol version, derived session ID, both
nonces, sequence, random 128-bit request ID, typed-payload hash, typed method,
stable caller identity, and bounded absolute deadline. Responses do not have a
second sequence: they carry the trusted session ID and request ID and are
accepted only through a stateful target correlator. The target registers each
outgoing request, validates response version/session/request ID/method, and
atomically consumes a matching response once. Parsing a response frame alone
does not establish correlation.

The donor rejects old sessions or nonces, duplicates, gaps, exhausted
sequences, expired or overlong deadlines, wrong pairs, invalid payload hashes,
wrong callers, and request-ID reuse with a changed authenticated request. An
exact completed request-ID replay returns its cached response without
re-executing donor state. Persistent generation/deletion ID conflicts and
operation-step conflicts use `REPLAY_CONFLICT`; invalid key and operation
handles use distinct stable errors.

Errors are typed at protocol, donor, and routing boundaries. They are not raw
KeyMint or Binder status parcels.

## State machines and recovery

Keys use:

`ABSENT → CREATING → ACTIVE → SUPERSEDED`

and:

`ACTIVE|SUPERSEDED → DELETE_PENDING → DELETED`

`QUARANTINED` is terminal pending explicit operator reconciliation.

V1 operations model only EC-P256/SHA-256 `SIGN`:

`BEGUN → DATA → FINISHING → FINISHED`

`UPDATE` appends each chunk and returns no output; `FINISH` is the only method
that returns the signature. `UPDATE_AAD` keeps its reserved typed wire shape for
future versions but is unsupported for V1 `SIGN`: it aborts the live operation,
caches that typed error for exact step replay, and makes later steps invalid.
`ABORTED` also represents explicit cancellation. Any nonterminal operation
found after donor restart becomes `LOST`; it is never silently resumed. Target
restart reconciles its handle states from complete donor public metadata.
Alias replacement supersedes the old opaque handle before activating the
replacement, and delete is idempotent.

## Routing boundary

The host-testable routing seam is shaped for
`KeyMintSecurityLevelInterceptor`. Only explicitly allowlisted, attested
`TRUSTED_ENVIRONMENT` requests are eligible. StrongBox, AVF, non-attested,
non-allowlisted-purpose, and non-allowlisted-caller requests are unchanged
platform pass-through bytes and do not contact the donor.

User-authentication and device-local semantics are rejected because their
security state cannot be truthfully virtualized across phones. If an eligible
routed request loses donor connectivity, it fails closed. There is no local
software generation, keybox, cached-private-key, or other fallback.

The module boot and action entry points remain inert. A later device milestone
must integrate this policy seam without introducing root-direct KeyMint,
software RKP, remote-provisioning CSR/certification calls, bundled keys or
endpoints, or any StrongBox/AVF hook.
