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

Each direction has an independent, exact unsigned 64-bit sequence beginning at
zero. Every request includes the protocol version, session ID, both nonces,
sequence, random 128-bit request ID, SHA-256 canonical-body hash, typed method,
and bounded absolute deadline. Bodies use deterministic length-prefixed fields
sorted by name with field-count, name, value, and total-size bounds.

The receiver rejects old sessions, duplicates, gaps, exhausted sequences,
expired deadlines, wrong pairs, invalid body hashes, copied handles, wrong
callers, and request-ID reuse with a changed body. A completed request ID with
the same body hash returns its cached response without re-executing the donor
operation.

Errors are typed at protocol, donor, and routing boundaries. They are not raw
KeyMint or Binder status parcels.

## State machines and recovery

Keys use:

`ABSENT → CREATING → ACTIVE → SUPERSEDED`

and:

`ACTIVE|SUPERSEDED → DELETE_PENDING → DELETED`

`QUARANTINED` is terminal pending explicit operator reconciliation.

Operations use:

`BEGUN → AAD → DATA → FINISHING → FINISHED`

with `ABORTED` for explicit cancellation. Any nonterminal operation found
after donor restart becomes `LOST`; it is never silently resumed. Target
restart reconciles its handle states from donor metadata. Alias replacement
supersedes the old opaque handle before activating the replacement, and delete
is idempotent.

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
