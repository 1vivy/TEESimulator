from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ObjectIdentifier

from two_phone_fixture import FixtureProof
from two_phone_types import ErrorCode, RunError


ATTESTATION_OID: Final = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
MAX_ATTESTATION_EXTENSION_BYTES: Final = 65_536
MAX_DER_ELEMENT_BYTES: Final = 65_536
TRUSTED_ENVIRONMENT: Final = 1
ORIGIN_GENERATED: Final = 0
ORIGIN_TAG: Final = 702


@dataclass(frozen=True, slots=True)
class DerTag:
    tag_class: int
    number: int
    constructed: bool


@dataclass(frozen=True, slots=True)
class DerValue:
    tag: DerTag
    value: bytes


@dataclass(frozen=True, slots=True)
class TrustAnchor:
    der: bytes


def load_trust_anchor(path: Path) -> TrustAnchor:
    try:
        encoded = path.read_bytes()
        if not 1 <= len(encoded) <= 87_384:
            raise ValueError("anchor bounds")
        if encoded.startswith(b"-----BEGIN CERTIFICATE-----"):
            if (
                encoded.count(b"-----BEGIN CERTIFICATE-----") != 1
                or encoded.count(b"-----END CERTIFICATE-----") != 1
                or not encoded.rstrip().endswith(b"-----END CERTIFICATE-----")
            ):
                raise ValueError("anchor pem shape")
            certificate = x509.load_pem_x509_certificate(encoded)
        elif b"-----BEGIN" in encoded or b"-----END" in encoded:
            raise ValueError("anchor pem shape")
        else:
            certificate = x509.load_der_x509_certificate(encoded)
            if certificate.public_bytes(serialization.Encoding.DER) != encoded:
                raise ValueError("anchor der trailing data")
        return TrustAnchor(certificate.public_bytes(serialization.Encoding.DER))
    except (OSError, ValueError) as failure:
        raise RunError(ErrorCode.ATTESTATION_VERIFICATION_FAILED) from failure


def load_trust_anchors(paths: tuple[Path, ...]) -> tuple[TrustAnchor, ...]:
    if not 1 <= len(paths) <= 8:
        raise RunError(ErrorCode.ATTESTATION_VERIFICATION_FAILED)
    anchors = tuple(load_trust_anchor(path) for path in paths)
    if len({anchor.der for anchor in anchors}) != len(anchors):
        raise RunError(ErrorCode.ATTESTATION_VERIFICATION_FAILED)
    return anchors


def verify_native_proof(proof: FixtureProof, challenge: bytes, trust_anchors: tuple[TrustAnchor, ...]) -> None:
    if len(challenge) != 32:
        raise RunError(ErrorCode.ATTESTATION_VERIFICATION_FAILED)
    try:
        if not proof.certificate_chain_der or proof.certificate_chain_der[-1] not in {anchor.der for anchor in trust_anchors}:
            raise ValueError("untrusted root")
        certificates = tuple(x509.load_der_x509_certificate(item) for item in proof.certificate_chain_der)
        _verify_chain(certificates)
        _verify_leaf(certificates[0], proof, challenge)
    except (InvalidSignature, ValueError, x509.ExtensionNotFound) as failure:
        raise RunError(ErrorCode.ATTESTATION_VERIFICATION_FAILED) from failure


def _verify_chain(certificates: tuple[x509.Certificate, ...]) -> None:
    if not 1 <= len(certificates) <= 8:
        raise ValueError("invalid chain size")
    for certificate, issuer in zip(certificates, certificates[1:]):
        if certificate.issuer != issuer.subject:
            raise ValueError("issuer mismatch")
        _verify_certificate_signature(certificate, issuer)
    root = certificates[-1]
    if root.issuer != root.subject:
        raise ValueError("untrusted root shape")
    _verify_certificate_signature(root, root)


def _verify_certificate_signature(certificate: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    algorithm = certificate.signature_hash_algorithm
    if algorithm is None:
        raise ValueError("signature algorithm missing")
    match key:
        case rsa.RSAPublicKey():
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), algorithm)
        case ec.EllipticCurvePublicKey():
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(algorithm))
        case _:
            raise ValueError("unsupported issuer key")


def _verify_leaf(certificate: x509.Certificate, proof: FixtureProof, challenge: bytes) -> None:
    key = certificate.public_key()
    match key:
        case ec.EllipticCurvePublicKey():
            if key.curve.name != "secp256r1":
                raise ValueError("not p256")
            key.verify(proof.signature, proof.payload, ec.ECDSA(hashes.SHA256()))
        case _:
            raise ValueError("not ec")
    extension = certificate.extensions.get_extension_for_oid(ATTESTATION_OID).value
    match extension:
        case x509.UnrecognizedExtension(value=encoded):
            _verify_key_description(encoded, challenge)
        case _:
            raise ValueError("unrecognized extension expected")


def _verify_key_description(encoded: bytes, challenge: bytes) -> None:
    if not 1 <= len(encoded) <= MAX_ATTESTATION_EXTENSION_BYTES:
        raise ValueError("attestation extension bounds")
    root, end = _read_value(encoded, 0)
    if end != len(encoded) or root.tag != DerTag(0, 16, True):
        raise ValueError("key description shape")
    fields = _children(root.value)
    if len(fields) != 8:
        raise ValueError("key description fields")
    if _integer(fields[1]) != TRUSTED_ENVIRONMENT or _integer(fields[3]) != TRUSTED_ENVIRONMENT:
        raise ValueError("not tee")
    if fields[4].tag != DerTag(0, 4, False) or fields[4].value != challenge:
        raise ValueError("challenge mismatch")
    tee_authorizations = fields[7]
    if tee_authorizations.tag != DerTag(0, 16, True):
        raise ValueError("tee authorizations")
    origins = [entry for entry in _children(tee_authorizations.value) if entry.tag == DerTag(2, ORIGIN_TAG, True)]
    if len(origins) != 1 or _integer(_only_child(origins[0])) != ORIGIN_GENERATED:
        raise ValueError("origin")


def _only_child(value: DerValue) -> DerValue:
    children = _children(value.value)
    if len(children) != 1:
        raise ValueError("explicit value")
    return children[0]


def _integer(value: DerValue) -> int:
    if value.tag not in (DerTag(0, 2, False), DerTag(0, 10, False)) or not value.value:
        raise ValueError("integer expected")
    if value.value[0] & 0x80:
        raise ValueError("negative integer")
    return int.from_bytes(value.value, "big")


def _children(encoded: bytes) -> tuple[DerValue, ...]:
    values: list[DerValue] = []
    position = 0
    while position < len(encoded):
        value, position = _read_value(encoded, position)
        values.append(value)
        if len(values) > 256:
            raise ValueError("too many fields")
    if position != len(encoded):
        raise ValueError("children bounds")
    return tuple(values)


def _read_value(encoded: bytes, position: int) -> tuple[DerValue, int]:
    tag, position = _read_tag(encoded, position)
    length, position = _read_length(encoded, position)
    end = position + length
    if length > MAX_DER_ELEMENT_BYTES or end > len(encoded):
        raise ValueError("truncated value")
    return DerValue(tag, encoded[position:end]), end


def _read_tag(encoded: bytes, position: int) -> tuple[DerTag, int]:
    if position >= len(encoded):
        raise ValueError("missing tag")
    initial = encoded[position]
    position += 1
    tag_class = initial >> 6
    constructed = bool(initial & 0x20)
    number = initial & 0x1F
    if number != 0x1F:
        return DerTag(tag_class, number, constructed), position
    number = 0
    for _ in range(4):
        if position >= len(encoded):
            raise ValueError("truncated high tag")
        octet = encoded[position]
        position += 1
        number = (number << 7) | (octet & 0x7F)
        if octet & 0x80 == 0:
            return DerTag(tag_class, number, constructed), position
    raise ValueError("high tag bounds")


def _read_length(encoded: bytes, position: int) -> tuple[int, int]:
    if position >= len(encoded):
        raise ValueError("missing length")
    initial = encoded[position]
    position += 1
    if initial < 0x80:
        return initial, position
    count = initial & 0x7F
    if count == 0 or count > 4 or position + count > len(encoded):
        raise ValueError("length bounds")
    octets = encoded[position : position + count]
    if octets[0] == 0:
        raise ValueError("leading length zero")
    length = int.from_bytes(octets, "big")
    minimum_count = max(1, (length.bit_length() + 7) // 8)
    if length < 128 or count != minimum_count:
        raise ValueError("noncanonical length")
    return length, position + count
