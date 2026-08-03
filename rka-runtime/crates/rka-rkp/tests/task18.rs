#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures fail immediately when certificate construction is invalid"
)]

use ciborium::value::Value;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData,
};
use ring::digest::{SHA256, digest};
use rka_rkp::{
    CertificateStatus, ExpectedKey, PreparedCertificateRequest, ResponseContext, RootBundle,
    StatusSnapshot, ValidationError, assemble_android_v3_body, parse_signed_certificates,
    returned_serials, validate_response,
};
use x509_parser::parse_x509_certificate;

fn noncanonical_hal_csr() -> Vec<u8> {
    vec![
        0x98, 0x02, 0x84, 0x43, 0x18, 0x01, 0x01, 0xa0, 0x45, 0x1a, 0, 0, 0, 1, 0x41, 0xaa, 0x84,
        0x42, 0x19, 0x01, 0xa0, 0x43, 0x18, 0x2a, 0x01, 0x41, 0xbb,
    ]
}

#[test]
fn standard_body_preserves_signed_csr_and_activates_unique_chains() {
    // Given a non-canonical OEM outer encoding containing signature-covered bstr values.
    let hal = noncanonical_hal_csr();

    // When Android's standard v3 body is assembled.
    let prepared = assemble_android_v3_body(&hal, "android/test/fingerprint").unwrap();

    // Then only the containing structure is re-encoded and the exact unverified map is appended.
    assert_ne!(prepared.body(), hal);
    assert!(
        prepared
            .body()
            .windows(3)
            .any(|value| value == [0x18, 0x01, 0x01])
    );
    assert!(
        prepared
            .body()
            .windows(3)
            .any(|value| value == [0x19, 0x01, 0xa0])
    );
    assert_ne!(prepared.hal_csr_hash(), prepared.server_body_hash());
    assert_eq!(
        prepared.body(),
        &[
            0x83, 0x84, 0x43, 0x18, 0x01, 0x01, 0xa0, 0x45, 0x1a, 0, 0, 0, 1, 0x41, 0xaa, 0x84,
            0x42, 0x19, 0x01, 0xa0, 0x43, 0x18, 0x2a, 0x01, 0x41, 0xbb, 0xa1, 0x6b, b'f', b'i',
            b'n', b'g', b'e', b'r', b'p', b'r', b'i', b'n', b't', 0x78, 0x18, b'a', b'n', b'd',
            b'r', b'o', b'i', b'd', b'/', b't', b'e', b's', b't', b'/', b'f', b'i', b'n', b'g',
            b'e', b'r', b'p', b'r', b'i', b'n', b't',
        ]
    );
    validates_unique_leaf_spki_and_every_chain_serial();
}

#[test]
fn parses_standard_shared_and_unique_certificate_response() {
    // Given AOSP's [shared bstr, [unique bstr...]] response.
    let body = [0x82, 0x42, 3, 4, 0x82, 0x42, 1, 2, 0x41, 9];

    // When parsed.
    let chains = parse_signed_certificates(&body, 2).unwrap();

    // Then each unique prefix is followed by the exact shared suffix.
    assert_eq!(chains, vec![vec![1, 2, 3, 4], vec![9, 3, 4]]);
}

#[test]
fn returned_certificate_serials_are_canonical_status_keys() {
    let (_, shared, leaves) = certificate_fixture();
    let response = signed_response(&shared, leaves.iter().map(|leaf| leaf.der.as_slice()));

    let serials = returned_serials(&response, leaves.len()).unwrap();

    assert!(!serials.is_empty());
    assert!(serials.iter().all(|serial| {
        !serial.starts_with('0')
            && serial
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }));
}

#[test]
fn validates_unique_leaf_spki_and_every_chain_serial() {
    let (root, shared, leaves) = certificate_fixture();
    let response = signed_response(&shared, leaves.iter().map(|leaf| leaf.der.as_slice()));
    let prepared = assemble_android_v3_body(&[0x80], "fingerprint").unwrap();
    let expected = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| ExpectedKey::new([u8::try_from(index + 1).unwrap(); 32], leaf.spki))
        .collect::<Vec<_>>();
    let now = 1_785_500_000;
    let status = StatusSnapshot::for_test(
        now,
        60,
        leaves
            .iter()
            .flat_map(|leaf| leaf.serials.iter())
            .chain(root.serials.iter())
            .map(|serial| (serial.as_str(), CertificateStatus::Good)),
    );
    let roots = RootBundle::for_test(7, vec![sha256(&root.der)]);
    let context = ResponseContext::new(
        prepared.hal_csr_hash(),
        "request",
        "request",
        [4; 32],
        [4; 32],
        7,
        now,
    );
    let mut quarantined = Vec::new();

    let validated = validate_response(
        &prepared,
        prepared.body(),
        &response,
        &expected,
        &context,
        &roots,
        &status,
        &mut |handle| quarantined.push(handle),
    )
    .unwrap();

    assert_eq!(
        validated
            .chains()
            .iter()
            .map(|chain| chain.leaf_spki_hash)
            .collect::<Vec<_>>(),
        leaves.iter().map(|leaf| leaf.spki).collect::<Vec<_>>()
    );
    assert_ne!(
        validated.chains().first().unwrap().chain_hash,
        validated.chains().get(1).unwrap().chain_hash
    );
    assert!(quarantined.is_empty());
}

#[test]
fn reject_mutated_csr() {
    let prepared = PreparedCertificateRequest::for_test([1; 32], [2; 32], vec![0x80]);
    let keys = [
        ExpectedKey::for_test([7; 32], [1; 32]),
        ExpectedKey::for_test([8; 32], [2; 32]),
    ];
    let mut quarantined = Vec::new();
    let result = validate_response(
        &prepared,
        &[0x81],
        &[],
        &keys,
        &ResponseContext::for_test([3; 32], "request", 7),
        &RootBundle::production(7),
        &StatusSnapshot::for_test(7, 60, []),
        &mut |handle| quarantined.push(handle),
    );
    assert_eq!(result, Err(ValidationError::CsrMutation));
    assert_eq!(quarantined, vec![[7; 32], [8; 32]]);
}

struct TestCertificate {
    der: Vec<u8>,
    spki: [u8; 32],
    serials: Vec<String>,
}

fn certificate_fixture() -> (TestCertificate, Vec<u8>, Vec<TestCertificate>) {
    certificate_fixture_with_eku(true, false, false)
}

fn certificate_fixture_with_leaf_policy(
    leaf_is_ca: bool,
    leaf_digital_signature: bool,
) -> (TestCertificate, Vec<u8>, Vec<TestCertificate>) {
    certificate_fixture_with_eku(leaf_is_ca, leaf_digital_signature, false)
}

fn certificate_fixture_with_eku(
    leaf_is_ca: bool,
    leaf_digital_signature: bool,
    restrictive_eku: bool,
) -> (TestCertificate, Vec<u8>, Vec<TestCertificate>) {
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let root_key = KeyPair::generate().unwrap();
    let root = root_params.self_signed(&root_key).unwrap();
    let root_der = root.der().to_vec();
    let root_issuer = Issuer::new(root_params, root_key);

    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let intermediate_der = intermediate.der().to_vec();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

    let leaves = (0..2)
        .map(|_| {
            let mut params = CertificateParams::new(vec!["key.invalid".to_owned()]).unwrap();
            if leaf_is_ca {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            }
            params.key_usages.push(if leaf_digital_signature {
                KeyUsagePurpose::DigitalSignature
            } else {
                KeyUsagePurpose::KeyCertSign
            });
            if restrictive_eku {
                params
                    .extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ClientAuth);
            }
            let key = KeyPair::generate().unwrap();
            let spki = sha256(&key.subject_public_key_info());
            let certificate = params.signed_by(&key, &intermediate_issuer).unwrap();
            TestCertificate {
                der: certificate.der().to_vec(),
                spki,
                serials: serials(&[certificate.der(), intermediate.der()]),
            }
        })
        .collect::<Vec<_>>();
    let mut shared = intermediate_der;
    shared.extend_from_slice(&root_der);
    (
        TestCertificate {
            der: root_der.clone(),
            spki: sha256(&root_issuer.key().subject_public_key_info()),
            serials: serials(&[root.der()]),
        },
        shared,
        leaves,
    )
}

fn serials(certificates: &[&[u8]]) -> Vec<String> {
    certificates
        .iter()
        .map(|der| {
            let certificate = parse_x509_certificate(der).unwrap().1;
            certificate
                .raw_serial()
                .iter()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .map(|nibble| {
                    char::from(
                        b"0123456789abcdef"
                            .get(usize::from(nibble))
                            .copied()
                            .unwrap(),
                    )
                })
                .skip_while(|character| *character == '0')
                .collect()
        })
        .collect()
}

fn signed_response<'a>(shared: &[u8], leaves: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let value = Value::Array(vec![
        Value::Bytes(shared.to_vec()),
        Value::Array(
            leaves
                .into_iter()
                .map(|leaf| Value::Bytes(leaf.to_vec()))
                .collect(),
        ),
    ]);
    let mut body = Vec::new();
    ciborium::into_writer(&value, &mut body).unwrap();
    body
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest(&SHA256, bytes).as_ref().try_into().unwrap()
}

#[test]
fn reject_duplicate_leaf_spki() {
    let prepared = PreparedCertificateRequest::for_test([1; 32], [2; 32], vec![0x80]);
    let keys = [
        ExpectedKey::for_test([7; 32], [1; 32]),
        ExpectedKey::for_test([8; 32], [1; 32]),
    ];
    let mut quarantined = Vec::new();
    let result = validate_response(
        &prepared,
        &[0x80],
        &[],
        &keys,
        &ResponseContext::for_test([1; 32], "request", 7),
        &RootBundle::production(7),
        &StatusSnapshot::for_test(
            7,
            60,
            [
                ("01", CertificateStatus::Good),
                ("02", CertificateStatus::Good),
            ],
        ),
        &mut |handle| quarantined.push(handle),
    );
    assert_eq!(result, Err(ValidationError::DuplicateSpki));
    assert_eq!(quarantined, vec![[7; 32], [8; 32]]);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-like adversarial scenario reuses a single generated chain fixture"
)]
fn rejects_count_spki_der_signature_validity_type_root_epoch_and_status_failures() {
    let (root, shared, leaves) = certificate_fixture();
    let prepared = assemble_android_v3_body(&[0x80], "fingerprint").unwrap();
    let expected = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| ExpectedKey::new([u8::try_from(index + 1).unwrap(); 32], leaf.spki))
        .collect::<Vec<_>>();
    let now = 1_785_500_000;
    let all_serials = leaves
        .iter()
        .flat_map(|leaf| leaf.serials.iter())
        .chain(root.serials.iter())
        .cloned()
        .collect::<Vec<_>>();
    let good_status = || {
        StatusSnapshot::for_test(
            now,
            60,
            all_serials
                .iter()
                .map(|serial| (serial.as_str(), CertificateStatus::Good)),
        )
    };
    let context = ResponseContext::new(
        prepared.hal_csr_hash(),
        "request",
        "request",
        [4; 32],
        [4; 32],
        7,
        now,
    );
    let roots = RootBundle::for_test(7, vec![sha256(&root.der)]);
    let response = signed_response(&shared, leaves.iter().map(|leaf| leaf.der.as_slice()));
    let validate = |body: &[u8],
                    keys: &[ExpectedKey],
                    response_context: &ResponseContext,
                    root_bundle: &RootBundle,
                    status: &StatusSnapshot| {
        validate_response(
            &prepared,
            prepared.body(),
            body,
            keys,
            response_context,
            root_bundle,
            status,
            &mut |_| {},
        )
    };

    assert_eq!(
        parse_signed_certificates(&response, 1),
        Err(ValidationError::Count)
    );
    let duplicate_response = signed_response(
        &shared,
        [
            leaves.first().unwrap().der.as_slice(),
            leaves.first().unwrap().der.as_slice(),
        ],
    );
    assert_eq!(
        validate(
            &duplicate_response,
            &expected,
            &context,
            &roots,
            &good_status()
        ),
        Err(ValidationError::DuplicateChain)
    );
    let mut missing = expected.clone();
    *missing.get_mut(1).unwrap() = ExpectedKey::new([2; 32], [9; 32]);
    assert_eq!(
        validate(&response, &missing, &context, &roots, &good_status()),
        Err(ValidationError::Spki)
    );
    let invalid_der = signed_response(
        &shared,
        [b"not-der".as_slice(), leaves.get(1).unwrap().der.as_slice()],
    );
    assert_eq!(
        validate(&invalid_der, &expected, &context, &roots, &good_status()),
        Err(ValidationError::Der)
    );
    let mut bad_leaf = leaves.first().unwrap().der.clone();
    *bad_leaf.last_mut().unwrap() ^= 1;
    let bad_signature = signed_response(
        &shared,
        [bad_leaf.as_slice(), leaves.get(1).unwrap().der.as_slice()],
    );
    assert_eq!(
        validate(&bad_signature, &expected, &context, &roots, &good_status()),
        Err(ValidationError::Signature)
    );
    let expired_context = ResponseContext::new(
        prepared.hal_csr_hash(),
        "request",
        "request",
        [4; 32],
        [4; 32],
        7,
        1,
    );
    assert_eq!(
        validate(
            &response,
            &expected,
            &expired_context,
            &roots,
            &good_status()
        ),
        Err(ValidationError::Validity)
    );
    assert_eq!(
        validate(
            &response,
            &expected,
            &context,
            &RootBundle::for_test(7, vec![[0; 32]]),
            &good_status()
        ),
        Err(ValidationError::Root)
    );
    let wrong_epoch = ResponseContext::new(
        prepared.hal_csr_hash(),
        "request",
        "request",
        [4; 32],
        [4; 32],
        8,
        now,
    );
    assert_eq!(
        validate(&response, &expected, &wrong_epoch, &roots, &good_status()),
        Err(ValidationError::Epoch)
    );
    let wrong_challenge = ResponseContext::new(
        prepared.hal_csr_hash(),
        "request",
        "request",
        [4; 32],
        [5; 32],
        7,
        now,
    );
    assert_eq!(
        validate(
            &response,
            &expected,
            &wrong_challenge,
            &roots,
            &good_status()
        ),
        Err(ValidationError::Challenge)
    );
    assert_eq!(
        validate(
            &response,
            &expected,
            &context,
            &roots,
            &StatusSnapshot::for_test(now, 1, []),
        ),
        Err(ValidationError::StatusIncomplete)
    );
    let revoked = StatusSnapshot::for_test(
        now,
        60,
        all_serials.iter().map(|serial| {
            (
                serial.as_str(),
                if serial == all_serials.first().unwrap() {
                    CertificateStatus::Revoked
                } else {
                    CertificateStatus::Good
                },
            )
        }),
    );
    assert_eq!(
        validate(&response, &expected, &context, &roots, &revoked),
        Err(ValidationError::Revoked)
    );
    assert_eq!(
        validate(
            &response,
            &expected,
            &context,
            &roots,
            &StatusSnapshot::for_test(
                now.saturating_sub(60),
                60,
                all_serials
                    .iter()
                    .map(|serial| (serial.as_str(), CertificateStatus::Good)),
            ),
        ),
        Err(ValidationError::StatusStale)
    );

    for (leaf_is_ca, digital_signature, expected_error) in [
        (false, false, ValidationError::AttestationBasicConstraints),
        (true, true, ValidationError::AttestationKeyUsage),
    ] {
        let (bad_root, bad_shared, bad_leaves) =
            certificate_fixture_with_leaf_policy(leaf_is_ca, digital_signature);
        let bad_expected = bad_leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| {
                ExpectedKey::new([u8::try_from(index + 1).unwrap(); 32], leaf.spki)
            })
            .collect::<Vec<_>>();
        let bad_response = signed_response(
            &bad_shared,
            bad_leaves.iter().map(|leaf| leaf.der.as_slice()),
        );
        let bad_status = StatusSnapshot::for_test(
            now,
            60,
            bad_leaves
                .iter()
                .flat_map(|leaf| leaf.serials.iter())
                .chain(bad_root.serials.iter())
                .map(|serial| (serial.as_str(), CertificateStatus::Good)),
        );
        assert_eq!(
            validate_response(
                &prepared,
                prepared.body(),
                &bad_response,
                &bad_expected,
                &context,
                &RootBundle::for_test(7, vec![sha256(&bad_root.der)]),
                &bad_status,
                &mut |_| {},
            ),
            Err(expected_error)
        );
    }

    let (bad_root, bad_shared, bad_leaves) = certificate_fixture_with_eku(true, false, true);
    let bad_response = signed_response(
        &bad_shared,
        bad_leaves.iter().map(|leaf| leaf.der.as_slice()),
    );
    let bad_expected = bad_leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| ExpectedKey::new([u8::try_from(index + 1).unwrap(); 32], leaf.spki))
        .collect::<Vec<_>>();
    let bad_status = StatusSnapshot::for_test(
        now,
        60,
        bad_leaves
            .iter()
            .flat_map(|leaf| leaf.serials.iter())
            .chain(bad_root.serials.iter())
            .map(|serial| (serial.as_str(), CertificateStatus::Good)),
    );
    assert_eq!(
        validate_response(
            &prepared,
            prepared.body(),
            &bad_response,
            &bad_expected,
            &context,
            &RootBundle::for_test(7, vec![sha256(&bad_root.der)]),
            &bad_status,
            &mut |_| {},
        ),
        Err(ValidationError::AttestationExtendedKeyUsage)
    );
}
