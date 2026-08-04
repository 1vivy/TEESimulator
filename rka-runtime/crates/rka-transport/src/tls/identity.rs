use rka_protocol::sha256;
use rustls::pki_types::CertificateDer;
use webpki::anchor_from_trusted_cert;

use crate::TlsError;

/// Parses a certificate with rustls-webpki and hashes its exact SPKI DER.
pub fn peer_spki_hash(certificate: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
    let anchor = anchor_from_trusted_cert(certificate).map_err(|_| TlsError::Certificate)?;
    let value = anchor.subject_public_key_info.as_ref();
    let mut spki = Vec::with_capacity(value.len().saturating_add(4));
    spki.push(0x30);
    encode_der_length(&mut spki, value.len())?;
    spki.extend_from_slice(value);
    Ok(sha256(&spki))
}

fn encode_der_length(output: &mut Vec<u8>, length: usize) -> Result<(), TlsError> {
    match length {
        0..=127 => output.push(u8::try_from(length).map_err(|_| TlsError::Certificate)?),
        128..=255 => {
            output.push(0x81);
            output.push(u8::try_from(length).map_err(|_| TlsError::Certificate)?);
        }
        256..=65_535 => {
            output.push(0x82);
            output.extend_from_slice(
                &u16::try_from(length)
                    .map_err(|_| TlsError::Certificate)?
                    .to_be_bytes(),
            );
        }
        _ => return Err(TlsError::Certificate),
    }
    Ok(())
}
