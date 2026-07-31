use crate::{Endpoint, TransportKind};

#[test]
fn endpoint_profile_selects_exact_lan_endpoint_and_pin() -> Result<(), Box<dyn std::error::Error>> {
    let lan = Endpoint::parse("192.168.50.8", 8443)?;
    let tailscale = Endpoint::parse("100.88.0.8", 8443)?;

    assert_eq!(lan.host(), "192.168.50.8");
    assert_eq!(tailscale.host(), "100.88.0.8");
    assert_eq!(lan.port(), 8443);
    assert!(Endpoint::parse("192.168.050.8", 8443).is_err());
    assert!(Endpoint::parse("DONOR.tailnet.ts.net", 8443).is_err());
    Ok(())
}

#[test]
fn endpoint_profile_usb_cannot_satisfy_direct() {
    assert!(TransportKind::DirectPinnedTls.satisfies_direct());
    assert!(!TransportKind::DiagnosticUsbRelay.satisfies_direct());
}
