//! Static material-boundary and redaction regression tests.

use std::error::Error;

use rka_sidecar::bridge::{BridgeMessage, PublicBytes, RequestId};

#[test]
fn bridge_material_debug_never_contains_payload_body() -> Result<(), Box<dyn Error>> {
    let payload = b"unique-public-body-marker";
    let message = BridgeMessage::PublicKeyRequest(
        RequestId::new(1),
        PublicBytes::bounded(payload, 16, 64)?,
        1,
    );
    let rendered = format!("{message:?}");
    assert!(!rendered.contains("unique-public-body-marker"));
    assert!(!rendered.contains("private"));
    Ok(())
}

#[test]
fn bridge_material_source_has_no_generic_or_forbidden_serializer() {
    let source = [
        include_str!("../src/bridge/mod.rs"),
        include_str!("../src/bridge/model.rs"),
        include_str!("../src/bridge/codec.rs"),
        include_str!("../src/bridge/decode_body.rs"),
        include_str!("../src/bridge/identity.rs"),
        include_str!("../src/bridge/trusted_record.rs"),
        include_str!("../src/bridge/runtime.rs"),
        include_str!("../src/bridge/executor_state.rs"),
        include_str!("../src/bridge/deadline.rs"),
        include_str!("../src/bridge/socket.rs"),
    ]
    .concat();
    for forbidden in [
        "serde_json",
        "unsafe {",
        "Binder",
        "Parcel",
        "private_key",
        "key_blob",
        "transport_secret",
        "unwrap(",
        "expect(",
        "panic!(",
        "todo!(",
        "unimplemented!(",
        "FnOnce",
        "thread::spawn",
        ".join()",
        "execute_with_deadline",
        "read_frame_with_timeout",
        "write_frame_with_timeout",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden source token {forbidden}"
        );
    }
    for required in [
        "write(&self.event",
        "shutdown(stream, Shutdown::Both)",
        "checked_duration_since(Instant::now())",
        "socket_error(&descriptor)",
    ] {
        assert!(
            source.contains(required),
            "required deadline invariant {required}"
        );
    }
}
