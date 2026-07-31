#![allow(missing_docs, reason = "integration tests are behavior-named")]

use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rka_sidecar::donor::{DonorIngress, DonorIngressError};

#[test]
fn ingress_rejects_a_non_root_owned_socket_tree() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root();
    let sockets = root.join("run/sockets");
    fs::create_dir_all(&sockets)?;
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700))?;
    let path = sockets.join("donor-rka.sock");
    let stale = UnixListener::bind(&path)?;
    drop(stale);

    // When
    let result = DonorIngress::bind(&root);

    // Then
    assert!(matches!(result, Err(DonorIngressError::Path)));
    assert!(path.exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn ingress_refuses_to_replace_a_non_socket_path() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root();
    let sockets = root.join("run/sockets");
    fs::create_dir_all(&sockets)?;
    fs::set_permissions(&sockets, fs::Permissions::from_mode(0o700))?;
    fs::write(sockets.join("donor-rka.sock"), b"owner-data")?;

    // When
    let result = DonorIngress::bind(&root);

    // Then
    assert!(matches!(result, Err(DonorIngressError::Path)));
    assert_eq!(fs::read(sockets.join("donor-rka.sock"))?, b"owner-data");
    fs::remove_dir_all(root)?;
    Ok(())
}

fn unique_root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "rka-donor-ingress-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
