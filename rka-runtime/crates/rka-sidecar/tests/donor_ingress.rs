#![allow(missing_docs, reason = "integration tests are behavior-named")]

use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use rka_sidecar::donor::{DonorIngress, DonorIngressError, DonorRuntime};

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

#[test]
fn ingress_rejects_symlinked_state_root_ancestor() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root();
    let target = unique_root();
    fs::create_dir_all(&target)?;
    symlink(&target, &root)?;
    let metadata = fs::metadata(&target)?;

    // When
    let result = DonorIngress::bind_for_owner_policy(&root, metadata.uid(), metadata.gid());

    // Then
    assert!(matches!(result, Err(DonorIngressError::Path)));
    assert!(!target.join("run/sockets/donor-rka.sock").exists());
    fs::remove_file(root)?;
    fs::remove_dir_all(target)?;
    Ok(())
}

#[test]
fn ingress_rejects_symlinked_run_component() -> Result<(), Box<dyn std::error::Error>> {
    reject_symlink_component("run")
}

#[test]
fn ingress_rejects_symlinked_sockets_component() -> Result<(), Box<dyn std::error::Error>> {
    reject_symlink_component("run/sockets")
}

#[test]
fn slow_drip_cannot_reset_the_absolute_frame_deadline() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let (mut writer, reader) = UnixStream::pair()?;
    let sender = thread::spawn(move || {
        for byte in 1_u32.to_be_bytes().into_iter().chain([0x80]) {
            if writer.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(12));
        }
    });

    // When
    let result = DonorIngress::read_frame_with_budget(reader, Duration::from_millis(35));

    // Then
    assert!(matches!(result, Err(DonorIngressError::Io)));
    sender.join().map_err(|_| "slow-drip sender panicked")?;
    Ok(())
}

#[test]
fn malformed_uds_frame_reaches_runtime_rejection() -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_system_root();
    fs::create_dir_all(&root)?;
    let metadata = fs::metadata(&root)?;
    let ingress = DonorIngress::bind_for_owner_policy(&root, metadata.uid(), metadata.gid())?;
    let mut client = UnixStream::connect(ingress.path())?;
    client.write_all(&1_u32.to_be_bytes())?;
    client.write_all(&[0x80])?;
    let mut runtime = DonorRuntime::new(root.join("unused-broker.sock").as_path());

    // When
    let result = ingress.serve_once_for_peer_policy(&mut runtime, metadata.uid(), metadata.gid());

    // Then
    assert!(matches!(result, Err(DonorIngressError::Runtime)));
    drop(client);
    drop(ingress);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn unique_system_root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    PathBuf::from("/tmp").join(format!(
        "rka-donor-ingress-system-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn unique_root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "rka-donor-ingress-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn reject_symlink_component(component: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Given
    let root = unique_root();
    let target = unique_root();
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&target)?;
    let link = root.join(component);
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    symlink(&target, &link)?;
    let metadata = fs::metadata(&root)?;

    // When
    let result = DonorIngress::bind_for_owner_policy(&root, metadata.uid(), metadata.gid());

    // Then
    assert!(matches!(result, Err(DonorIngressError::Path)));
    assert!(!target.join("donor-rka.sock").exists());
    fs::remove_dir_all(root)?;
    fs::remove_dir_all(target)?;
    Ok(())
}
