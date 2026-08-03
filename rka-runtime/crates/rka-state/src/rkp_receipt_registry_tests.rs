use super::*;
use rustix::{
    fs::{AtFlags, CWD, Gid, Uid, chownat},
    process::geteuid,
};
use std::{
    fs::Permissions,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

fn anchor() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let anchor = std::env::temp_dir().join(format!(
        "rka-registry-security-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&anchor).unwrap();
    anchor
}

fn create_parents(anchor: &Path) {
    let mut current = anchor.to_path_buf();
    for component in std::iter::once(SYSTEM_DATA_COMPONENT).chain(PRIVATE_COMPONENTS) {
        current.push(component);
        std::fs::create_dir(&current).unwrap();
        std::fs::set_permissions(&current, Permissions::from_mode(DIRECTORY_MODE)).unwrap();
    }
}

#[test]
fn android_data_ancestor_may_use_the_platform_traversal_mode() {
    let anchor = anchor();
    create_parents(&anchor);
    std::fs::set_permissions(anchor.join("data"), Permissions::from_mode(0o771)).unwrap();

    let registry = ValidatedReceiptRegistry::for_test(&anchor).unwrap();

    drop(registry);
    std::fs::remove_dir_all(anchor).unwrap();
}

#[test]
fn only_approved_relative_path_is_opened() {
    let anchor = anchor();
    std::fs::create_dir_all(anchor.join("data/adb/teesimulator-rka/wrong")).unwrap();
    assert!(ValidatedReceiptRegistry::for_test(&anchor).is_err());
    std::fs::remove_dir_all(anchor).unwrap();
}

#[test]
fn symlink_ancestor_and_leaf_are_rejected() {
    let ancestor_anchor = anchor();
    std::fs::create_dir(ancestor_anchor.join("data")).unwrap();
    std::fs::set_permissions(
        ancestor_anchor.join("data"),
        Permissions::from_mode(DIRECTORY_MODE),
    )
    .unwrap();
    let outside = anchor();
    symlink(&outside, ancestor_anchor.join("data/adb")).unwrap();
    assert!(ValidatedReceiptRegistry::for_test(&ancestor_anchor).is_err());
    std::fs::remove_dir_all(ancestor_anchor).unwrap();
    std::fs::remove_dir_all(outside).unwrap();

    let leaf_anchor = anchor();
    create_parents(&leaf_anchor);
    let outside = anchor();
    symlink(
        &outside,
        leaf_anchor
            .join("data/adb/teesimulator-rka/journal")
            .join(LEAF),
    )
    .unwrap();
    assert!(ValidatedReceiptRegistry::for_test(&leaf_anchor).is_err());
    std::fs::remove_dir_all(leaf_anchor).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
}

#[test]
fn weak_ancestor_and_leaf_modes_are_rejected() {
    let ancestor = anchor();
    create_parents(&ancestor);
    std::fs::set_permissions(ancestor.join("data/adb"), Permissions::from_mode(0o750)).unwrap();
    assert!(ValidatedReceiptRegistry::for_test(&ancestor).is_err());
    std::fs::remove_dir_all(ancestor).unwrap();

    let leaf = anchor();
    create_parents(&leaf);
    let registry = ValidatedReceiptRegistry::for_test(&leaf).unwrap();
    drop(registry);
    std::fs::set_permissions(
        leaf.join("data/adb/teesimulator-rka/journal").join(LEAF),
        Permissions::from_mode(0o750),
    )
    .unwrap();
    assert!(ValidatedReceiptRegistry::for_test(&leaf).is_err());
    std::fs::remove_dir_all(leaf).unwrap();
}

#[test]
fn non_root_owned_ancestor_is_rejected_when_chown_is_available() {
    if !geteuid().is_root() {
        return;
    }
    let anchor = anchor();
    create_parents(&anchor);
    chownat(
        CWD,
        anchor.join("data/adb"),
        Some(Uid::from_raw(1)),
        Some(Gid::from_raw(1)),
        AtFlags::empty(),
    )
    .unwrap();
    assert!(ValidatedReceiptRegistry::for_test(&anchor).is_err());
    std::fs::remove_dir_all(anchor).unwrap();
}
