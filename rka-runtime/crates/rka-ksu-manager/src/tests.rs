use std::{cell::Cell, rc::Rc};

use super::*;

#[derive(Debug)]
struct Driver(Rc<Cell<u32>>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

struct FakeKernel {
    root: bool,
    inherited: bool,
    appid: Result<u32, ManagerAppIdError>,
    boot_ids: Vec<Vec<u8>>,
    calls: Vec<String>,
    drops: Rc<Cell<u32>>,
}

impl KernelProbe for FakeKernel {
    type Driver = Driver;

    fn is_root(&self) -> bool {
        self.root
    }

    fn boot_id(&mut self) -> Result<Vec<u8>, ManagerAppIdError> {
        self.calls.push("boot".to_owned());
        if self.boot_ids.is_empty() {
            Err(ManagerAppIdError::QueryFailed)
        } else {
            Ok(self.boot_ids.remove(0))
        }
    }

    fn scan_driver(
        &mut self,
        exact_target: &str,
    ) -> Result<Option<Self::Driver>, ManagerAppIdError> {
        self.calls.push(format!("scan:{exact_target}"));
        Ok(self.inherited.then(|| Driver(Rc::clone(&self.drops))))
    }

    fn acquire_driver(
        &mut self,
        request: InstallSupercall,
    ) -> Result<Self::Driver, ManagerAppIdError> {
        self.calls.push(format!(
            "acquire:{:08x}:{:08x}:{}",
            request.magic_1, request.magic_2, request.command
        ));
        Ok(Driver(Rc::clone(&self.drops)))
    }

    fn manager_appid(
        &mut self,
        _driver: &Self::Driver,
        ioctl: u32,
    ) -> Result<u32, ManagerAppIdError> {
        self.calls
            .push(format!("ioctl:{ioctl:08x}:{}", size_of::<u32>()));
        self.appid
            .as_ref()
            .copied()
            .map_err(|_| ManagerAppIdError::QueryFailed)
    }
}

fn fake(appid: Result<u32, ManagerAppIdError>) -> FakeKernel {
    FakeKernel {
        root: true,
        inherited: false,
        appid,
        boot_ids: vec![b"same".to_vec(), b"same".to_vec()],
        calls: Vec::new(),
        drops: Rc::new(Cell::new(0)),
    }
}

#[test]
fn absent_driver_uses_only_install_supercall_and_exact_ioctl() {
    let mut kernel = fake(Ok(10123));
    assert!(matches!(probe_with(&mut kernel), Ok(10123)));
    assert_eq!(
        kernel.calls,
        [
            "boot",
            "scan:anon_inode:[ksu_driver]",
            "acquire:deadbeef:cafebabe:0",
            "ioctl:80004b0a:4",
            "boot"
        ]
    );
    assert_eq!(kernel.drops.get(), 1);
    assert_ne!(INSTALL_SUPERCALL.magic_1, 0xfee1_dead);
    assert_ne!(INSTALL_SUPERCALL.magic_2, 0x2812_1969);
}

#[test]
fn inherited_exact_driver_skips_supercall_and_is_closed() {
    let mut kernel = fake(Ok(10073));
    kernel.inherited = true;
    assert!(matches!(probe_with(&mut kernel), Ok(10073)));
    assert!(!kernel.calls.iter().any(|call| call.starts_with("acquire:")));
    assert_eq!(kernel.drops.get(), 1);
}

#[test]
fn zero_error_nonroot_and_boot_drift_fail_typed() {
    let mut zero = fake(Ok(0));
    assert!(matches!(
        probe_with(&mut zero),
        Err(ManagerAppIdError::ZeroAppId)
    ));
    let mut error = fake(Err(ManagerAppIdError::QueryFailed));
    assert!(matches!(
        probe_with(&mut error),
        Err(ManagerAppIdError::QueryFailed)
    ));
    assert_eq!(error.calls.last().map(String::as_str), Some("boot"));
    assert_eq!(error.drops.get(), 1);
    let mut drift = fake(Ok(10123));
    drift.boot_ids[1] = b"changed".to_vec();
    assert!(matches!(
        probe_with(&mut drift),
        Err(ManagerAppIdError::BootIdDrift)
    ));
    let mut nonroot = fake(Ok(10123));
    nonroot.root = false;
    assert!(matches!(
        probe_with(&mut nonroot),
        Err(ManagerAppIdError::NotRoot)
    ));
}

#[test]
fn android_boundary_keeps_exact_u32_ioctl_buffer_and_raw_syscall() {
    let source = include_str!("platform.rs");
    assert!(source.contains("let mut command = 0_u32;"));
    assert!(source.contains("libc::SYS_reboot"));
    assert!(source.contains("OwnedFd::from_raw_fd(fd)"));
    assert!(!source.contains("LINUX_REBOOT_CMD"));
}
