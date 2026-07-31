//! Android-only raw KernelSU ABI wrapper.

#![allow(
    unsafe_code,
    reason = "the pinned KernelSU supercall and ioctl ABIs have no safe libc API"
)]

use std::{
    fs,
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
};

use crate::{InstallSupercall, KernelProbe, ManagerAppIdError};

pub(crate) struct AndroidKernelProbe;

impl KernelProbe for AndroidKernelProbe {
    type Driver = OwnedFd;

    fn is_root(&self) -> bool {
        rustix::process::geteuid().is_root()
    }

    fn boot_id(&mut self) -> Result<Vec<u8>, ManagerAppIdError> {
        fs::read("/proc/sys/kernel/random/boot_id").map_err(|_| ManagerAppIdError::QueryFailed)
    }

    fn scan_driver(
        &mut self,
        exact_target: &str,
    ) -> Result<Option<Self::Driver>, ManagerAppIdError> {
        let entries =
            fs::read_dir("/proc/self/fd").map_err(|_| ManagerAppIdError::DriverUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| ManagerAppIdError::DriverUnavailable)?;
            let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let target =
                fs::read_link(entry.path()).map_err(|_| ManagerAppIdError::DriverUnavailable)?;
            if target.as_os_str() == exact_target {
                // SAFETY: [Category 8 — FFI boundary] `/proc/self/fd/<fd>` resolved in this
                // single-threaded CLI to the exact live KernelSU anon inode immediately above;
                // ownership intentionally closes that inherited descriptor after the one query.
                return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
            }
        }
        Ok(None)
    }

    fn acquire_driver(
        &mut self,
        request: InstallSupercall,
    ) -> Result<Self::Driver, ManagerAppIdError> {
        let mut fd = -1_i32;
        // SAFETY: [Category 8 — FFI boundary] the exact pinned KernelSU reboot-hook tuple
        // treats arg4 as a writable `int *`; `fd` is initialized, aligned, live for the call,
        // and the normal reboot tuple is unrepresentable at the typed caller.
        unsafe {
            libc::syscall(
                libc::SYS_reboot,
                request.magic_1,
                request.magic_2,
                request.command,
                &raw mut fd,
            )
        };
        if fd < 0 {
            return Err(ManagerAppIdError::DriverUnavailable);
        }
        // SAFETY: [Category 8 — FFI boundary] the KernelSU hook returned a newly installed,
        // process-owned descriptor in `fd`; `OwnedFd` provides the single close on all paths.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn manager_appid(
        &mut self,
        driver: &Self::Driver,
        ioctl: u32,
    ) -> Result<u32, ManagerAppIdError> {
        let mut command = 0_u32;
        // SAFETY: [Category 8 — FFI boundary] the pinned ioctl is read-only and writes exactly
        // one aligned `u32` to the live `command` object; `driver` owns an exact KSU descriptor.
        let request = i32::from_ne_bytes(ioctl.to_ne_bytes());
        let result = unsafe { libc::ioctl(driver.as_raw_fd(), request, &raw mut command) };
        if result < 0 {
            Err(ManagerAppIdError::QueryFailed)
        } else {
            Ok(command)
        }
    }
}
