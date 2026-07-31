//! Read-only access to the kernel-held `KernelSU` manager application id.

#![deny(unsafe_code)]

use thiserror::Error;

#[cfg(all(
    target_os = "android",
    feature = "android-syscall-skip-miri",
    not(miri)
))]
mod platform;

#[cfg(any(test, target_os = "android"))]
const DRIVER_TARGET: &str = "anon_inode:[ksu_driver]";
#[cfg(any(test, target_os = "android"))]
const INSTALL_SUPERCALL: InstallSupercall = InstallSupercall {
    magic_1: 0xDEAD_BEEF,
    magic_2: 0xCAFE_BABE,
    command: 0,
};
#[cfg(any(test, target_os = "android"))]
const GET_MANAGER_APPID: u32 = 0x8000_4b0a;

/// Stable, non-identifying failures exposed by the manager-appid CLI.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManagerAppIdError {
    /// The command is not running as root.
    #[error("not root")]
    NotRoot,
    /// No exact `KernelSU` driver descriptor could be opened.
    #[error("driver unavailable")]
    DriverUnavailable,
    /// The read-only manager query failed.
    #[error("query failed")]
    QueryFailed,
    /// The kernel returned the reserved zero appid.
    #[error("zero appid")]
    ZeroAppId,
    /// The boot identity changed during the read-only probe.
    #[error("boot identity changed")]
    BootIdDrift,
    /// The host is not Android.
    #[error("unsupported platform")]
    UnsupportedPlatform,
}

impl ManagerAppIdError {
    /// Returns a fixed status token with no package or signer identifier.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        match self {
            Self::NotRoot => "not_root",
            Self::DriverUnavailable => "driver_unavailable",
            Self::QueryFailed => "query_failed",
            Self::ZeroAppId => "zero_appid",
            Self::BootIdDrift => "boot_id_drift",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}

#[cfg(any(test, target_os = "android"))]
#[derive(Clone, Copy)]
struct InstallSupercall {
    magic_1: u32,
    magic_2: u32,
    command: u32,
}

#[cfg(any(test, target_os = "android"))]
trait KernelProbe {
    type Driver;

    fn is_root(&self) -> bool;
    fn boot_id(&mut self) -> Result<Vec<u8>, ManagerAppIdError>;
    fn scan_driver(
        &mut self,
        exact_target: &str,
    ) -> Result<Option<Self::Driver>, ManagerAppIdError>;
    fn acquire_driver(
        &mut self,
        request: InstallSupercall,
    ) -> Result<Self::Driver, ManagerAppIdError>;
    fn manager_appid(
        &mut self,
        driver: &Self::Driver,
        ioctl: u32,
    ) -> Result<u32, ManagerAppIdError>;
}

#[cfg(any(test, target_os = "android"))]
fn probe_with(api: &mut impl KernelProbe) -> Result<u32, ManagerAppIdError> {
    if !api.is_root() {
        return Err(ManagerAppIdError::NotRoot);
    }
    let before = api.boot_id()?;
    let result = (|| {
        let driver = match api.scan_driver(DRIVER_TARGET)? {
            Some(driver) => driver,
            None => api.acquire_driver(INSTALL_SUPERCALL)?,
        };
        api.manager_appid(&driver, GET_MANAGER_APPID)
    })();
    let after = api.boot_id()?;
    if before != after {
        return Err(ManagerAppIdError::BootIdDrift);
    }
    match result? {
        0 => Err(ManagerAppIdError::ZeroAppId),
        appid => Ok(appid),
    }
}

/// Queries the authorized KernelSU manager appid without changing kernel state.
///
/// # Errors
/// Returns a typed failure if root, driver, ioctl, or boot-continuity checks fail.
#[cfg(all(
    target_os = "android",
    feature = "android-syscall-skip-miri",
    not(miri)
))]
pub fn probe_manager_appid() -> Result<u32, ManagerAppIdError> {
    probe_with(&mut platform::AndroidKernelProbe)
}

/// Reports that the `KernelSU` supercall ABI is unavailable off Android.
///
/// # Errors
/// Always returns [`ManagerAppIdError::UnsupportedPlatform`].
#[cfg(not(all(
    target_os = "android",
    feature = "android-syscall-skip-miri",
    not(miri)
)))]
pub const fn probe_manager_appid() -> Result<u32, ManagerAppIdError> {
    Err(ManagerAppIdError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests;
