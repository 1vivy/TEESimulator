//! Strict startup consumption boundary for atomically published direct profiles.

use std::{
    env, fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use crate::{LifecycleRole, SidecarError};

mod loader;
mod receipt;

pub use receipt::{consume, probe};

const MAX_PROFILE_BYTES: u64 = 4096;
const PROFILE_NAME: &str = "profiles/direct.conf";

#[derive(Clone, Copy, Debug)]
pub(crate) struct DirectProfile {
    pub(crate) epoch: u64,
    pub(crate) endpoint: Ipv4Addr,
    pub(crate) listen_interface: Ipv4Addr,
    pub(crate) dial_mode: DialMode,
    pub(crate) peer_pin: [u8; 32],
}

type LoadedProfiles = Vec<(DirectProfile, Vec<u8>)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DonorProfileSource {
    Legacy,
    Indexed,
}

pub(crate) fn load_donor_profiles()
-> Result<(PathBuf, DonorProfileSource, LoadedProfiles), SidecarError> {
    loader::load_donor_profiles()
}

#[cfg(test)]
pub(crate) fn load_published_profiles(
    state_root: &Path,
    role: LifecycleRole,
    expected_epoch: u64,
) -> Result<LoadedProfiles, SidecarError> {
    loader::load_published_profiles(state_root, role, expected_epoch)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DialMode {
    CandidateDials,
    DonorDials,
}

impl DirectProfile {
    fn parse(
        raw: &[u8],
        expected_role: LifecycleRole,
        expected_epoch: u64,
    ) -> Result<Self, SidecarError> {
        let text = std::str::from_utf8(raw).map_err(|_| SidecarError::RuntimeContext)?;
        let lines = text
            .strip_suffix('\n')
            .ok_or(SidecarError::RuntimeContext)?
            .split('\n')
            .collect::<Vec<_>>();
        let (version, role, epoch, endpoint, listen_interface, dial_mode, peer_pin, transport) =
            match lines.as_slice() {
                [version, role, epoch, endpoint, peer_pin, transport] => (
                    *version,
                    *role,
                    *epoch,
                    *endpoint,
                    *endpoint,
                    DialMode::CandidateDials,
                    *peer_pin,
                    *transport,
                ),
                [
                    version,
                    role,
                    epoch,
                    mode,
                    endpoint,
                    listen,
                    peer_pin,
                    transport,
                ] => (
                    *version,
                    *role,
                    *epoch,
                    *endpoint,
                    *listen,
                    parse_mode(mode)?,
                    *peer_pin,
                    *transport,
                ),
                _ => return Err(SidecarError::RuntimeContext),
            };
        if role != expected_role.profile_line()
            || transport != "transport=DIRECT"
            || (version == "version=1" && dial_mode != DialMode::CandidateDials)
            || (version != "version=1" && version != "version=2")
        {
            return Err(SidecarError::RuntimeContext);
        }
        let parsed_epoch = epoch
            .strip_prefix("profile_epoch=")
            .ok_or(SidecarError::RuntimeContext)?
            .parse::<u64>()
            .map_err(|_| SidecarError::RuntimeContext)?;
        if parsed_epoch != expected_epoch {
            return Err(SidecarError::RuntimeContext);
        }
        let parsed_endpoint = endpoint
            .strip_prefix(if version == "version=1" {
                "peer_endpoint="
            } else {
                "dial_endpoint="
            })
            .ok_or(SidecarError::RuntimeContext)?
            .parse::<Ipv4Addr>()
            .map_err(|_| SidecarError::RuntimeContext)?;
        let parsed_listen_interface = listen_interface
            .strip_prefix(if version == "version=1" {
                "peer_endpoint="
            } else {
                "listen_interface="
            })
            .ok_or(SidecarError::RuntimeContext)?
            .parse::<Ipv4Addr>()
            .map_err(|_| SidecarError::RuntimeContext)?;
        if version == "version=2"
            && (!global_ipv4(parsed_endpoint) || !global_ipv4(parsed_listen_interface))
        {
            return Err(SidecarError::RuntimeContext);
        }
        let parsed_pin = decode_pin(
            peer_pin
                .strip_prefix("peer_spki_sha256=")
                .ok_or(SidecarError::RuntimeContext)?,
        )?;
        Ok(Self {
            epoch: parsed_epoch,
            endpoint: parsed_endpoint,
            listen_interface: parsed_listen_interface,
            dial_mode,
            peer_pin: parsed_pin,
        })
    }
}

pub(crate) fn load(role: LifecycleRole) -> Result<(PathBuf, DirectProfile, Vec<u8>), SidecarError> {
    let state_root =
        PathBuf::from(env::var_os("RKA_STATE_ROOT").ok_or(SidecarError::RuntimeContext)?);
    let profile_path =
        PathBuf::from(env::var_os("RKA_PROFILE_PATH").ok_or(SidecarError::RuntimeContext)?);
    if profile_path != state_root.join(PROFILE_NAME) {
        return Err(SidecarError::RuntimeContext);
    }
    let expected_epoch = env::var("RKA_EXPECTED_PROFILE_EPOCH")
        .map_err(|_| SidecarError::RuntimeContext)?
        .parse::<u64>()
        .map_err(|_| SidecarError::RuntimeContext)?;
    let (profile, raw) = load_from((&state_root, &profile_path, role), expected_epoch)?;
    Ok((state_root, profile, raw))
}

pub(crate) fn load_from(
    context: (&Path, &Path, LifecycleRole),
    expected_epoch: u64,
) -> Result<(DirectProfile, Vec<u8>), SidecarError> {
    let (state_root, profile_path, role) = context;
    if profile_path != state_root.join(PROFILE_NAME) {
        return Err(SidecarError::RuntimeContext);
    }
    load_profile_file((state_root, profile_path, role), expected_epoch)
}

fn load_profile_file(
    context: (&Path, &Path, LifecycleRole),
    expected_epoch: u64,
) -> Result<(DirectProfile, Vec<u8>), SidecarError> {
    let (state_root, profile_path, role) = context;
    let root_metadata =
        fs::symlink_metadata(state_root).map_err(|_| SidecarError::RuntimeContext)?;
    let profile_metadata =
        fs::symlink_metadata(profile_path).map_err(|_| SidecarError::RuntimeContext)?;
    if !root_metadata.file_type().is_dir()
        || !profile_metadata.file_type().is_file()
        || profile_metadata.len() > MAX_PROFILE_BYTES
    {
        return Err(SidecarError::RuntimeContext);
    }
    let raw = fs::read(profile_path).map_err(|_| SidecarError::RuntimeContext)?;
    let profile = DirectProfile::parse(&raw, role, expected_epoch)?;
    Ok((profile, raw))
}

#[doc(hidden)]
pub fn donor_dials(role: LifecycleRole) -> Result<bool, SidecarError> {
    load(role).map(|(_, profile, _)| profile.dial_mode == DialMode::DonorDials)
}

fn parse_mode(line: &str) -> Result<DialMode, SidecarError> {
    match line {
        "dial_mode=CANDIDATE_DIALS" => Ok(DialMode::CandidateDials),
        "dial_mode=DONOR_DIALS" => Ok(DialMode::DonorDials),
        _ => Err(SidecarError::RuntimeContext),
    }
}

const fn global_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
}

fn decode_pin(encoded: &str) -> Result<[u8; 32], SidecarError> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SidecarError::RuntimeContext);
    }
    let mut decoded = [0_u8; 32];
    for (destination, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| SidecarError::RuntimeContext)?;
        *destination = u8::from_str_radix(text, 16).map_err(|_| SidecarError::RuntimeContext)?;
    }
    Ok(decoded)
}
