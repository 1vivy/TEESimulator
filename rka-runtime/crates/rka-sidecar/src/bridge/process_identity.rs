use super::BridgeError;

pub(super) fn parse_start_time(stat: &[u8]) -> Result<u64, BridgeError> {
    let stat = std::str::from_utf8(stat).map_err(|_| BridgeError::PeerIdentity)?;
    let close = stat.rfind(')').ok_or(BridgeError::PeerIdentity)?;
    let fields = stat
        .get(close.checked_add(2).ok_or(BridgeError::PeerIdentity)?..)
        .ok_or(BridgeError::PeerIdentity)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or(BridgeError::PeerIdentity)?
        .parse::<u64>()
        .map_err(|_| BridgeError::PeerIdentity)
}

pub(super) fn parse_cmdline(bytes: &[u8]) -> Result<Vec<String>, BridgeError> {
    if bytes.is_empty() || bytes.last().copied() != Some(0) {
        return Err(BridgeError::PeerIdentity);
    }
    let mut values = Vec::new();
    let content = bytes
        .get(..bytes.len().saturating_sub(1))
        .ok_or(BridgeError::PeerIdentity)?;
    for value in content.split(|byte| *byte == 0) {
        if value.is_empty() {
            return Err(BridgeError::PeerIdentity);
        }
        values.push(
            std::str::from_utf8(value)
                .map_err(|_| BridgeError::PeerIdentity)?
                .to_owned(),
        );
    }
    if values.is_empty() {
        return Err(BridgeError::PeerIdentity);
    }
    Ok(values)
}
