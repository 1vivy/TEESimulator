use zeroize::Zeroizing;

use crate::StateError;

/// Explicit boundary for persistent secret material.
pub trait SensitiveStateStore {
    /// Atomically replaces secret bytes without accepting an ordinary slice.
    fn replace_sensitive(&self, key: &[u8], value: &Zeroizing<Vec<u8>>) -> Result<(), StateError>;
}
