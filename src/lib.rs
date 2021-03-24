#![deny(missing_docs)]

//! A Rust clone of the very first commit of git.

/// A directory cache.
pub mod cache;

use std::fmt::{Debug, Display};

/// The error type for directory database operations.
#[derive(thiserror::Error)]
pub enum Error {
    /// IO errors from the underlying file system.
    #[error("File system: {0}")]
    FS(#[from] std::io::Error),

    /// Header file corrupted.
    #[error("Header corrupted: {0}")]
    CorruptedHeader(&'static str),

    /// Cache entry corrupted.
    #[error("Entry corrupted: {0}")]
    CorruptedEntry(&'static str),

    /// Bincode (de)serialize error.
    #[error("Bincode: {0}")]
    Bincode(#[from] bincode::Error),

    /// System time before Unix epoch.
    #[error("System time before UNIX epoch")]
    Time(#[from] std::time::SystemTimeError),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    #[test]
    fn compatible_platform() {
        // so all casts in the library is safe
        assert!(mem::size_of::<u32>() <= mem::size_of::<usize>());
        assert!(mem::size_of::<usize>() <= mem::size_of::<u64>());
    }
}
