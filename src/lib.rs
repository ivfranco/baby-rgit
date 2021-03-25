#![deny(missing_docs)]

//! A Rust clone of the very first commit of git.

/// A directory cache.
pub mod cache;

/// Command line utilities.
pub mod cmd;

use std::fmt::{Debug, Display};

/// The error type for directory database operations.
#[derive(thiserror::Error)]
pub enum Error {
    /// IO errors from the underlying file system.
    #[error("File system: {0}")]
    FS(#[from] std::io::Error),

    /// Index file corrupted.
    #[error("Header corrupted: {0}")]
    CorruptedIndex(&'static str),

    /// Cache entry corrupted.
    #[error("Entry corrupted: {0}")]
    CorruptedEntry(&'static str),

    /// Bincode (de)serialize error.
    #[error("Bincode: {0}")]
    Bincode(#[from] bincode::Error),

    /// System time before Unix epoch.
    #[error("System time before UNIX epoch")]
    Time(#[from] std::time::SystemTimeError),

    /// Object file corrupted.
    #[error("Object file corrupted: {0}")]
    CorruptedObject(&'static str),

    /// Integer overflow errors.
    #[error("Integer overflow: {0}")]
    Overflow(&'static str),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}
