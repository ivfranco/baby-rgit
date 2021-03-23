#![deny(missing_docs)]

//! A Rust clone of the very first commit of git.

/// A directory cache.
pub mod cache;

use std::fmt::{Debug, Display};
use thiserror::Error;

/// The error type for directory database operations.
#[derive(Error)]
pub enum Error {
    /// IO errors from the underlying file system.
    #[error("{0}")]
    FS(#[from] std::io::Error),

    /// Header file corrupted.
    #[error("Header corrupted: {0}")]
    CorruptedHeader(&'static str),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}
