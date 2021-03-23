#![deny(missing_docs)]

//! A Rust clone of the very first commit of git.

/// A directory cache.
pub mod cache;

use std::fmt::{Debug, Display};
use std::io::{self, Read, Write};

/// The error type for directory database operations.
#[derive(thiserror::Error)]
pub enum Error {
    /// IO errors from the underlying file system.
    #[error("{0}")]
    FS(#[from] std::io::Error),

    /// Header file corrupted.
    #[error("Header corrupted: {0}")]
    CorruptedHeader(&'static str),

    /// Cache entry corrupted.
    #[error("Entry corrupted: {0}")]
    CorruptedEntry(&'static str),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

/// Helper trait to read and write primitive number types.
pub(crate) trait ReadWriteLE: Sized {
    /// Read the number in little-endian order.
    fn read_le<R: Read>(reader: R) -> io::Result<Self>;

    /// Write the number in little-endian order.
    fn write_le<W: Write>(self, writer: W) -> io::Result<()>;
}

macro_rules! impl_read_write_le {
    ($ty: ty) => {
        impl ReadWriteLE for $ty {
            fn read_le<R: std::io::Read>(mut reader: R) -> io::Result<Self> {
                use std::mem;

                let mut buf = [0u8; mem::size_of::<$ty>()];
                reader.read_exact(&mut buf)?;
                Ok(Self::from_le_bytes(buf))
            }

            fn write_le<W: std::io::Write>(self, mut writer: W) -> io::Result<()> {
                writer.write_all(&self.to_le_bytes())
            }
        }
    };
}

impl_read_write_le!(u32);
impl_read_write_le!(u64);
