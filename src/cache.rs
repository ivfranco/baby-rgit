use std::{convert::TryFrom, env, ffi::OsString, fs::FileType, io::{BufRead, Cursor}, mem, time::{SystemTime, SystemTimeError}};
use sha2::{Digest, Sha256};

use crate::Error;
use std::io::{self, Read, Write};

/// Name of the environment variable containing the path to the directory cache.
pub const DB_ENVIRONMENT: &str = "SHA_FILE_DIRECTORY";

/// Default value of [DB_ENVIRONMENT](DB_ENVIRONMENT).
pub const DEFAULT_DB_ENVIRONMENT: &str = ".dircache/objects";

const SHA256_OUTPUT_LEN: usize = 32;
const CACHE_SIGNATURE:u32 = 0x44495243	/* "DIRC" */;

/// Helper trait to read and write primitive number types.
pub trait ReadWriteLE: Sized {
    /// Read the number in little-endian order.
    fn read_le<R: Read>(reader: R) -> io::Result<Self>;

    /// Write the number in little-endian order.
    fn write_le<W: Write>(self, writer: W) -> io::Result<()>;
}

macro_rules! impl_read_write_le {
    ($ty: ty) => {
        impl ReadWriteLE for $ty {
            fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
                let mut buf = [0u8; mem::size_of::<$ty>()];
                reader.read_exact(&mut buf)?;
                Ok(Self::from_le_bytes(buf))
            }

            fn write_le<W: Write>(self, mut writer: W) -> io::Result<()> {
                writer.write_all(&self.to_le_bytes())
            }
        }
    }
}

impl_read_write_le!(u32);
impl_read_write_le!(u64);

fn digest_buffered<D: Digest, R: BufRead>(hasher: &mut D, mut reader: R) -> io::Result<()> {
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }

        hasher.update(buf);
    }

    Ok(())
}

struct CacheHeader {
    signature: u32,
    version: u32,
    entries: u32,
    // sha1 has been deprecated
    sha256: [u8; SHA256_OUTPUT_LEN],
}

impl CacheHeader {
    const fn size() -> usize {
        mem::size_of::<u32>() * 3 + SHA256_OUTPUT_LEN
    }

    fn read_and_verify<R: BufRead>(reader: &mut R, size: u64) -> Result<Self, Error> {
        // there's no mmap in safe Rust, wonder how different would the performance be
        let mut buf = [0u8; Self::size()];
        reader.read_exact(&mut buf)?;
        let mut cursor = Cursor::new(&buf);

        let signature = u32::read_le(&mut cursor)?;
        if signature != CACHE_SIGNATURE {
            return Err(Error::CorruptedHeader("bad signature"));
        }

        let version = u32::read_le(&mut cursor)?;
        if version != 1 {
            return Err(Error::CorruptedHeader("bad version"));
        }

        let entries = u32::read_le(&mut cursor)?;
        let mut sha256 = [0u8; SHA256_OUTPUT_LEN];
        cursor.read_exact(&mut sha256)?;

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        digest_buffered(&mut hasher, reader.take(size - buf.len() as u64))?;

        if hasher.finalize().as_slice() != sha256 {
            return Err(Error::CorruptedHeader("wrong sha256 signature"));
        }

        Ok(Self {
            signature,
            version,
            entries,
            sha256,
        })
    }
}

/// The lower 32 bits of times (creation or modification), only used to verify if the file changed
/// since last time.
#[derive(Clone, Copy)]
struct CacheTime {
    sec: u32,
    nsec: u32,
}

impl TryFrom<SystemTime> for CacheTime {
    type Error = SystemTimeError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        let duration = value.duration_since(SystemTime::UNIX_EPOCH)?;
        let sec = duration.as_secs() as u32;
        let nsec = duration.as_nanos() as u32;

        Ok(Self { sec, nsec })
    }
}

/// A lot of the entries in the original C implementation will be missing, device number / uid / gid
/// / inode as a concept doesn't exist on a few platforms supported by stable Rust, hopefully the
/// extra robustness of SHA256 over SHA1 would be sufficient for the purpose.
#[derive(Clone, Copy)]
struct FileStat {
    created: CacheTime,
    modified: CacheTime,
    file_type: FileType,
    file_size: u64,
}

struct CacheEntry {
    stat: FileStat,
    sha256: [u8; SHA256_OUTPUT_LEN],
    name: OsString,
}

impl CacheEntry {
    /// The size of a cache entry when serialized to the disk in the most obvious way.
    pub fn ce_size(&self) -> usize {
        mem::size_of::<FileStat>() +    /* file stats with default memory layout */ 
        SHA256_OUTPUT_LEN +             /* SHA256 */ 
        mem::size_of::<usize>() +       /* length of file name */
        self.name.len() +               /* file name */
        8                               /* why? */
    }
}

/// A directory cache.
pub struct DirCache;

impl DirCache {
    /// Initialize the cache information.
    pub fn read_cache() -> Result<Self, Error> {
        let dir = env::var_os(DB_ENVIRONMENT).unwrap_or_else(|| OsString::from(DEFAULT_DB_ENVIRONMENT));
        unimplemented!()
    }

    /// Return a statically allocated filename matching the sha1 signature.
    pub fn sha_file_name(&self, sha: &[u8; SHA256_OUTPUT_LEN]) -> OsString {
        unimplemented!()
    }
}