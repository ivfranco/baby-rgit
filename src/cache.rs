use bitflags::bitflags;
use sha2::{Digest, Sha256};
use std::{
    convert::TryFrom,
    env,
    fs::{self, File, FileType},
    io::{BufRead, BufReader, Cursor, Seek, SeekFrom},
    mem,
    path::Path,
    time::{SystemTime, SystemTimeError},
};

use crate::{Error, ReadWriteLE};
use std::io::{self, Read};

/// Name of the environment variable containing the path to the directory cache.
pub const DB_ENVIRONMENT: &str = "SHA_FILE_DIRECTORY";

/// Default value of [DB_ENVIRONMENT](DB_ENVIRONMENT).
pub const DEFAULT_DB_ENVIRONMENT: &str = ".dircache/objects";

const SHA256_OUTPUT_LEN: usize = 32;
const CACHE_SIGNATURE: u32 = u32::from_be_bytes(*b"DIRC");
const CACHE_VERSION: u32 = 1;

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
    entries: usize,
    // sha1 has been deprecated
    sha256: [u8; SHA256_OUTPUT_LEN],
}

impl CacheHeader {
    const fn on_disk_size_without_sha() -> usize {
        mem::size_of::<u32>() * 3
    }

    const fn on_disk_size() -> usize {
        Self::on_disk_size() + SHA256_OUTPUT_LEN
    }

    fn read_and_verify<R: BufRead>(reader: &mut R, size: u64) -> Result<Self, Error> {
        // there's no mmap in safe Rust, we cannot use it anyway as Rust does not guarantee memory
        // layout of structs, wonder how different would the performance be
        let mut buf = [0u8; Self::on_disk_size_without_sha()];
        reader.read_exact(&mut buf)?;
        let mut cursor = Cursor::new(&buf);

        let signature = u32::read_le(&mut cursor)?;
        if signature != CACHE_SIGNATURE {
            return Err(Error::CorruptedHeader("bad signature"));
        }

        let version = u32::read_le(&mut cursor)?;
        if version != CACHE_VERSION {
            return Err(Error::CorruptedHeader("bad version"));
        }

        let entries = u32::read_le(&mut cursor)? as usize;

        let mut sha256 = [0u8; SHA256_OUTPUT_LEN];
        reader.read_exact(&mut sha256)?;

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        digest_buffered(&mut hasher, reader.take(size - Self::on_disk_size() as u64))?;

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

impl CacheTime {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let sec = u32::read_le(&mut *reader)?;
        let nsec = u32::read_le(&mut *reader)?;
        Ok(Self { sec, nsec })
    }
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

bitflags! {
    /// There's only 3 bits of reliably available information from std::io::FileType:
    /// - FileType::is_dir
    /// - FileType::is_file
    /// - FileType::is_symlink
    #[repr(transparent)] /* make sure it has the same size as a u32 */
    struct FileMode: u32 {
        const IS_DIR        = 0b0001;
        const IS_FILE       = 0b0010;
        const IS_SYMLINK    = 0b0100;
    }
}

impl FileMode {
    fn new(file_type: FileType) -> Self {
        let mut flags = Self::empty();
        if file_type.is_dir() {
            flags.insert(Self::IS_DIR);
        }
        if file_type.is_file() {
            flags.insert(Self::IS_FILE);
        }
        if file_type.is_symlink() {
            flags.insert(Self::IS_SYMLINK);
        }

        flags
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let bits = u32::read_le(reader)?;
        Self::from_bits(bits).ok_or(Error::CorruptedEntry("unknown file mode"))
    }
}

/// A lot of the entries in the original C implementation will be missing, device number / uid / gid
/// / inode as a concept doesn't exist on a few platforms supported by stable Rust, hopefully the
/// extra robustness of SHA256 over SHA1 would be sufficient for the purpose.
#[derive(Clone, Copy)]
struct FileStats {
    created: CacheTime,
    modified: CacheTime,
    mode: FileMode,
    size: u64,
}

impl FileStats {
    const fn on_disk_size() -> usize {
        mem::size_of::<u32>() * 2 * 2 + mem::size_of::<FileMode>() + mem::size_of::<u64>()
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let created = CacheTime::read(&mut *reader)?;
        let modified = CacheTime::read(&mut *reader)?;
        let mode = FileMode::read(&mut *reader)?;
        let size = u64::read_le(&mut *reader)?;

        Ok(Self {
            created,
            modified,
            mode,
            size,
        })
    }
}

struct CacheEntry {
    stats: FileStats,
    sha256: [u8; SHA256_OUTPUT_LEN],
    name: String,
}

impl CacheEntry {
    fn skip<R: Read + Seek>(reader: &mut R) -> Result<u64, Error> {
        let _ = FileStats::read(&mut *reader)?;
        reader.seek(SeekFrom::Current(SHA256_OUTPUT_LEN as i64))?;
        let name_len = u32::read_le(&mut *reader)?;
        reader.seek(SeekFrom::Current(name_len as i64))?;
        Ok((FileStats::on_disk_size() + SHA256_OUTPUT_LEN + name_len as usize) as u64)
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let stats = FileStats::read(&mut *reader)?;
        let mut sha256 = [0u8; SHA256_OUTPUT_LEN];
        reader.read_exact(&mut sha256)?;

        let len = u32::read_le(&mut *reader)?;
        let mut name = String::with_capacity(len as usize);
        reader.take(len as u64).read_to_string(&mut name)?;

        Ok(Self {
            stats,
            sha256,
            name,
        })
    }
}

/// A directory cache.
pub struct DirCache {
    // all global variables go in here
    active_cache: Vec<u64>,
    reader: BufReader<File>,
}

impl DirCache {
    /// Initialize the cache information.
    pub fn read_cache() -> Result<Self, Error> {
        let dir = env::var(DB_ENVIRONMENT).unwrap_or_else(|_| DEFAULT_DB_ENVIRONMENT.to_string());
        let path = Path::new(&dir);
        // there's no way to check permission to a dir, try read from it and return whatever error
        // the read operation returns
        fs::read_dir(path)?;

        let mut fd = BufReader::new(File::open(".dircache/index")?);
        let size = fd.get_ref().metadata()?.len();
        let header = CacheHeader::read_and_verify(&mut fd, size)?;

        let mut pos = CacheHeader::on_disk_size() as u64;
        fd.seek(SeekFrom::Start(pos))?;
        let mut active_cache = Vec::with_capacity(header.entries);

        for _ in 0..header.entries {
            let skip = CacheEntry::skip(&mut fd)?;
            active_cache.push(pos);
            pos += skip;
        }

        Ok(Self {
            active_cache,
            reader: fd,
        })
    }

    /// Return a statically allocated filename matching the sha1 signature.
    pub fn sha_file_name(&self, sha: &[u8; SHA256_OUTPUT_LEN]) -> String {
        unimplemented!()
    }
}
