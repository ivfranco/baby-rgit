use bitflags::bitflags;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::TryFrom,
    env,
    fs::{self, File, FileType},
    io::{BufReader, Cursor, Seek, SeekFrom},
    mem,
    path::{Path, PathBuf},
    time::{SystemTime, SystemTimeError},
};

use crate::{Error, ReadLE, WriteLE};
use std::io::{self, Read};

/// Name of the environment variable containing the path to the directory cache.
pub const DB_ENVIRONMENT: &str = "SHA256_FILE_DIRECTORY";

/// Default value of [DB_ENVIRONMENT](DB_ENVIRONMENT).
pub const DEFAULT_DB_ENVIRONMENT: &str = ".dircache/objects";

const SHA256_OUTPUT_LEN: usize = 32;
type SHA256Output = [u8; SHA256_OUTPUT_LEN];
const CACHE_SIGNATURE: u32 = u32::from_be_bytes(*b"DIRC");
const CACHE_VERSION: u32 = 1;

struct CacheHeader {
    signature: u32,
    version: u32,
    entries: usize,
    // sha1 has been deprecated
    sha256: SHA256Output,
}

impl CacheHeader {
    const fn on_disk_size_without_sha256() -> usize {
        mem::size_of::<u32>() * 3
    }

    const fn on_disk_size() -> usize {
        Self::on_disk_size_without_sha256() + SHA256_OUTPUT_LEN
    }

    fn read_and_verify<R: Read>(reader: &mut R, size: u64) -> Result<Self, Error> {
        // there's no mmap in safe Rust, we cannot use it anyway as Rust does not guarantee memory
        // layout of structs, wonder how different would the performance be
        let mut buf = [0u8; Self::on_disk_size_without_sha256()];
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

        let mut sha256 = SHA256Output::default();
        reader.read_exact(&mut sha256)?;

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        io::copy(
            &mut reader.take(size - Self::on_disk_size() as u64),
            &mut hasher,
        )?;

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

impl WriteLE for CacheHeader {
    fn write_le<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.signature.write_le(&mut writer)?;
        self.version.write_le(&mut writer)?;
        (self.entries as u32).write_le(&mut writer)?;
        writer.write_all(&self.sha256)?;
        Ok(())
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
    sha256: SHA256Output,
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
        let mut sha256 = SHA256Output::default();
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

/// A directory cache. All global variables go in here.
pub struct DirCache {
    /// The C implementation used a memory mapped sorted array, construction and search was fast but
    /// remove and insert is O(n), as there's no mmap in Rust maybe HashMap is the right way to go.
    active_cache: HashMap<String, CacheEntry>,
    db_environment: PathBuf,
}

impl DirCache {
    /// Initialize the cache information.
    pub fn read_cache() -> Result<Self, Error> {
        let var = env::var(DB_ENVIRONMENT).unwrap_or_else(|_| DEFAULT_DB_ENVIRONMENT.to_string());
        let db_environment = PathBuf::from(var);
        // there's no way to check permission to a dir, instead try read its contents and return
        // whatever error the read operation returns
        fs::read_dir(&db_environment)?;

        let mut fd = BufReader::new(File::open(".dircache/index")?);
        let size = fd.get_ref().metadata()?.len();
        let header = CacheHeader::read_and_verify(&mut fd, size)?;

        let entry_start = CacheHeader::on_disk_size() as u64;
        fd.seek(SeekFrom::Start(entry_start))?;

        let mut active_cache = HashMap::with_capacity(header.entries);

        for _ in 0..header.entries {
            let entry = CacheEntry::read(&mut fd)?;
            active_cache.insert(entry.name.clone(), entry);
        }

        Ok(Self {
            active_cache,
            db_environment,
        })
    }
}

fn sha256_to_hex(sha256: &SHA256Output) -> String {
    use std::fmt::Write;

    let mut name = String::new();
    for &byte in sha256 {
        write!(&mut name, "{:02x}", byte).unwrap();
    }
    name
}

fn hexval(char: u8) -> Option<u8> {
    match char {
        b'0'..=b'9' => Some(char - b'0'),
        b'a'..=b'f' => Some(char - b'a' + 10),
        _ => None,
    }
}

fn hex_to_sha256(hex: &str) -> Option<SHA256Output> {
    let bytes = hex.as_bytes();
    assert_eq!(bytes.len(), 64);

    let mut sha256 = SHA256Output::default();

    for i in 0..SHA256_OUTPUT_LEN {
        sha256[i] = hexval(bytes[2 * i])? << 4;
        sha256[i] |= hexval(bytes[2 * i + 1])?;
    }

    Some(sha256)
}

#[cfg(test)]
mod tests {}
