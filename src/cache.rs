use bitflags::bitflags;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::TryFrom,
    env,
    fs::{self, File, FileType},
    io::{BufReader, ErrorKind, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, SystemTimeError},
};

use crate::Error;
use bincode::{deserialize_from, serialize_into, serialized_size};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

/// Name of the environment variable containing the path to the directory cache.
pub const DB_ENVIRONMENT: &str = "SHA256_FILE_DIRECTORY";

/// Default value of [DB_ENVIRONMENT](DB_ENVIRONMENT).
pub const DEFAULT_DB_ENVIRONMENT: &str = ".dircache/objects";
const DEFAULT_INDEX_LOCATION: &str = ".dircache/index";

const SHA256_OUTPUT_LEN: usize = 32;
type SHA256Output = [u8; SHA256_OUTPUT_LEN];
const CACHE_SIGNATURE: u32 = u32::from_be_bytes(*b"DIRC");
const CACHE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct CacheHeader {
    signature: u32,
    version: u32,
    entries: usize,
}

impl CacheHeader {
    fn new(entries: usize) -> Self {
        Self {
            signature: CACHE_SIGNATURE,
            version: CACHE_VERSION,
            entries,
        }
    }

    fn read_and_verify<R: Read>(reader: &mut R, size: u64) -> Result<Self, Error> {
        // there's no mmap in safe Rust, we cannot use it anyway as Rust does not guarantee memory
        // layout of structs, wonder how different would the performance be

        let header: CacheHeader = deserialize_from(&mut *reader)?;

        if header.signature != CACHE_SIGNATURE {
            eprintln!("{:08x}", header.signature);
            eprintln!("{:08x}", CACHE_SIGNATURE);
            return Err(Error::CorruptedHeader("bad signature"));
        }

        if header.version != CACHE_VERSION {
            return Err(Error::CorruptedHeader("bad version"));
        }

        let mut sha256 = SHA256Output::default();
        reader.read_exact(&mut sha256)?;

        let mut hasher = Sha256::new();
        serialize_into(&mut hasher, &header)?;
        io::copy(
            &mut reader.take(size - serialized_size(&header)?),
            &mut hasher,
        )?;

        if hasher.finalize().as_slice() != sha256 {
            return Err(Error::CorruptedHeader("wrong sha256 signature"));
        }

        Ok(header)
    }
}

/// The lower 32 bits of times (creation or modification), only used to verify if the file changed
/// since last time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
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

bitflags! {
    /// There's only 3 bits of reliably available information from std::io::FileType:
    /// - FileType::is_dir
    /// - FileType::is_file
    /// - FileType::is_symlink
    #[repr(transparent)] /* make sure it has the same size as a u32 */
    #[derive(Serialize, Deserialize)]
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
}

/// A lot of the entries in the original C implementation will be missing, device number / uid / gid
/// / inode as a concept doesn't exist on a few platforms supported by stable Rust, hopefully the
/// extra robustness of SHA256 over SHA1 would be sufficient for the purpose.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
struct FileStats {
    created: CacheTime,
    modified: CacheTime,
    mode: FileMode,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct CacheEntry {
    stats: FileStats,
    sha256: SHA256Output,
    name: String,
}

/// A directory cache. All global variables go in here.
/// # On Disk Structure:
///
/// 1.  Header { signature, version, number of entries }
/// 2.  SHA256 of header and entries
/// 3.  Cache entries { file stats, sha256 of object, file name }
pub struct DirCache {
    /// The C implementation used a memory mapped sorted array, construction and search was fast but
    /// remove and insert is O(n), as there's no mmap in Rust maybe HashMap is the right way to go.
    active_cache: HashMap<String, CacheEntry>,
    db_environment: PathBuf,
}

impl DirCache {
    fn new(db_environment: PathBuf) -> Self {
        Self {
            active_cache: HashMap::new(),
            db_environment,
        }
    }

    /// Initialize the cache information.
    pub fn read_cache() -> Result<Self, Error> {
        let var = env::var(DB_ENVIRONMENT).unwrap_or_else(|_| DEFAULT_DB_ENVIRONMENT.to_string());
        let db_environment = PathBuf::from(var);
        // there's no way to check permission to a dir, instead try read its contents and return
        // whatever error the read operation returns
        fs::read_dir(&db_environment)?;

        let mut fd = BufReader::new(File::open(DEFAULT_INDEX_LOCATION)?);
        let size = fd.get_ref().metadata()?.len();
        let header = CacheHeader::read_and_verify(&mut fd, size)?;

        let entry_start = serialized_size(&header)? + SHA256_OUTPUT_LEN as u64;
        fd.seek(SeekFrom::Start(entry_start))?;

        let mut active_cache = HashMap::with_capacity(header.entries);

        for _ in 0..header.entries {
            let entry: CacheEntry = deserialize_from(&mut fd)?;
            active_cache.insert(entry.name.clone(), entry);
        }

        Ok(Self {
            active_cache,
            db_environment,
        })
    }

    /// Write out cache to persistent storage.
    pub fn write_cache<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let header = CacheHeader::new(self.active_cache.len());

        let mut hasher = Sha256::new();
        serialize_into(&mut hasher, &header)?;
        for entry in self.active_cache.values() {
            serialize_into(&mut hasher, entry)?;
        }
        let sha256: SHA256Output = hasher.finalize().into();

        serialize_into(&mut *writer, &header)?;
        writer.write_all(&sha256)?;
        for entry in self.active_cache.values() {
            serialize_into(&mut *writer, entry)?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Get an entry by file name.
    pub(crate) fn get(&self, name: &str) -> Option<&CacheEntry> {
        self.active_cache.get(name)
    }

    /// Insert an entry into the directory cache.
    pub(crate) fn insert(&mut self, entry: CacheEntry) {
        self.active_cache.insert(entry.name.clone(), entry);
    }

    pub(crate) fn remove(&mut self, name: &str) {
        self.active_cache.remove(name);
    }

    /// Add a file to the cache.
    pub fn add_file(&mut self, path: &str) -> Result<(), Error> {
        let mut fd = match File::open(path) {
            Ok(fd) => fd,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    self.remove(path);
                }
                return Err(From::from(e));
            }
        };

        let metadata = fd.metadata()?;
        let created = CacheTime::try_from(metadata.created()?)?;
        let modified = CacheTime::try_from(metadata.modified()?)?;
        let mode = FileMode::new(metadata.file_type());
        let size = metadata.len();

        let stats = FileStats {
            created,
            modified,
            mode,
            size,
        };

        let sha256 = self.index_file(path, fd)?;

        let entry = CacheEntry {
            stats,
            sha256,
            name: path.to_string(),
        };

        self.insert(entry);

        Ok(())
    }

    fn index_file(&self, path: &str, fd: File) -> Result<SHA256Output, Error> {
        unimplemented!()
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
mod tests {
    use super::*;
    use rand::{
        distributions::{Alphanumeric, Standard},
        prelude::{Distribution, StdRng},
        Rng, SeedableRng,
    };
    use tempfile::TempDir;

    impl Distribution<CacheTime> for Standard {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> CacheTime {
            CacheTime {
                sec: rng.gen(),
                nsec: rng.gen(),
            }
        }
    }

    impl Distribution<FileMode> for Standard {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> FileMode {
            let bits = rng.gen_range(0..=FileMode::all().bits());
            FileMode::from_bits(bits).unwrap()
        }
    }

    impl Distribution<FileStats> for Standard {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> FileStats {
            FileStats {
                created: rng.gen(),
                modified: rng.gen(),
                mode: rng.gen(),
                size: rng.gen(),
            }
        }
    }

    impl Distribution<CacheEntry> for Standard {
        fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> CacheEntry {
            let name_len = rng.gen_range(5..=20);
            let mut name = String::new();
            for _ in 0..name_len {
                name.push(char::from(rng.sample(Alphanumeric)));
            }

            CacheEntry {
                stats: rng.gen(),
                sha256: rng.gen(),
                name,
            }
        }
    }

    #[test]
    fn cache_write_read() {
        let temp_dir = TempDir::new().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        let mut cache = DirCache::new(PathBuf::from(DEFAULT_DB_ENVIRONMENT));
        let seed: u64 = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);

        for _ in 0..10 {
            cache.insert(rng.gen());
        }

        fs::create_dir(".dircache").unwrap();
        fs::create_dir(DEFAULT_DB_ENVIRONMENT).unwrap();
        let mut file = File::create(DEFAULT_INDEX_LOCATION).unwrap();
        cache.write_cache(&mut file).unwrap();

        drop(file);

        let dir_cache = DirCache::read_cache().unwrap();
        assert_eq!(cache.active_cache, dir_cache.active_cache);
    }

    #[test]
    fn hex_sha256() {
        let sha256 = rand::random();
        let hex = sha256_to_hex(&sha256);
        assert_eq!(hex_to_sha256(&hex), Some(sha256));
    }
}
