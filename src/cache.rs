use bincode::{deserialize_from, serialize_into, serialized_size};
use bitflags::bitflags;
use flate2::{bufread::ZlibDecoder, write::ZlibEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::{
    collections::HashMap,
    convert::TryFrom,
    env,
    fs::{self, File, FileType, OpenOptions},
    io::{self, BufReader, BufWriter, Cursor, ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::from_utf8,
    time::{SystemTime, SystemTimeError},
};

use crate::Error;

/// Name of the environment variable containing the path to the directory cache.
pub const DB_ENVIRONMENT: &str = "SHA256_FILE_DIRECTORY";

/// Default value of [DB_ENVIRONMENT](DB_ENVIRONMENT).
pub const DEFAULT_DB_ENVIRONMENT: &str = ".dircache";
const INDEX_LOCATION: &str = "index";
const OBJECT_STORE_LOCATION: &str = "objects";

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
            return Err(Error::CorruptedIndex("bad signature"));
        }

        if header.version != CACHE_VERSION {
            return Err(Error::CorruptedIndex("bad version"));
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
            return Err(Error::CorruptedIndex("wrong sha256 signature"));
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

/// Types of objects in the object store.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObjectType {
    /// A binary blob of data.
    Blob,
    /// A list of metadata and blob data sorted by name.
    Tree,
}

impl ObjectType {
    fn tag(self) -> &'static str {
        match self {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
        }
    }
}

#[derive(Debug, PartialEq)]
struct ObjectHeader {
    ty: ObjectType,
    size: u64,
}

const fn u64_max_len() -> usize {
    "18446744073709551615".len()
}

impl ObjectHeader {
    fn write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        // provides a little bit more robustness to the SHA256 hash against non-adversarial
        // collisions
        serialize_into(&mut *writer, self.ty.tag())?;

        let mut buf = [0u8; u64_max_len()];
        let mut cursor = Cursor::new(&mut buf[..]);
        write!(&mut cursor, "{}", self.size).unwrap();
        let pos = cursor.position() as usize;
        let decimal = from_utf8(&buf[..pos]).unwrap();

        serialize_into(&mut *writer, decimal)?;

        Ok(())
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let ty = match deserialize_from::<_, String>(&mut *reader)?.as_str() {
            "blob" => ObjectType::Blob,
            "tree" => ObjectType::Tree,
            _ => return Err(Error::CorruptedObject("unknown object type")),
        };

        let decimal: String = deserialize_from::<_, String>(&mut *reader)?;
        let size = decimal
            .parse::<u64>()
            .map_err(|_| Error::CorruptedObject("illegal decimal size"))?;

        Ok(Self { ty, size })
    }
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
    /// Initialize an empty cache.
    pub fn new(db_environment: PathBuf) -> Self {
        Self {
            active_cache: HashMap::new(),
            db_environment,
        }
    }

    /// Initialize the cache information from index file.
    pub fn read_cache<P: AsRef<Path>>(db_environment: P) -> Result<Self, Error> {
        let db_environment = db_environment.as_ref().to_path_buf();
        // there's no way to check permission to a dir, instead try read its contents and return
        // whatever error the read operation returns
        fs::read_dir(db_environment.join(OBJECT_STORE_LOCATION))?;

        let mut fd = BufReader::new(File::open(db_environment.join(INDEX_LOCATION))?);
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

    /// Write out cache to persistent index file.
    pub fn write_cache(&self) -> Result<(), Error> {
        let header = CacheHeader::new(self.active_cache.len());

        let mut hasher = Sha256::new();
        serialize_into(&mut hasher, &header)?;
        for entry in self.active_cache.values() {
            serialize_into(&mut hasher, entry)?;
        }
        let sha256: SHA256Output = hasher.finalize().into();

        let fd = OpenOptions::new()
            .write(true)
            .create(true)
            .open(self.db_environment.join(INDEX_LOCATION))?;
        let mut writer = BufWriter::new(fd);

        serialize_into(&mut writer, &header)?;
        writer.write_all(&sha256)?;
        for entry in self.active_cache.values() {
            serialize_into(&mut writer, entry)?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Get an entry by file name.
    fn get(&self, name: &str) -> Option<&CacheEntry> {
        self.active_cache.get(name)
    }

    /// Insert an entry into the directory cache.
    fn insert(&mut self, entry: CacheEntry) {
        self.active_cache.insert(entry.name.clone(), entry);
    }

    fn remove(&mut self, name: &str) {
        self.active_cache.remove(name);
    }

    /// Add a file to the cache.
    pub fn add_file(&mut self, path: &str) -> Result<SHA256Output, Error> {
        let fd = match File::open(path) {
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

        let sha256 = self.index_file(fd, &stats)?;

        let entry = CacheEntry {
            stats,
            sha256,
            name: path.to_string(),
        };

        self.insert(entry);

        Ok(sha256)
    }

    fn index_file(&self, fd: File, stats: &FileStats) -> Result<SHA256Output, Error> {
        let mut reader = BufReader::new(fd);
        self.write_sha256_file(ObjectType::Blob, &mut reader, stats.size)
    }

    fn write_sha256_buffer(&self, sha256: &SHA256Output, buf: &[u8]) -> Result<(), Error> {
        let path = self.db_environment.join(sha256_to_hex(sha256));

        let mut fd = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(fd) => fd,
            Err(e) => {
                if e.kind() == ErrorKind::AlreadyExists {
                    // if the object exists, by SHA256 it must has the same content as `buf`
                    return Ok(());
                } else {
                    return Err(From::from(e));
                }
            }
        };

        fd.write_all(buf)?;
        fd.flush()?;

        Ok(())
    }

    /// Read a sha256 indexed file from the object store.
    pub fn read_sha256_file(&self, sha256: &SHA256Output) -> Result<(ObjectType, Vec<u8>), Error> {
        let path = self.db_environment.join(sha256_to_hex(sha256));
        let fd = File::open(path)?;
        let mut reader = ZlibDecoder::new(BufReader::new(fd));

        // Rust doesn't have sscanf nor are rust strings terminated by \0, the scheme in C has to be
        // tweaked a little bit.
        let ObjectHeader { ty, size } = ObjectHeader::read(&mut reader)?;

        let mut buf = Vec::with_capacity(size as usize);
        reader.read_to_end(&mut buf)?;

        Ok((ty, buf))
    }

    /// Write a buffer to sha256 indexed file in object store.
    pub fn write_sha256_file<R>(
        &self,
        ty: ObjectType,
        reader: &mut R,
        size: u64,
    ) -> Result<SHA256Output, Error>
    where
        R: Read,
    {
        let compressed = Vec::with_capacity(size as usize);
        let mut writer = ZlibEncoder::new(compressed, Compression::best());
        ObjectHeader { ty, size }.write(&mut writer)?;
        io::copy(&mut *reader, &mut writer)?;
        let compressed = writer.finish()?;

        let sha256 = Sha256::digest(&compressed).into();

        self.write_sha256_buffer(&sha256, &compressed)?;

        Ok(sha256)
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
    use std::path::Path;

    use super::*;
    use rand::{
        distributions::{Alphanumeric, Standard},
        prelude::{Distribution, StdRng},
        Rng, SeedableRng,
    };
    use tempfile::{NamedTempFile, TempDir};

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

    impl Distribution<ObjectType> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ObjectType {
            if rng.gen_bool(0.5) {
                ObjectType::Blob
            } else {
                ObjectType::Tree
            }
        }
    }

    impl Distribution<ObjectHeader> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ObjectHeader {
            ObjectHeader {
                ty: rng.gen(),
                size: rng.gen(),
            }
        }
    }

    fn test_env() -> (TempDir, DirCache) {
        let dir = TempDir::new().unwrap();
        // cwd is process-wide, the temp dir will be shared between multiple test threads
        // env::set_current_dir(dir.path()).unwrap();

        let path = dir.path();
        fs::create_dir(path.join(DEFAULT_DB_ENVIRONMENT)).unwrap();
        fs::create_dir(
            path.join(DEFAULT_DB_ENVIRONMENT)
                .join(OBJECT_STORE_LOCATION),
        )
        .unwrap();
        let cache = DirCache::new(path.join(DEFAULT_DB_ENVIRONMENT));

        (dir, cache)
    }

    #[test]
    fn cache_write_read() {
        let (dir, mut cache) = test_env();

        let seed: u64 = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);

        for _ in 0..10 {
            cache.insert(rng.gen());
        }

        cache.write_cache().unwrap();

        let dir_cache = DirCache::read_cache(dir.path().join(DEFAULT_DB_ENVIRONMENT)).unwrap();
        assert_eq!(cache.active_cache, dir_cache.active_cache);
    }

    #[test]
    fn hex_sha256_conversion() {
        let sha256 = rand::random();
        let hex = sha256_to_hex(&sha256);
        assert_eq!(hex_to_sha256(&hex), Some(sha256));
    }

    #[test]
    fn object_header_ser_de() {
        let mut buf = vec![];
        let header: ObjectHeader = rand::random();
        header.write(&mut buf).unwrap();
        from_utf8(&buf).unwrap();
        let de = ObjectHeader::read(&mut buf.as_slice()).unwrap();

        assert_eq!(header, de);
    }

    #[test]
    fn sha256_file_write_read() {
        let (dir, mut cache) = test_env();

        let mut rng = rand::thread_rng();
        let len = rng.gen_range(0..0x1000);
        let buf: Vec<u8> = (&mut rng).sample_iter(Standard).take(len).collect();

        let mut file = NamedTempFile::new_in(dir.path()).unwrap();
        file.write_all(&buf).unwrap();
        file.flush().unwrap();

        let sha256 = cache.add_file(file.path().to_str().unwrap()).unwrap();
        let (ty, deflated) = cache.read_sha256_file(&sha256).unwrap();

        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(deflated, buf);
    }
}
