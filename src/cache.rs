use bincode::{deserialize, deserialize_from, serialize, serialize_into, serialized_size};
use bitflags::bitflags;
use flate2::{bufread::ZlibDecoder, write::ZlibEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::{
    borrow::Cow,
    collections::BTreeMap,
    convert::TryFrom,
    fs::{self, File, FileType, OpenOptions},
    io::{self, BufReader, BufWriter, ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::from_utf8,
    time::{SystemTime, SystemTimeError},
};

use crate::Error;

/// Name of the environment variable containing the path to the directory cache.
pub const DB_ENVIRONMENT: &str = "DB_ENVIRONMENT";

/// Default value of [DB_ENVIRONMENT](DB_ENVIRONMENT).
pub const DEFAULT_DB_ENVIRONMENT: &str = ".dircache";

/// Location of cache index file under cache directory.
pub const INDEX_LOCATION: &str = "index";

/// Subdirectory of the object store.
pub const OBJECT_STORE_LOCATION: &str = "objects";

const SHA256_OUTPUT_LEN: usize = 32;

/// Output of SHA256 hash algorithm as a fixed-length byte array.
pub type SHA256Output = [u8; SHA256_OUTPUT_LEN];
const CACHE_SIGNATURE: u32 = u32::from_le_bytes(*b"DIRC");
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
    /// A commit recording author and relations between trees.
    Commit,
}

impl ObjectType {
    fn tag(self) -> &'static str {
        match self {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
            ObjectType::Commit => "commit",
        }
    }
}

#[derive(Debug, PartialEq)]
struct ObjectHeader {
    ty: ObjectType,
    size: u64,
}

impl ObjectHeader {
    fn write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        // serializing the header in ASCII provides a little bit more robustness to the SHA256 hash
        // against non-adversarial collisions, meaningless once it's busted like SHA1
        serialize_into(&mut *writer, self.ty.tag())?;
        serialize_into(&mut *writer, &format!("{}", self.size))?;

        Ok(())
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let ty = match deserialize_from::<_, String>(&mut *reader)?.as_str() {
            "blob" => ObjectType::Blob,
            "tree" => ObjectType::Tree,
            "commit" => ObjectType::Commit,
            _ => return Err(Error::CorruptedObject("unknown object type")),
        };

        let decimal: String = deserialize_from::<_, String>(&mut *reader)?;
        let size = decimal
            .parse::<u64>()
            .map_err(|_| Error::CorruptedObject("illegal decimal size"))?;

        Ok(Self { ty, size })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TreeObjectEntry<'a> {
    name: Cow<'a, String>,
    sha256: Cow<'a, SHA256Output>,
}

impl<'a> TreeObjectEntry<'a> {
    fn new(cache_entry: &'a CacheEntry) -> Self {
        Self {
            name: Cow::Borrowed(&cache_entry.name),
            sha256: Cow::Borrowed(&cache_entry.sha256),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TreeObject<'a> {
    entries: Vec<TreeObjectEntry<'a>>,
}

impl<'a> TreeObject<'a> {
    fn new(cache: &'a DirCache) -> Self {
        let entries: Vec<_> = cache
            .active_cache
            .values()
            .map(TreeObjectEntry::new)
            .collect();

        Self { entries }
    }

    fn pack(&self, db_env: &DBEnv) -> Result<SHA256Output, Error> {
        let buf = serialize(self)?;
        db_env.write_sha256_file(ObjectType::Tree, &mut buf.as_slice(), buf.len() as u64)
    }

    fn unpack(&self, db_env: &DBEnv) -> Result<(), Error> {
        for TreeObjectEntry { name, sha256 } in &self.entries {
            let mut file = recreate_file(name)?;
            let (ty, buf) = db_env.read_sha256_file(sha256)?;
            if ty != ObjectType::Blob {
                return Err(Error::CorruptedObject("bad object file referred by tree"));
            }
            file.write_all(&buf)?;
        }

        Ok(())
    }
}

fn recreate_file(path: &str) -> Result<File, Error> {
    let fd = match File::create(path) {
        Ok(fd) => fd,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(path)?
        }
        Err(e) => return Err(From::from(e)),
    };

    Ok(fd)
}

#[derive(Serialize, Deserialize)]
struct CommitObject {
    tree: SHA256Output,
    parents: Vec<SHA256Output>,
    time: SystemTime,
    comment: String,
}

/// Object database environment, should be the only interface to all things in
/// [DB_ENVIRONMENT](DB_ENVIRONMENT)
pub struct DBEnv {
    _root: PathBuf,
    cache_index: PathBuf,
    obj_store: PathBuf,
}

impl DBEnv {
    /// Construct an interface to the object database components without checking whether it exists
    /// on disk.
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        let root = root.as_ref().to_path_buf();

        Self {
            cache_index: root.join(INDEX_LOCATION),
            obj_store: root.join(OBJECT_STORE_LOCATION),
            _root: root,
        }
    }

    fn init<P: AsRef<Path>>(root: P) -> Result<Self, Error> {
        fn ignore_exist(e: io::Error) -> Result<(), io::Error> {
            if e.kind() == ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        }

        let root = root.as_ref().to_path_buf();

        fs::create_dir(&root).or_else(ignore_exist)?;

        let obj_store = root.join(OBJECT_STORE_LOCATION);
        fs::create_dir(&obj_store).or_else(ignore_exist)?;

        for byte in 0..=255u8 {
            let sub = byte_to_hex(byte);
            fs::create_dir(obj_store.join(from_utf8(&sub).unwrap())).or_else(ignore_exist)?;
        }

        Ok(Self {
            cache_index: root.join(INDEX_LOCATION),
            obj_store: root.join(OBJECT_STORE_LOCATION),
            _root: root,
        })
    }

    fn obj_store_path(&self) -> &Path {
        self.obj_store.as_path()
    }

    fn cache_index_path(&self) -> &Path {
        self.cache_index.as_path()
    }

    fn index_file(&self, fd: File, stats: &FileStats) -> Result<SHA256Output, Error> {
        let mut reader = BufReader::new(fd);
        self.write_sha256_file(ObjectType::Blob, &mut reader, stats.size)
    }

    fn write_sha256_buffer(&self, sha256: &SHA256Output, buf: &[u8]) -> Result<(), Error> {
        let path = sha256_file_name(self.obj_store_path(), sha256);

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
    ///
    /// # C counterpart:
    /// read-cache.c#read_sha1_file
    pub fn read_sha256_file(&self, sha256: &SHA256Output) -> Result<(ObjectType, Vec<u8>), Error> {
        let path = sha256_file_name(self.obj_store_path(), sha256);
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
    ///
    /// # C counterpart:
    /// read-cache.c#write_sha1_file
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

    /// Check the existence, accessibility and SHA256 signature of an object file without reading its
    /// entirety into memory.
    ///
    /// # C counterpart:
    /// write-tree.c#check_valid_sha1
    pub fn check_sha256_inplace(&self, sha256: &SHA256Output) -> Result<(), Error> {
        let path = sha256_file_name(self.obj_store_path(), sha256);
        let fd = File::open(path)?;
        let mut reader = BufReader::new(fd);

        let mut hasher = Sha256::new();
        io::copy(&mut reader, &mut hasher)?;
        let hash: SHA256Output = hasher.finalize().into();

        if sha256 == &hash {
            Ok(())
        } else {
            Err(Error::CorruptedObject("SHA256 mismatch"))
        }
    }

    /// Unpack a snapshot of cached directory by its sha256 signature, restore all files mentioned
    /// in the tree object to the captured content.
    ///
    /// # C counterpart
    /// read-tree.c#unpack
    pub fn unpack(&self, sha256: &SHA256Output) -> Result<(), Error> {
        let (ty, buf) = self.read_sha256_file(sha256)?;

        if ty != ObjectType::Tree {
            return Err(Error::CorruptedObject("Expected tree object"));
        }

        let tree: TreeObject = deserialize(&buf)?;
        tree.unpack(&self)?;

        Ok(())
    }

    /// Commit a SHA256-indexed tree object.
    pub fn commit(
        &self,
        tree: SHA256Output,
        parents: Vec<SHA256Output>,
        time: SystemTime,
        comment: String,
    ) -> Result<SHA256Output, Error> {
        let commit = CommitObject {
            tree,
            parents,
            time,
            comment,
        };

        let buf = serialize(&commit)?;
        self.write_sha256_file(ObjectType::Commit, &mut buf.as_slice(), buf.len() as u64)
    }
}

/// A directory cache. All global variables go in here.
/// # On Disk Structure:
///
/// 1.  Header { signature, version, number of entries }
/// 2.  SHA256 of header and entries
/// 3.  Cache entries { file stats, sha256 of object, file name }
pub struct DirCache {
    /// The object database environment managed by this cache.
    pub db_env: DBEnv,
    /// The C implementation used a memory mapped sorted array, construction and search was fast but
    /// remove and insert is O(n), as there's no mmap in Rust maybe HashMap is the right way to go.
    active_cache: BTreeMap<String, CacheEntry>,
}

impl DirCache {
    /// The number of active cache entries.
    pub fn entries(&self) -> usize {
        self.active_cache.len()
    }

    /// # C counterpart:
    /// extracted from init-db.c
    pub fn init<P: AsRef<Path>>(db_environment: P) -> Result<Self, Error> {
        let db_environment = DBEnv::init(db_environment)?;
        let index = File::create(db_environment.cache_index_path())?;

        let this = Self {
            db_env: db_environment,
            active_cache: BTreeMap::new(),
        };
        this.write_index(&index)?;

        Ok(this)
    }

    /// Initialize the cache information from index file.
    ///
    /// # C counterpart:
    /// read-cache.c#read_cache
    pub fn read_index<P: AsRef<Path>>(db_environment: P) -> Result<Self, Error> {
        let db_environment = DBEnv::new(db_environment);
        // there's no way to check permission to a dir, instead try read its contents and return
        // whatever error the read operation returns
        fs::read_dir(db_environment.obj_store_path())?;

        let mut fd = BufReader::new(File::open(db_environment.cache_index_path())?);
        let size = fd.get_ref().metadata()?.len();
        let header = CacheHeader::read_and_verify(&mut fd, size)?;

        let entry_start = serialized_size(&header)? + SHA256_OUTPUT_LEN as u64;
        fd.seek(SeekFrom::Start(entry_start))?;

        let mut active_cache = BTreeMap::new();

        for _ in 0..header.entries {
            let entry: CacheEntry = deserialize_from(&mut fd)?;
            active_cache.insert(entry.name.clone(), entry);
        }

        Ok(Self {
            db_env: db_environment,
            active_cache,
        })
    }

    /// Write out cache to persistent index file.
    ///
    /// # C counterpart:
    /// update-cache.c#write_cache
    pub fn write_index(&self, file: &File) -> Result<(), Error> {
        let header = CacheHeader::new(self.active_cache.len());

        let mut hasher = Sha256::new();
        serialize_into(&mut hasher, &header)?;
        for entry in self.active_cache.values() {
            serialize_into(&mut hasher, entry)?;
        }
        let sha256: SHA256Output = hasher.finalize().into();

        let mut writer = BufWriter::new(file);

        serialize_into(&mut writer, &header)?;
        writer.write_all(&sha256)?;
        for entry in self.active_cache.values() {
            serialize_into(&mut writer, entry)?;
        }

        writer.flush()?;

        Ok(())
    }

    /// Insert an entry into the directory cache.
    fn insert(&mut self, entry: CacheEntry) {
        self.active_cache.insert(entry.name.clone(), entry);
    }

    fn remove(&mut self, name: &str) {
        self.active_cache.remove(name);
    }

    /// Add a file to the cache, return the SHA256 hash of the compressed data on disk.
    ///
    /// # C countpart:
    /// update-cache.c#add_file_to_cache
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

        let sha256 = self.db_env.index_file(fd, &stats)?;

        let entry = CacheEntry {
            stats,
            sha256,
            name: path.to_string(),
        };

        self.insert(entry);

        Ok(sha256)
    }

    /// Pack the current state of the directory cache into an object file, write it out to the
    /// object store.
    ///
    /// # C counterpart
    /// extracted from write-tree.c
    pub fn pack(&self) -> Result<SHA256Output, Error> {
        for entry in self.active_cache.values() {
            self.db_env.check_sha256_inplace(&entry.sha256)?;
        }

        let tree = TreeObject::new(self);
        tree.pack(&self.db_env)
    }
}

fn valhex(byte: u8) -> Option<u8> {
    match byte {
        0..=9 => Some(b'0' + byte),
        10..=15 => Some(b'a' + byte - 10),
        _ => None,
    }
}

fn byte_to_hex(byte: u8) -> [u8; 2] {
    let h = byte >> 4;
    let l = byte & 0b1111;

    [valhex(h).unwrap(), valhex(l).unwrap()]
}

/// Convert SHA256 output to a hex ASCII string.
pub fn sha256_to_hex(sha256: &SHA256Output) -> String {
    sha256
        .iter()
        .flat_map(|&b| std::array::IntoIter::new(byte_to_hex(b)))
        .map(char::from)
        .collect()
}

// <$path>/<first two digits of SHA256>/<rest digits of sha256>
fn sha256_file_name(path: &Path, sha256: &SHA256Output) -> PathBuf {
    let mut buf = path.to_path_buf();

    let first_two_digits = byte_to_hex(sha256[0]);
    buf.push(from_utf8(&first_two_digits).unwrap());

    let mut rest_digits = [0u8; SHA256_OUTPUT_LEN * 2 - 2];

    for (i, &byte) in sha256.iter().skip(1).enumerate() {
        let [h, l] = byte_to_hex(byte);
        rest_digits[2 * i] = h;
        rest_digits[2 * i + 1] = l;
    }

    buf.push(from_utf8(&rest_digits).unwrap());

    buf
}

fn hexval(char: u8) -> Option<u8> {
    match char {
        b'0'..=b'9' => Some(char - b'0'),
        b'a'..=b'f' => Some(char - b'a' + 10),
        _ => None,
    }
}

/// Convert a hex ASCII string to 32-bytes of SHA256 output.
pub fn hex_to_sha256(hex: &str) -> Option<SHA256Output> {
    let bytes = hex.as_bytes();
    if bytes.len() != SHA256_OUTPUT_LEN * 2 {
        return None;
    }

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

    #[test]
    fn cache_write_read() {
        let dir = TempDir::new().unwrap();
        let db_env = dir.path().join(DEFAULT_DB_ENVIRONMENT);
        let mut cache = DirCache::init(&db_env).unwrap();

        let seed: u64 = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);

        for _ in 0..10 {
            cache.insert(rng.gen());
        }

        let index = File::create(cache.db_env.cache_index_path()).unwrap();
        cache.write_index(&index).unwrap();

        let dir_cache = DirCache::read_index(&db_env).unwrap();
        assert_eq!(cache.active_cache, dir_cache.active_cache);
    }

    #[test]
    fn hex_val_conversion() {
        for b in 0..=255u8 {
            let [h, l] = byte_to_hex(b);
            assert_eq!((hexval(h).unwrap() << 4) + hexval(l).unwrap(), b);
        }
    }

    #[test]
    fn object_header_ser_de() {
        let mut buf = vec![];
        let header: ObjectHeader = rand::random();
        header.write(&mut buf).unwrap();
        // should be safe, length of both strings cannot go beyond the higher half of a byte
        std::str::from_utf8(&buf).unwrap();
        let de = ObjectHeader::read(&mut buf.as_slice()).unwrap();

        assert_eq!(header, de);
    }

    #[test]
    fn sha256_file_write_check_read() {
        let dir = TempDir::new().unwrap();
        let mut cache = DirCache::init(dir.path().join(DEFAULT_DB_ENVIRONMENT)).unwrap();

        let mut rng = rand::thread_rng();
        let len = rng.gen_range(0..0x1000);
        let buf: Vec<u8> = (&mut rng).sample_iter(Standard).take(len).collect();

        let mut file = NamedTempFile::new_in(dir.path()).unwrap();
        file.write_all(&buf).unwrap();
        file.flush().unwrap();

        let sha256 = cache.add_file(file.path().to_str().unwrap()).unwrap();
        cache.db_env.check_sha256_inplace(&sha256).unwrap();
        let (ty, deflated) = cache.db_env.read_sha256_file(&sha256).unwrap();

        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(deflated, buf);
    }

    #[test]
    fn tree_pack_unpack() {
        let dir = TempDir::new().unwrap();
        let mut cache = DirCache::init(dir.path().join(DEFAULT_DB_ENVIRONMENT)).unwrap();

        let mut rng = rand::thread_rng();
        for _ in 0..rng.gen_range(1..100) {
            cache.insert(rng.gen());
        }

        let sha256 = TreeObject::new(&cache).pack(&cache.db_env).unwrap();
        let (ty, buf) = cache.db_env.read_sha256_file(&sha256).unwrap();
        assert_eq!(ty, ObjectType::Tree);

        let unpack: TreeObject = deserialize(&buf).unwrap();
        assert_eq!(unpack, TreeObject::new(&cache));
    }
}
