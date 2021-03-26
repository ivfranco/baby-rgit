use std::{
    collections::VecDeque,
    fs::{self, File},
    io::{self, Write},
    path::Path,
    str::from_utf8,
};

use assert_cmd::Command;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

use baby_rgit::cache::{
    DirCache, SHA256Output, DEFAULT_DB_ENVIRONMENT, INDEX_LOCATION, OBJECT_STORE_LOCATION,
};
use walkdir::{DirEntry, WalkDir};

fn random_file_under<R: RngCore>(rng: &mut R, dir: &Path) -> io::Result<()> {
    const MAX_LEN: usize = 0x10000;

    let mut file = NamedTempFile::new_in(dir)?;

    let mut buf = vec![0; rng.gen_range(0..=MAX_LEN)];
    rng.fill(buf.as_mut_slice());

    file.write_all(&buf)?;
    file.keep()?;

    Ok(())
}

// returns total number of files
fn random_structure<R: Rng>(rng: &mut R, dir: &Path) -> io::Result<u32> {
    const MAX_FILE: u32 = 100;
    const MAX_DIR_FILE: u32 = 5;
    const MAX_DIR_SUB: u32 = 3;

    let mut queue = VecDeque::new();
    queue.push_back((dir.to_path_buf(), 1u32));
    let mut files = 0;

    while let Some((dir, level)) = queue.pop_front() {
        let n_files = rng.gen_range(0..=MAX_DIR_FILE);

        for _ in 0..n_files {
            random_file_under(&mut *rng, &dir)?;
        }

        files += n_files;
        if files > MAX_FILE {
            break;
        }

        if rng.gen_bool(1.0 / (level as f64)) {
            let n_subs = rng.gen_range(0..=MAX_DIR_SUB);

            for _ in 0..n_subs {
                let sub = TempDir::new_in(&dir)?;
                queue.push_back((sub.into_path(), level + 1));
            }
        }
    }

    Ok(files)
}

fn dir_walker(root: &Path) -> impl Iterator<Item = Result<DirEntry, walkdir::Error>> + '_ {
    WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !entry.path().ends_with(DEFAULT_DB_ENVIRONMENT))
}

fn same_file(lhs: &Path, rhs: &Path) -> io::Result<bool> {
    let mut lhs = File::open(lhs)?;
    let mut rhs = File::open(rhs)?;

    let mut hasher = Sha256::new();
    io::copy(&mut lhs, &mut hasher)?;
    let l_sha: SHA256Output = hasher.finalize_reset().into();

    io::copy(&mut rhs, &mut hasher)?;
    let r_sha: SHA256Output = hasher.finalize_reset().into();

    Ok(l_sha == r_sha)
}

#[test]
fn cli_init_db() {
    let temp = TempDir::new().unwrap();

    Command::cargo_bin("init_db")
        .unwrap()
        .current_dir(&temp)
        .assert()
        .success();

    let db_environment = temp.path().join(DEFAULT_DB_ENVIRONMENT);
    assert!(db_environment.is_dir());
    assert!(db_environment.join(INDEX_LOCATION).is_file());

    let _ = DirCache::read_index(&db_environment).unwrap();

    let obj_store = db_environment.join(OBJECT_STORE_LOCATION);
    for b in 0..=255u8 {
        assert!(obj_store.join(format!("{:02x}", b)).is_dir());
    }
}

#[test]
fn cli_update_cache() {
    let temp = TempDir::new().unwrap();
    let db_env = temp.path().join(DEFAULT_DB_ENVIRONMENT);
    let _ = DirCache::init(&db_env).unwrap();

    let mut rng = rand::thread_rng();
    let files = random_structure(&mut rng, temp.path()).unwrap();

    for entry in dir_walker(temp.path()) {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() {
            Command::cargo_bin("update_cache")
                .unwrap()
                .current_dir(&temp)
                .arg(path)
                .assert()
                .success();
        }
    }

    let cache = DirCache::read_index(&db_env).unwrap();
    assert_eq!(cache.entries(), files as usize);
}

#[test]
fn cli_tree_read_write() {
    let temp = TempDir::new().unwrap();
    let orig = temp.path().join("orig");
    fs::create_dir(&orig).unwrap();

    let db_env = orig.join(DEFAULT_DB_ENVIRONMENT);
    let _ = DirCache::init(&db_env).unwrap();

    let mut rng = rand::thread_rng();
    let _ = random_structure(&mut rng, &orig);

    let mut cache = DirCache::read_index(&db_env).unwrap();
    for entry in dir_walker(&orig) {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            cache.add_file(entry.path().to_str().unwrap()).unwrap();
        }
    }

    let index = File::create(db_env.join(INDEX_LOCATION)).unwrap();
    cache.write_index(&index).unwrap();
    drop(index);

    let copy = temp.path().join("copy");

    let write_assert = Command::cargo_bin("write_tree")
        .unwrap()
        .current_dir(&orig)
        .assert()
        .success();

    let hex = &write_assert.get_output().stdout;

    // temp/orig -> temp/copy
    fs::rename(&orig, &copy).unwrap();
    // again create temp/orig
    fs::create_dir(&orig).unwrap();
    // temp/copy/.dircache -> temp/orig/.dircache
    fs::rename(
        copy.join(DEFAULT_DB_ENVIRONMENT),
        orig.join(DEFAULT_DB_ENVIRONMENT),
    )
    .unwrap();

    let hex = from_utf8(hex).unwrap();

    Command::cargo_bin("read_tree")
        .unwrap()
        .arg(hex)
        .current_dir(&orig)
        .assert()
        .success();

    let copy_walker = dir_walker(&copy);
    let mut orig_walker = dir_walker(&orig);

    for copy_entry in copy_walker {
        let copy_entry = copy_entry.unwrap();

        if !copy_entry.path().is_file() {
            continue;
        }

        // unpack doesn't recreate empty directories
        let orig_entry = loop {
            let orig_entry = orig_walker.next().unwrap().unwrap();
            if orig_entry.path().is_file() {
                break orig_entry;
            }
        };

        assert_eq!(copy_entry.file_name(), orig_entry.file_name());
        assert!(same_file(copy_entry.path(), orig_entry.path()).unwrap());
    }
}
