use std::{
    fs::OpenOptions,
    io::BufWriter,
    path::{Path, PathBuf},
};

use anyhow::Context;
use argh::FromArgs;
use baby_rgit::{
    cache::{DirCache, INDEX_LOCATION},
    cmd::*,
};

fn main() {
    let UpdateCache { files } = argh::from_env();
    if let Err(e) = exec(files) {
        error_exit(e);
    }
}

fn exec(files: Vec<String>) -> anyhow::Result<()> {
    let db_env = PathBuf::from(&db_environment());
    let path = db_env.join("index.lock");
    let lock = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .context("Unable to create new cache file")?;

    let mut cache = DirCache::read_cache(&db_env)?;

    for file in files {
        if !verify_path(&file) {
            eprintln!("Skipped file {}", file);
            continue;
        }

        cache
            .add_file(&file)
            .with_context(|| format!("failed to add {} to cache", file))?;
    }

    cache.write_index(&lock)?;
    std::fs::rename(path, db_env.join(INDEX_LOCATION))?;

    Ok(())
}

#[derive(FromArgs)]
/// Add listed files to the directory cache.
struct UpdateCache {
    #[argh(positional)]
    /// A list of unicode file names to be added to the directory cache.
    files: Vec<String>,
}
