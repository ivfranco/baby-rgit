use std::{convert::TryFrom, fs::File, io::Read, str::from_utf8};

use anyhow::Context;
use argh::FromArgs;
use baby_rgit::{
    cache::{sha256_to_hex, DirCache, FileStats},
    cmd::{db_environment, error_exit},
};
use bitflags::bitflags;
use difference::{Changeset, Difference::*};

bitflags! {
    struct Diff: u32 {
        const CTIME_CHANGED     = 0b0001;
        const MTIME_CHANGED     = 0b0010;
        const MODE_CHANGED      = 0b0100;
        const DATA_CHANGED      = 0b1000;
    }
}

fn match_stats(cache: &FileStats, file: &FileStats) -> Diff {
    let mut diff = Diff::empty();

    if cache.created != file.created {
        diff.insert(Diff::CTIME_CHANGED);
    }

    if cache.modified != file.modified {
        diff.insert(Diff::MTIME_CHANGED);
    }

    if cache.mode != file.mode {
        diff.insert(Diff::MODE_CHANGED);
    }

    // only a heuristic
    if cache.size != file.size {
        diff.insert(Diff::DATA_CHANGED);
    }

    diff
}

fn main() {
    let _: ShowDiff = argh::from_env();
    if let Err(e) = exec() {
        error_exit(e);
    }
}

fn exec() -> anyhow::Result<()> {
    let cache =
        DirCache::read_index(db_environment()).context("Failed reading cache from index file")?;

    dbg!(cache.entries());

    for entry in cache.active_cache() {
        let cache_stats = &entry.stats;
        let file = File::open(&entry.name).context("Failed to open the cached file")?;
        let file_stats = FileStats::try_from(&file.metadata()?)?;

        dbg!(cache_stats, file_stats);

        let diff = match_stats(&cache_stats, &file_stats);
        if diff.is_empty() {
            println!("{}: ok", entry.name);
            continue;
        }

        println!("{}: {}", entry.name, sha256_to_hex(&entry.sha256));

        let (_, buf) = cache
            .db_env
            .read_sha256_file(&entry.sha256)
            .context("Failed to read cached object")?;

        show_difference(file, &buf)?;
    }

    Ok(())
}

fn show_difference(mut file: File, buf: &[u8]) -> anyhow::Result<()> {
    let mut file_content = Vec::with_capacity(buf.len());
    file.read_to_end(&mut file_content)
        .context("Failed to read file content")?;

    let file_str = if let Ok(str) = from_utf8(&file_content) {
        str
    } else {
        println!("Binary file");
        return Ok(());
    };

    let cache_str = if let Ok(str) = from_utf8(&buf) {
        str
    } else {
        println!("Binary cache");
        return Ok(());
    };

    let changeset = Changeset::new(cache_str, file_str, "\n");
    show_changeset(&changeset);

    Ok(())
}

fn show_changeset(changeset: &Changeset) {
    for diff in &changeset.diffs {
        match diff {
            Add(s) => println!("+{}", s),
            Rem(s) => println!("-{}", s),
            _ => (),
        }
    }
}

#[derive(FromArgs)]
/// Show differences between on-disk files and cached objects.
struct ShowDiff {}
