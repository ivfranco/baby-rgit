use anyhow::Context;
use argh::FromArgs;
use baby_rgit::{cache::DirCache, cmd::*};

fn main() {
    let _: WriteTree = argh::from_env();

    if let Err(e) = exec() {
        error_exit(e);
    }
}

fn exec() -> anyhow::Result<()> {
    let var = db_environment();
    let cache = DirCache::read_index(var).context("Unable to read index file")?;
    cache.pack().context("Failed to pack cache state")?;

    Ok(())
}

#[derive(FromArgs)]
/// Capture the current state of the directory cache.
struct WriteTree {}
