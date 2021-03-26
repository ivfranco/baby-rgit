use anyhow::Context;
use argh::FromArgs;
use baby_rgit::{
    cache::{sha256_to_hex, DirCache},
    cmd::*,
};

fn main() {
    let _: WriteTree = argh::from_env();

    if let Err(e) = exec() {
        error_exit(e);
    }
}

fn exec() -> anyhow::Result<()> {
    let var = db_environment();
    let cache = DirCache::read_index(var).context("Unable to read index file")?;
    let sha256 = cache.pack().context("Failed to pack cache state")?;

    print!("{}", sha256_to_hex(&sha256));

    Ok(())
}

#[derive(FromArgs)]
/// Capture the current state of the directory cache.
struct WriteTree {}
