use argh::FromArgs;
use baby_rgit::{cache::Sha256Output, cmd::error_exit};
use baby_rgit::{
    cache::{hex_to_sha256, DbEnv},
    cmd::db_environment,
};

fn main() {
    let ReadTree { key } = argh::from_env();
    let db_env = DbEnv::new(db_environment());
    if let Err(e) = db_env.unpack(&key) {
        error_exit(e);
    }
}

#[derive(FromArgs)]
/// Read and unpack a sha256 indexed snapshot of committed directory cache.
struct ReadTree {
    #[argh(positional, from_str_fn(key_from_str))]
    /// SHA256 key of a commit.
    key: Sha256Output,
}

fn key_from_str(str: &str) -> Result<Sha256Output, String> {
    hex_to_sha256(str).ok_or_else(|| "argument is not valid hex string".to_string())
}
