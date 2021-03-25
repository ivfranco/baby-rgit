use argh::FromArgs;
use baby_rgit::{cache::SHA256Output, cmd::error_exit};
use baby_rgit::{
    cache::{hex_to_sha256, DBEnv},
    cmd::db_environment,
};

fn main() {
    let ReadTree { key } = argh::from_env();
    let db_env = DBEnv::new(db_environment());
    if let Err(e) = db_env.unpack(&key) {
        error_exit(e);
    }
}

#[derive(FromArgs)]
/// Read and unpack a sha256 indexed snapshot of committed directory cache.
struct ReadTree {
    #[argh(positional, from_str_fn(key_from_str))]
    /// SHA256 key of a commit.
    key: SHA256Output,
}

fn key_from_str(str: &str) -> Result<SHA256Output, String> {
    hex_to_sha256(str).ok_or_else(|| "argument is not valid hex string".to_string())
}
