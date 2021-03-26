use argh::FromArgs;
use baby_rgit::{
    cache::DBEnv,
    cmd::{db_environment, sha256_from_str},
};
use baby_rgit::{cache::SHA256Output, cmd::error_exit};

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
    #[argh(positional, from_str_fn(sha256_from_str))]
    /// SHA256 key of a commit.
    key: SHA256Output,
}
