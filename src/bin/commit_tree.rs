use std::time::SystemTime;

use argh::FromArgs;
use baby_rgit::cache::{sha256_to_hex, DBEnv, SHA256Output};
use baby_rgit::cmd::*;

fn main() {
    let args = argh::from_env();

    if let Err(e) = exec(args) {
        error_exit(e);
    }
}

fn exec(args: CommitTree) -> anyhow::Result<()> {
    let db_env = DBEnv::new(db_environment());
    let time = SystemTime::now();
    let sha256 = db_env.commit(args.sha256, args.parents, time, args.comment)?;
    print!("{}", sha256_to_hex(&sha256));
    Ok(())
}

#[derive(FromArgs)]
/// Commit a cached tree object.
struct CommitTree {
    #[argh(positional, from_str_fn(sha256_from_str))]
    sha256: SHA256Output,
    #[argh(option, short = 'p', from_str_fn(sha256_from_str))]
    /// parents of this commit
    parents: Vec<SHA256Output>,
    #[argh(option, short = 'c', from_str_fn(non_empty_comment))]
    /// comment to this commit
    comment: String,
}

fn non_empty_comment(str: &str) -> Result<String, String> {
    if str.is_empty() {
        return Err("empty commit comment".to_string());
    }

    Ok(str.to_string())
}
