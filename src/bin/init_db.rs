use argh::FromArgs;
use baby_rgit::cache::*;
use baby_rgit::cmd::*;

fn main() {
    let _: InitDB = argh::from_env();

    let db_environment = db_environment();
    if let Err(e) = DirCache::init(db_environment) {
        error_exit(e);
    }
}

#[derive(FromArgs)]
/// Initialize the object database.
struct InitDB {}
