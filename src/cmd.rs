use std::{
    env::{self, VarError},
    fmt::Display,
    path::Path,
    process,
};

use crate::cache::{DB_ENVIRONMENT, DEFAULT_DB_ENVIRONMENT};

/// Get path of the directory cache and object store. Default to
/// [DEFAULT_DB_ENVIRONMENT](DEFAULT_DB_ENVIRONMENT) when the environment variable doesn't exist or
/// is not valid utf-8.
pub fn db_environment() -> String {
    match env::var(DB_ENVIRONMENT) {
        Ok(var) => var,
        Err(e) => {
            if let VarError::NotUnicode(var) = e {
                eprintln!("{} is not unicode: {:?}", DB_ENVIRONMENT, var);
            }
            DEFAULT_DB_ENVIRONMENT.to_string()
        }
    }
}

/// Print error message to stderr then exit with non-zero exit code.
pub fn error_exit<T: Display>(error: T) -> ! {
    eprintln!("{}", error);
    process::exit(1);
}

/// Verify if the path is safe to be added to the directory cache.
///
/// # C counterpart:
/// update-cache#verify_path
///
/// The C version ignored all paths starting with dot or ends with slash, which is not how git
/// behaves today (git add .gitignore for example).
pub fn verify_path(path: &str) -> bool {
    let db_env = db_environment();
    let path = Path::new(path);

    if path.starts_with(&db_env) {
        eprintln!("adding files in directory cache");
        false
    } else if path.ends_with(".") || path.ends_with("..") {
        eprintln!("dot or dot-dot");
        false
    } else {
        true
    }
}
