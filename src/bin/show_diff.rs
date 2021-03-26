use std::process::{Command, ExitStatus};

use anyhow::Context;
use baby_rgit::cmd::error_exit;
use bitflags::bitflags;

bitflags! {
    struct Diff: u32 {
        const CTIME_CHANGED     = 0b0001;
        const MTIME_CHANGED     = 0b0010;
        const MODE_CHANGED      = 0b0100;
        const DATA_CHANGED      = 0b1000;
    }
}

fn main() {
    match detect_diff() {
        Ok(status) => {
            if !status.success() {
                error_exit(format!("diff returned {:?}", status.code()));
            }
        }
        Err(e) => {
            error_exit(e);
        }
    }
}

fn detect_diff() -> anyhow::Result<ExitStatus> {
    Command::new("diff")
        .arg("-v")
        .status()
        .context("Error calling diff")
}
