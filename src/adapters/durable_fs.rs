//! Atomic write helpers with file + parent-directory fsync.
//!
//! Rename alone is not enough after a crash: without `sync_all` on the file and
//! its parent, share / epoch blobs can revert to truncated or stale contents.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::domain::DomainError;

/// Write `data` to `path` via tmp + fsync + rename + parent fsync.
pub fn atomic_write_fsync(path: &Path, data: &[u8]) -> Result<(), DomainError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("open tmp: {e}")))?;
        f.write_all(data).map_err(|e| DomainError::ShareStoreForbidden(format!("write tmp: {e}")))?;
        f.sync_all().map_err(|e| DomainError::ShareStoreForbidden(format!("fsync tmp: {e}")))?;
    }
    fs::rename(&tmp, path).map_err(|e| DomainError::ShareStoreForbidden(format!("rename: {e}")))?;
    fsync_parent(path)?;
    Ok(())
}

/// fsync the parent directory so the rename itself is durable.
pub fn fsync_parent(path: &Path) -> Result<(), DomainError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let dir = File::open(parent)
        .map_err(|e| DomainError::ShareStoreForbidden(format!("open parent {}: {e}", parent.display())))?;
    dir.sync_all().map_err(|e| DomainError::ShareStoreForbidden(format!("fsync parent: {e}")))?;
    Ok(())
}
