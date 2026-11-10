//! Reading a whole lock file, under a cap.

use std::path::Path;

use crate::core::error::{Error, Result};
use crate::net::ByteLimit;

/// The largest lock file that will be read into memory.
///
/// Generous, because real ones get big: a monorepo `pnpm-lock.yaml` or a
/// `package-lock.json` with tens of thousands of entries is routinely tens
/// of megabytes. Past this the file is refused rather than silently
/// exhausting memory.
pub(crate) const LOCK_FILE_LIMIT: ByteLimit = ByteLimit::mib(256);

/// Read a lock file, refusing one over [`LOCK_FILE_LIMIT`] before reading
/// it.
pub(super) async fn read_capped(file: &Path) -> Result<Vec<u8>> {
    let size = tokio::fs::metadata(file)
        .await
        .map_err(|source| Error::ReadFile {
            path: file.to_path_buf(),
            source,
        })?
        .len();

    if size > LOCK_FILE_LIMIT.get() {
        return Err(Error::TooLarge {
            url: file.display().to_string(),
            limit: LOCK_FILE_LIMIT.get(),
        });
    }

    tokio::fs::read(file)
        .await
        .map_err(|source| Error::ReadFile {
            path: file.to_path_buf(),
            source,
        })
}
