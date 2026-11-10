//! What a target reports about each file it was handed.

/// What became of one file a target was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// Sent, and accepted.
    Uploaded,

    /// The target already held these exact bytes, so nothing was written.
    AlreadyPresent,

    /// Not sent, by the target's own rule: a checksum file PyPI does not
    /// take, a legacy distribution under `legacy-dists: skip`.
    Skipped,
}

/// Per-file results of one publish, as the target reports them.
///
/// Filled as the target goes rather than returned at the end, so a publish
/// failing on its third file still says the first two were written. A file
/// started and never finished is the one a failure belongs to; a target
/// sending several files in one request has all of them pending at once.
///
/// ```text
///   start("a.jar")  finish("a.jar", Uploaded)
///   start("b.jar")  <error>                    pending() == ["b.jar"]
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delivery {
    finished: Vec<(String, Delivered)>,
    pending: Vec<String>,
}

impl Delivery {
    /// The target is about to send `file`.
    pub fn start(&mut self, file: &str) {
        self.pending.push(file.to_owned());
    }

    /// `file` is done, one way or another.
    ///
    /// A file never started is finished all the same: a target deciding to
    /// skip a file has nothing to start.
    pub fn finish(&mut self, file: &str, how: Delivered) {
        self.pending.retain(|pending| pending != file);
        self.finished.push((file.to_owned(), how));
    }

    pub fn files(&self) -> &[(String, Delivered)] {
        &self.finished
    }

    /// Files started and not finished.
    pub fn pending(&self) -> &[String] {
        &self.pending
    }
}
