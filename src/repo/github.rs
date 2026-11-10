//! GitHub releases, as a read-only source.
//!
//! **Source and never `Target`**, which is the case the separate trait sets
//! were made for: a release is created by a project's own process and
//! cannot be pushed to by a mirroring tool. Implementing `Target` to return
//! `Unimplemented` would be worse than not implementing it -- the type
//! system can say this outright.
//!
//! ```text
//!   GET {api}/repos/{owner}/{repo}/releases            every release, newest first
//!   GET {api}/repos/{owner}/{repo}/releases/latest     GitHub's own "latest"
//!   GET {api}/repos/{owner}/{repo}/releases/tags/{tag} one release by tag
//! ```
//!
//! # Resolution asks GitHub rather than ordering a list
//!
//! [`Source::resolve`] is overridden here, which no other adapter does. The
//! default implementation lists versions and asks the ecosystem to select
//! the highest -- and for a tag list there is no highest. `v10` against `v9`,
//! `nightly` against `2024-01-05`: tag text supports no ordering worth
//! acting on.
//!
//! So an exact tag is fetched by tag, and a versionless request is answered
//! by GitHub's own `/releases/latest`. Both are one request instead of a
//! paged walk, and neither invents a comparison.
//!
//! # A release is a raw artifact
//!
//! Named `owner/repo` and versioned by its tag, so `gitleaks/gitleaks@v8.18.0`
//! is `pkg:raw/gitleaks%2Fgitleaks@v8.18.0`, and only a raw target accepts
//! it. Under a `name-version-file` target its assets land at
//! `owner/repo/{tag}/{asset}`.
//!
//! **A tag holding `@` is refused.** A raw coordinate splits its version
//! off at the last `@`, so such a tag could never be asked for by name.
//!
//! # A name mapping may choose another name
//!
//! The source's `names` rules (see `repo::names`) map `owner/repo` and a
//! tag pattern to an artifact name and version, so `tools/gitleaks@8.18.0`
//! can read `gitleaks/gitleaks` at `v8.18.0`. A request names the mapped
//! side; everything past this source sees only that name. A mapped tag may
//! hold `@` where the version it maps to does not.
//!
//! # Only the repositories it lists
//!
//! The `repositories` option is required, and a request outside it is
//! refused before anything is fetched; see `allowed`.
//!
//! # Drafts are not releases
//!
//! A draft is unpublished -- visible only to people who can write to the
//! repository, and its assets are not downloadable. It is skipped
//! everywhere here, and never counted as a pre-release: `--pre-release`
//! asks for release candidates, not for somebody's unfinished draft.

use std::sync::Arc;

use super::kind::{Kinds, Names, SourceKind, Versions};
use super::{NameMap, Source};
use crate::core::error::Result;
use crate::ext::{ExtHost, Options};

mod allowed;
mod release;
mod source;

pub use source::GitHubSource;

/// The kinds this server offers: a source, which alone reads `names`.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(
        SourceKind::new("github", open_source)
            .checked(GitHubSource::check_options)
            .named(Names {
                open: open_named,
                check: GitHubSource::check_names,
            })
            .versions(Versions::Declared),
    ),
    target: None,
    enumerators: &[],
};

/// The releases of the repositories `options` lists.
fn open_source(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
    _trust: super::Trust,
) -> Result<Arc<dyn Source>> {
    Ok(Arc::new(GitHubSource::open(base_url, options, host)?))
}

/// The same, reading each artifact's repository and tags through `names`.
fn open_named(
    base_url: &str,
    options: &Options,
    names: NameMap,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Source>> {
    Ok(Arc::new(
        GitHubSource::open(base_url, options, host)?.naming(names),
    ))
}
