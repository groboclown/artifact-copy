//! Small answers every repository adapter gives the same way, for a
//! `Source` or `Target` implementation to reuse.

use crate::core::error::{Error, Result};
use crate::ecosystem::Ecosystem;
use crate::model::{ArtifactId, Version};

/// The version a registry adapter was handed, or an error saying it needs
/// one.
///
/// Every adapter in this crate but the raw one answers [`Source::versioned`](super::Source::versioned)
/// with true, so `None` here means a caller asked npm or Maven to resolve an
/// artifact with no version -- incoherent, and a bug in whatever composed
/// them. Saying so beats the alternatives on offer: inventing a version, or
/// publishing `publish-lodash-.json`.
pub fn version_required<'v>(id: &ArtifactId, version: Option<&'v Version>) -> Result<&'v Version> {
    version.ok_or_else(|| Error::BadRequest {
        ecosystem: "repository",
        text: id.purl(),
        detail: "this repository's artifacts have versions, and none was given".to_owned(),
    })
}

/// A source that speaks exactly one ecosystem.
///
/// The common case: every registry adapter in this crate.  A repository
/// manager implements [`Source::ecosystem`](super::Source::ecosystem) directly instead.
pub fn sole_ecosystem<'e>(
    ecosystem: &'e dyn Ecosystem,
    id: &ArtifactId,
) -> Result<&'e dyn Ecosystem> {
    let spoken = ecosystem.id();

    if id.ecosystem() != &spoken {
        return Err(Error::UnknownKind {
            collection: "ecosystem for this source",
            kind: id.ecosystem().to_string(),
        });
    }

    Ok(ecosystem)
}
