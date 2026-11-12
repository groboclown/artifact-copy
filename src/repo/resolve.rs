//! Picking one version, and explaining when none will do.
//!
//! [`Source::resolve`](super::Source::resolve) is a default method, and
//! this is its body. It lives here because it is the most subtle piece of
//! logic in resolution and a reader of `trait Source` should be reading an
//! interface, not an algorithm.
//!
//! # Why it steps down rather than selecting once
//!
//! "Highest **acceptable** version" is two questions asked at two
//! different moments. The version specification can be checked against the
//! version list; a publish window cannot, because the publish time arrives
//! with the metadata -- *after* a version has been picked. So a version that
//! turns out to be too recent is dropped from the candidate list and the
//! next newest is tried.
//!
//! The loop is bounded, and the bound is a cost statement: each step is a
//! metadata fetch, which for npm is a cache hit and for Maven is a request.
//!
//! # A quarantine rule may excuse the window
//!
//! The window stays a *criterion* rather than becoming a quarantine
//! finding: [`Criteria::old_enough`] answers the same question it always
//! did, and nothing about what the window *is* has changed. What changed is
//! that the answer is no longer the last word. A version inside the window
//! reports `publish-too-recent`, and **the disposition that comes back
//! decides whether to step down**. A per-artifact rule saying `allowed`
//! therefore takes the version.
//!
//! This reuses the quarantine file as the bypass channel rather than
//! growing a second per-artifact mechanism beside it, which is a deliberate
//! trade: the two are categorically different -- one is a rule a version
//! must satisfy, the other a reservation about a version -- and one
//! reviewable file of per-artifact exceptions is worth more than the
//! separation.
//!
//! The case it exists for: Log4Shell is disclosed, `2.15.0` is published to
//! patch it, and a team decides to take that one artifact before the window
//! has run because the thing the window protects against is less dangerous
//! than the thing being patched. That is a judgement about one artifact,
//! with a written justification, which is exactly what the quarantine file
//! is for -- and it is not an argument for shortening the window for
//! everything.
//!
//! ## `allowed` and `soft` both take it, and differ afterwards
//!
//! Any class below `skip-artifact` excuses the window, which is two of the
//! four, and the difference is worth knowing before writing one:
//!
//! | Class | The artifact | In the quarantine list | Under `--harden` |
//! | --- | --- | --- | --- |
//! | `allowed` | taken | no | still taken |
//! | `soft` | taken | yes | refused again |
//!
//! `soft` is usually the one wanted: the artifact is copied *and* stays in
//! `ArtifactRecord.quarantine` for somebody to audit. `allowed` is the
//! stronger statement, for a team that wants the exception to hold even in
//! a run that hardens everything else. Both leave a `publish-too-recent`
//! problem line carrying the rule's justification.
//!
//! ## What it does not excuse
//!
//! Only the window. A pre-release is excluded by `--pre-release` rather than
//! by a finding, so no rule here makes `2.15.0-rc1` a candidate -- that is a
//! question about the *request*, not a reservation about an artifact.
//!
//! And because `publish-too-recent` and `publish-time-unknown` share a
//! `Code` -- the action is the same and the code drives the table -- a rule
//! naming `publish-too-recent` excuses both. For one named artifact that is
//! the reading somebody writing "take this one regardless of the window"
//! would expect; it is worth knowing it is what they get.

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::{Action, Code};
use crate::message;
use crate::model::{ArtifactRequest, ResolvedArtifact, Version, VersionSpec};
use crate::version::{PreRelease, VersionHandler};

use super::{Criteria, Source};

/// How many versions a resolution will step down through.
///
/// Each step costs a metadata fetch, which for npm is a cache hit and for
/// Maven is a request. A repository whose recent releases are all inside
/// the publish window should say so rather than walking its whole history.
const MAX_STEP_DOWN: usize = 8;

/// The step-down loop behind [`Source::resolve`](super::Source::resolve).
///
/// Generic over `?Sized` so a `&dyn Source` can call it: the trait is used
/// as `Arc<dyn Source>` everywhere, and a plain `&impl Source` argument
/// would quietly make `resolve` undispatchable.
pub(super) async fn resolve<S: Source + ?Sized>(
    source: &S,
    request: &ArtifactRequest,
    criteria: Criteria,
    ctx: &Ctx,
) -> Result<ResolvedArtifact> {
    // A repository that declares it has no versions has nothing to select
    // between, so there is no step-down: one artifact, taken or refused.
    // Asking `versions` first and finding one empty list would conflate
    // "there are none" with "this artifact is not here", and the second is
    // a 404 that belongs to `metadata`.
    if !source.versioned(&request.id) {
        let about = ctx.for_artifact(request.id.clone(), None);
        let ctx = &about;

        let artifact = source.metadata(&request.id, None, ctx).await?;

        return match window(&artifact, request, None, criteria, ctx) {
            true => Ok(artifact),

            // No next candidate to try, so the exhaustion message would be
            // a lie about what was searched. The window refused the only
            // thing there is.
            false => {
                let message = message!(
                    "versionless-window-refused",
                    "the configured publish window refused {purl}, and a repository \
                         with no versions has no older one to step down to",
                    purl = request.id.purl(),
                );

                let detail = message.render();
                let problem = ctx.reported(Code::VersionUnresolvable, message);

                Err(Error::Unresolvable {
                    artifact: request.id.purl(),
                    detail,
                    problem: Box::new(problem),
                })
            }
        };
    }

    // The configured handler when the source has one, and the artifact's
    // ecosystem otherwise. Selection is the only thing this needs from
    // either, and selection is exactly what a version convention decides.
    let versions = source.version_handler(&request.id)?;
    let request = &respecified(request, versions);
    let mut candidates = candidates(source, request, versions, criteria, ctx).await?;

    for _ in 0..MAX_STEP_DOWN {
        let Some(chosen) = versions.select(&request.spec, &candidates, criteria.pre) else {
            return Err(unresolvable(request, versions, &candidates, criteria, ctx));
        };

        // Narrowed to the candidate before its metadata is read, because
        // everything from here on is about *that version*: a signature it
        // carries, the window it falls inside. A per-artifact rule naming
        // `@<2` cannot match until a version has been chosen, and the
        // choice happens here rather than in the caller.
        let about = ctx.for_artifact(request.id.clone(), Some(chosen.clone()));
        let ctx = &about;

        let artifact = source.metadata(&request.id, Some(&chosen), ctx).await?;

        if window(&artifact, request, Some(&chosen), criteria, ctx) {
            return Ok(artifact);
        }

        // Dropped rather than remembered separately, which keeps the
        // next `select` a plain call on a shorter list.
        candidates.retain(|candidate| candidate != &chosen);
    }

    let message = message!(
        "publish-window-exhausted",
        "no version of {purl} within the last {tried} candidates is old \
             enough for the configured publish window",
        purl = request.id.purl(),
        tried = MAX_STEP_DOWN,
    );

    let detail = message.render();
    let problem = ctx.reported(Code::PublishTooRecent, message);

    Err(Error::Unresolvable {
        artifact: request.id.purl(),
        detail,
        problem: Box::new(problem),
    })
}

/// The request with an exact version re-read under the source's handler.
///
/// The ecosystem parsed the request, and raw reads every `@x` as exact. A
/// source whose versions are semver means `tool@24` as the newest `24.x.y`,
/// and `tool@24.1.0` stays exact. A registry ecosystem parsed with the
/// handler's own rules already, so re-reading changes nothing there --
/// **provided** every handler reads an `Exact`'s text back as `Exact`.
/// PEP 440 strips `==` on the first read, so its `version_spec` must take
/// a bare version as exact too; `version::tests::exact_text_reads_back_exact`
/// holds every handler to it.
fn respecified(request: &ArtifactRequest, versions: &dyn VersionHandler) -> ArtifactRequest {
    let VersionSpec::Exact(text) = &request.spec else {
        return request.clone();
    };

    ArtifactRequest {
        spec: versions.version_spec(text),
        ..request.clone()
    }
}

/// The versions to select from: for an exact request, the version itself
/// where the source confirms it directly; otherwise the source's list, and
/// for an exact request the list cannot satisfy, the version itself where
/// the source confirms it exists.
///
/// A missing list is no answer to an exact request either, since a stale
/// index may be absent as well as incomplete; the source's error stands
/// only when the version cannot be confirmed.
async fn candidates<S: Source + ?Sized>(
    source: &S,
    request: &ArtifactRequest,
    versions: &dyn VersionHandler,
    criteria: Criteria,
    ctx: &Ctx,
) -> Result<Vec<Version>> {
    let VersionSpec::Exact(text) = &request.spec else {
        return source.versions(&request.id, ctx).await;
    };

    // Narrowed to the version, as the step-down loop narrows to its
    // candidate: confirming may read what `metadata` reads next, and its
    // findings belong to that version.
    let about = ctx.for_artifact(request.id.clone(), Some(versions.version(text)));

    if let Some(found) = source.confirmed(&request.id, text, &about).await? {
        return Ok(vec![found]);
    }

    let listed = source.versions(&request.id, ctx).await;

    let (mut candidates, missing) = match listed {
        Ok(candidates) => (candidates, None),
        Err(err) if err.code() == Code::ArtifactNotFound => (Vec::new(), Some(err)),
        Err(err) => return Err(err),
    };

    if versions
        .select(&request.spec, &candidates, criteria.pre)
        .is_some()
    {
        return Ok(candidates);
    }

    match (source.unlisted(&request.id, text, ctx).await?, missing) {
        (Some(found), _) => candidates.push(found),

        // Unconfirmed, so a missing list reports as it always did.
        (None, Some(err)) => return Err(err),
        (None, None) => {}
    }

    Ok(candidates)
}

/// Whether the publish window accepts this artifact.
///
/// Shared by the two paths above rather than written twice, because the
/// quarantine bypass is the subtle part: the disposition is read rather than
/// discarded, and it is asked **once**. Asking a second time would evaluate
/// the rule's expiry again, and a long run crossing it would then refuse a
/// window it had just excused.
///
/// `version` is `None` for a repository that declares none, and the messages
/// then name the versionless purl -- `{purl}@` would read as a version that
/// is blank rather than absent.
fn window(
    artifact: &ResolvedArtifact,
    request: &ArtifactRequest,
    version: Option<&Version>,
    criteria: Criteria,
    ctx: &Ctx,
) -> bool {
    if criteria.old_enough(artifact.published) {
        return true;
    }

    let purl = match version {
        Some(version) => request.id.purl_at(version.text()),
        None => request.id.purl(),
    };

    // Two different facts, and a user debugging a skipped artifact needs to
    // know which: the version is genuinely too new, or the repository does
    // not say when it was published and the window therefore cannot be
    // satisfied at all.
    //
    // Neither message says what happens next, and that is deliberate: the
    // disposition below decides, so a message predicting a step-down would
    // be wrong exactly when a rule excused the window.
    let message = match artifact.published {
        Some(published) => message!(
            "publish-too-recent",
            "{purl} was published {published}, which is inside the configured \
                 publish window",
            purl = &purl,
            published = &published.to_rfc3339(),
        ),

        None => message!(
            "publish-time-unknown",
            "{purl} has no publish time, so it cannot be shown to satisfy the \
                 configured publish window. Set unknown-publish-time to allow \
                 if this repository never reports one",
            purl = &purl,
        ),
    };

    // Excused for this artifact, and the problem stays recorded either way,
    // so the report carries a `publish-too-recent` line naming the rule and
    // its justification. An artifact taken on an acknowledgement is visible
    // nowhere else.
    ctx.report(Code::PublishTooRecent, message) < Action::SkipArtifact
}

/// Report, and describe, a request nothing satisfies.
pub(super) fn unresolvable(
    request: &ArtifactRequest,
    versions: &dyn VersionHandler,
    candidates: &[Version],
    criteria: Criteria,
    ctx: &Ctx,
) -> Error {
    // Suggest --pre-release only when it would actually have helped.
    // A range like `^5.0.0` excludes `5.0.0-rc.1` on its own terms,
    // not because pre-releases were filtered, and telling someone to
    // retry with a flag that changes nothing wastes their time.
    let would_help = criteria.pre == PreRelease::Exclude
        && versions
            .select(&request.spec, candidates, PreRelease::Include)
            .is_some();

    let hint = if would_help {
        "; try --pre-release"
    } else {
        ""
    };

    let message = message!(
        "version-unresolvable",
        "no version of {purl} satisfies {spec}{hint}",
        purl = request.id.purl(),
        spec = &request.spec,
        hint = hint,
    );

    let detail = message.render();
    let problem = ctx.reported(Code::VersionUnresolvable, message);

    Error::Unresolvable {
        artifact: request.id.purl(),
        detail,
        problem: Box::new(problem),
    }
}
