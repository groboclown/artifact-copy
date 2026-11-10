//! One artifact's turn in the walk: resolved, screened, visited, and its
//! dependencies queued.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::summary::Tally;

use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::core::problem::{Action, Code};
use crate::core::progress::Unit;
use crate::message;
use crate::model::{ArtifactRequest, Cause, DepKind, ResolvedArtifact};
use crate::repo::Source;

use super::{Depth, Pending, Pushed, RootTotal, Seen, Spider, Ticket, Walk};

impl Spider {
    /// Queue tasks, applying the depth limit first.
    ///
    /// The limit is checked once the children are known, not before they
    /// are asked for. Stopping earlier would save a `deps` call per leaf and
    /// cost the ability to tell a truncated walk from a finished one --
    /// which is the difference between a report that can be trusted and
    /// one that cannot.
    pub(super) async fn enqueue(
        &self,
        tasks: impl Iterator<Item = Pending>,
        walk: &Walk<'_>,
        tally: &Tally,
    ) -> Result<()> {
        let mut queued = 0u64;
        let mut duplicates = 0u64;

        // Roots the caller already counted: never added to the total again,
        // but still advanced when they are found done or dropped.
        let mut promised_done = 0u64;

        for task in tasks {
            let promised = task.depth == 0 && self.roots == RootTotal::Promised;

            // Not counted into the total: discarded work that was promised
            // would leave the bar permanently short of its own end.
            if task.depth > self.max_depth {
                tally.beyond_depth.fetch_add(1, Ordering::SeqCst);
                tally.pruned.fetch_add(1, Ordering::SeqCst);
                continue;
            }

            match (walk.frontier.push(task).await?, promised) {
                (Pushed::Queued, false) => queued += 1,
                (Pushed::Queued, true) => {}
                (Pushed::Duplicate, false) => duplicates += 1,

                (Pushed::Duplicate, true) => {
                    tally.already_seen.fetch_add(1, Ordering::SeqCst);
                    promised_done += 1;
                }

                (Pushed::Full, promised) => {
                    tally.overflowed.fetch_add(1, Ordering::SeqCst);
                    tally.pruned.fetch_add(1, Ordering::SeqCst);

                    if promised {
                        promised_done += 1;
                    }
                }
            }
        }

        // A duplicate is work looked at and found done, so it is promised
        // and advanced at once, as a claim lost at resolution would be.
        tally.already_seen.fetch_add(duplicates, Ordering::SeqCst);
        walk.progress.grow_total(queued + duplicates);
        walk.progress.advance(duplicates + promised_done);

        Ok(())
    }

    /// Whether the artifacts at this depth have their edges read at all.
    ///
    /// Distinct from the depth limit, which is applied to the children
    /// afterwards. Stopping *here* means the user asked for nothing more;
    /// stopping at the limit means the walk was truncated, and only the
    /// second is worth reporting.
    pub(super) fn may_descend(&self, depth: usize) -> bool {
        if self.spec.is_empty() {
            return false;
        }

        match self.spec.depth() {
            // Direct dependencies of the roots, and no further. Not a
            // truncation: it is exactly what `shallow` asked for.
            Depth::Shallow => depth == 0,
            Depth::Deep => true,
        }
    }

    /// Resolve one artifact, emit it, and return the edges to follow.
    ///
    /// Wraps [`Spider::descend_from`] so that progress is advanced on every
    /// path out of it -- a skip and an already-seen are work done, and a bar
    /// that counted only successes would never reach its total.
    ///
    /// `None` children means the task was cut short by a stop.
    pub(super) async fn process(
        &self,
        ticket: Ticket,
        task: Pending,
        walk: &Walk<'_>,
        ctx: &Ctx,
        tally: &Tally,
    ) -> Result<(Ticket, Option<Vec<Pending>>)> {
        // A child node names what is being worked on right now. Its total
        // is unknown -- resolution is a couple of requests, not a
        // measurable quantity -- so it renders as an activity line rather
        // than a bar. Dropping it at the end of this scope closes it.
        let working =
            walk.progress
                .child(format!("resolve {}", task.request.id), Unit::Items, None);

        // The run's context under the task's own chain, which is exactly
        // what a dependency's context is: `Ctx::child` replaces only the
        // provenance.
        let task_ctx = ctx.rooted(Arc::clone(&task.request.prov));
        let descend = self.may_descend(task.depth);

        // Raced against the stop signal rather than merely checked before
        // it: a task can sit in a multi-megabyte fetch, and waiting that
        // out would make Ctrl-C feel broken. Losing the race drops the
        // future, which closes the connection instead of draining it.
        let outcome = tokio::select! {
            outcome = self.descend_from(ticket, &task, &task_ctx, descend, walk, tally) => {
                outcome.map(Some)
            }

            () = ctx.cancelled() => Ok(None),
        };

        drop(working);

        // Advanced even when the task was cut short: the progress total
        // promised this artifact, so leaving it uncounted would strand the
        // bar short of its own end at exactly the moment a user is
        // watching it shut down.
        walk.progress.advance(1);

        outcome.map(|children| (ticket, children))
    }

    pub(super) async fn descend_from(
        &self,
        ticket: Ticket,
        task: &Pending,
        task_ctx: &Ctx,
        descend: bool,
        walk: &Walk<'_>,
        tally: &Tally,
    ) -> Result<Vec<Pending>> {
        // Opened before resolution, not after: a rule about a version can
        // only match once a version is chosen, and choosing happens inside
        // `resolve`. Starting the list here is what lets what resolution
        // found and what the dependency read found land in one record.
        let collecting = task_ctx.collecting();
        let ctx = &collecting;

        let artifact = match walk.source.resolve(&task.request, self.criteria, ctx).await {
            Ok(artifact) => artifact,

            Err(err) => {
                if task_ctx.is_aborted() {
                    return Err(err);
                }

                // An unresolvable request arrives with its diagnosis already
                // recorded, so it is acted on rather than recorded again.
                // Anything else, such as an unreachable host, was recorded by
                // nobody and is recorded here.
                let problem = match &err {
                    Error::Unresolvable { problem, .. } => (**problem).clone(),
                    _ => task_ctx.reported_err(&err),
                };

                if problem.action() == Action::Abort {
                    return Err(err);
                }

                // Told to the visitor, not merely counted. A request that
                // resolved to nothing is exactly what somebody auditing a
                // run afterwards is looking for, and the request does not
                // outlive this frame.
                walk.visitor
                    .unresolved(&task.request, &problem, ctx)
                    .await?;

                tally.skipped.fetch_add(1, Ordering::SeqCst);

                return Ok(Vec::new());
            }
        };

        // Claimed on the **resolved** coordinate, not the request. Two
        // requests can name one artifact -- `[1.0,2.0)` and `1.5` may both
        // land on 1.5 -- and keying on the request would walk that subtree
        // twice. The losing claimant's resolution was not wasted work: it
        // was served from the source's cache.
        if walk.visited.mark(&artifact.purl(), ticket).await? == Seen::Already {
            tally.already_seen.fetch_add(1, Ordering::SeqCst);

            return Ok(Vec::new());
        }

        // Narrowed to the artifact now that the version is known, which
        // is what makes a per-artifact quarantine rule apply at all: until
        // a version is chosen there is nothing for `pkg:npm/tuna@<2` to
        // match against. Everything below -- the visit, the dependency
        // read -- reports under it.
        let about = collecting.for_artifact(artifact.id.clone(), artifact.version.clone());

        // Judged before the refusal is read, because a forbidden license is
        // one of the things that refuses: `license-forbidden` is
        // `skip-artifact`, so reporting it here is what makes the check
        // below drop the artifact and prune its subtree. The verdict rides
        // on the context either way, so a report can say what was decided
        // even when the decision was to allow.
        //
        // Before the call is built, because the call borrows the context
        // this replaces.
        let about = self.judged(&artifact, about, walk);
        let about = screened(&artifact, about, walk);
        let ctx = &about;

        if let Some(why) = about.refusal() {
            walk.visitor.refused(&artifact, &why, ctx).await?;
            tally.refused.fetch_add(1, Ordering::SeqCst);

            return Ok(Vec::new());
        }

        walk.visitor.visit(&artifact, walk.source, ctx).await?;
        tally.emitted.fetch_add(1, Ordering::SeqCst);

        if !descend {
            return Ok(Vec::new());
        }

        self.children(&artifact, task.depth + 1, walk, ctx, tally)
            .await
    }

    /// Evaluate the license policy, report what it found, and carry the
    /// verdict on the context.
    ///
    /// The problem is reported under the **narrowed** context, so a
    /// per-artifact quarantine rule can excuse a forbidden license for one
    /// artifact exactly as it can excuse anything else.
    pub(super) fn judged(&self, artifact: &ResolvedArtifact, about: Ctx, walk: &Walk<'_>) -> Ctx {
        let Some(policy) = walk.licenses else {
            return about;
        };

        let verdict = policy.evaluate(&artifact.purl(), artifact.license.as_deref());

        // Only when the policy had something to say. An allowed artifact
        // with nothing odd about it raises no problem, and a report that
        // recorded one per artifact would bury the ones that matter.
        if let Some(code) = verdict.problem {
            about.report(code, verdict.reason.clone());
        }

        about.judged(verdict)
    }

    /// The dependency edges of one artifact, as tasks at `depth`.
    pub(super) async fn children(
        &self,
        artifact: &ResolvedArtifact,
        depth: usize,
        walk: &Walk<'_>,
        ctx: &Ctx,
        tally: &Tally,
    ) -> Result<Vec<Pending>> {
        let wanted = self.wanted_kinds(&artifact.id, walk.source, ctx)?;

        if wanted.is_empty() {
            return Ok(Vec::new());
        }

        let deps = match walk.source.deps(artifact, ctx).await {
            Ok(deps) => deps,

            Err(err) => {
                // Losing an artifact's dependency list prunes its subtree
                // but keeps the artifact: it was resolved and emitted, and
                // dropping it now would lose work already done and already
                // reported.
                let action = ctx.report_err(&err);

                if action == Action::Abort {
                    return Err(err);
                }

                tally.pruned.fetch_add(1, Ordering::SeqCst);

                return Ok(Vec::new());
            }
        };

        // Checked after the read, not before the visit, because the only
        // code that says "stop descending" -- an unsupported POM profile --
        // is reported while reading the dependencies. Asking any earlier
        // would always find nothing and read as though it worked.
        //
        // Stopping still follows `build` edges: a profile cannot change the
        // parent POM, and without it the artifact's own POM cannot be read.
        let stopped = ctx.stops_spider();

        if stopped {
            tally.pruned.fetch_add(1, Ordering::SeqCst);
        }

        Ok(deps
            .into_iter()
            .filter(|dep| wanted.contains(&dep.kind))
            .filter(|dep| !stopped || dep.kind == DepKind::Build)
            .map(|dep| Pending {
                request: ArtifactRequest {
                    id: dep.id,
                    spec: dep.spec,
                    prov: ctx.prov().child(Cause::Dependency {
                        of: artifact.id.clone(),
                        version: artifact.version.clone(),
                        kind: dep.kind,
                    }),
                },
                depth,
            })
            .collect())
    }

    /// Which dependency kinds to follow for this artifact's ecosystem.
    ///
    /// `all` means "this ecosystem's union", which is why it resolves here
    /// and not at parse time: `test` exists only for Maven and `peer` only
    /// for npm.
    pub(super) fn wanted_kinds(
        &self,
        id: &crate::model::ArtifactId,
        source: &dyn Source,
        ctx: &Ctx,
    ) -> Result<BTreeSet<DepKind>> {
        let supported = source.ecosystem(id)?.dep_kinds();

        // A kind this ecosystem does not publish is said out loud.
        // Returning nothing would read as "this package has no test
        // dependencies", which is a different and wrong answer.
        for kind in self.spec.unsupported(supported) {
            ctx.report(
                Code::ConfigInvalid,
                message!(
                    "spider-unsupported-dep-kind",
                    "{ecosystem} publishes no {kind} dependencies, so none can be \
                     followed for {purl}",
                    ecosystem = id.ecosystem(),
                    kind = kind.as_str(),
                    purl = id.purl(),
                ),
            );
        }

        Ok(self.spec.resolve(supported))
    }
}

/// Screen an artifact against the corpora, report what they found, and carry
/// the findings on the context.
///
/// Beside the license verdict and before the refusal is read, for the same
/// reason: `malware-known` and `advisory-version-unusable` are
/// `skip-artifact`, so reporting them here is what drops the artifact and
/// prunes its subtree.
///
/// Only a versioned artifact is screened. An advisory is about versions,
/// and a raw file has none to place.
pub(super) fn screened(artifact: &ResolvedArtifact, about: Ctx, walk: &Walk<'_>) -> Ctx {
    let (Some(screen), Some(version)) = (walk.screen, artifact.version.as_ref()) else {
        return about;
    };

    // Asked of the source, so screening orders versions exactly as
    // resolution did. Reported rather than skipped: an artifact that could
    // not be screened must not read as a clean one.
    let handler = match walk.source.version_handler(&artifact.id) {
        Ok(handler) => handler,

        Err(err) => {
            about.report_err(&err);
            return about;
        }
    };

    let flags = screen.artifact(&artifact.id, version, handler, walk.security, &about);

    about.screened(flags)
}
