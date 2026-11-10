//! A target that never receives what its `omit` rules leave out.
//!
//! The files are fetched and verified as usual, since a source may need
//! them to check the rest, and are dropped only at the upload: a target
//! that refuses a repository's own checksum files never sees them.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use super::Omit;
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ecosystem::{Companion, Ecosystem};
use crate::model::{ArtifactId, ResolvedArtifact, Version};
use crate::repo::{Companions, Delivery, Target};

pub struct OmittingTarget {
    inner: Arc<dyn Target>,
    omit: Omit,
}

impl OmittingTarget {
    pub fn new(inner: Arc<dyn Target>, omit: Omit) -> Self {
        Self { inner, omit }
    }
}

#[async_trait]
impl Target for OmittingTarget {
    fn ecosystem(&self, id: &ArtifactId) -> Result<&dyn Ecosystem> {
        self.inner.ecosystem(id)
    }

    async fn exists(&self, id: &ArtifactId, version: Option<&Version>, ctx: &Ctx) -> Result<bool> {
        self.inner.exists(id, version, ctx).await
    }

    fn declines(&self, companion: Companion) -> bool {
        self.inner.declines(companion)
    }

    fn omitted(&self, artifact: &ResolvedArtifact) -> Option<String> {
        self.omit.artifact(&artifact.id, artifact.version.as_ref())
    }

    /// The artifact less what these rules leave out, each file with its
    /// staged path. A whole artifact is decided earlier, by
    /// [`Target::omitted`], so a refusal is never graded as a failed copy.
    async fn publish(
        &self,
        artifact: &ResolvedArtifact,
        files: &[PathBuf],
        companions: &Companions,
        delivery: &mut Delivery,
        ctx: &Ctx,
    ) -> Result<()> {
        let version = artifact.version.as_ref();

        let paired: Vec<_> = artifact
            .files
            .iter()
            .cloned()
            .zip(files.iter().cloned())
            .collect();
        let kept = self.omit.retain(
            &artifact.id,
            version,
            paired,
            |(file, _)| file.name.as_str(),
            ctx,
        );

        let (kept_files, kept_paths): (Vec<_>, Vec<_>) = kept.into_iter().unzip();

        let sent = ResolvedArtifact {
            files: kept_files,
            ..artifact.clone()
        };

        self.inner
            .publish(&sent, &kept_paths, companions, delivery, ctx)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::config::OmitRule;
    use crate::core::problem::Code;
    use crate::model::{Cause, EcosystemId, FileRef, Release};

    /// Records what it was asked to publish.
    #[derive(Default)]
    struct Recording {
        sent: Mutex<Vec<(String, PathBuf)>>,
    }

    #[async_trait]
    impl Target for Recording {
        fn ecosystem(&self, _id: &ArtifactId) -> Result<&dyn Ecosystem> {
            Ok(&crate::ecosystem::Raw)
        }

        async fn exists(&self, _: &ArtifactId, _: Option<&Version>, _: &Ctx) -> Result<bool> {
            Ok(false)
        }

        async fn publish(
            &self,
            artifact: &ResolvedArtifact,
            files: &[PathBuf],
            _companions: &Companions,
            _delivery: &mut Delivery,
            _ctx: &Ctx,
        ) -> Result<()> {
            let mut sent = self.sent.lock().expect("unpoisoned");

            for (file, path) in artifact.files.iter().zip(files) {
                sent.push((file.name.clone(), path.clone()));
            }

            Ok(())
        }
    }

    fn artifact() -> ResolvedArtifact {
        ResolvedArtifact {
            id: ArtifactId::new(EcosystemId::raw(), None, "tools/cli"),
            version: Some(Version::new("1.0", Release::General)),
            files: ["cli.tar.gz", "cli.tar.gz.sha256", "README"]
                .iter()
                .map(|name| FileRef::new(*name, format!("h://source.test/{name}")))
                .collect(),
            license: None,
            published: None,
        }
    }

    fn omitting(rules: serde_json::Value) -> (OmittingTarget, Arc<Recording>) {
        let rules: Vec<OmitRule> = serde_json::from_value(rules).expect("rules");
        let recording = Arc::new(Recording::default());
        let target = OmittingTarget::new(recording.clone(), Omit::parse(&rules).expect("parses"));

        (target, recording)
    }

    fn ctx() -> Ctx {
        Ctx::for_test(Cause::Requested { arg: "cli".into() })
    }

    /// Fetched and verified, then never sent, each file beside its own
    /// staged path.
    #[tokio::test]
    async fn omitted_file_not_sent() {
        let (target, recording) = omitting(serde_json::json!([{ "files": "*.sha256" }]));
        let paths: Vec<PathBuf> = ["a", "b", "c"].iter().map(PathBuf::from).collect();
        let ctx = ctx();

        target
            .publish(
                &artifact(),
                &paths,
                &Companions::default(),
                &mut Delivery::default(),
                &ctx,
            )
            .await
            .expect("published");

        assert_eq!(
            *recording.sent.lock().expect("unpoisoned"),
            [
                ("cli.tar.gz".to_owned(), PathBuf::from("a")),
                ("README".to_owned(), PathBuf::from("c")),
            ]
        );
        assert_eq!(ctx.problems().counts()[&Code::FileOmitted], 1);
    }

    /// Decided before the publish, so copy can record a refusal rather
    /// than a failed upload.
    #[test]
    fn omitted_artifact_named() {
        let (target, _) = omitting(serde_json::json!([{ "purl": "pkg:raw/tools*" }]));

        assert!(target.omitted(&artifact()).is_some());

        let (target, _) = omitting(serde_json::json!([{ "files": "*.sha256" }]));

        assert!(target.omitted(&artifact()).is_none());
    }
}
