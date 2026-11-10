//! Where a coordinate's files sit in the Maven layout, and what they are
//! named.
//!
//! References: [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

use super::MavenSource;
use super::metadata::Snapshot;
use crate::core::error::{Error, Result};
use crate::ecosystem::maven::CLASSIFIER_QUALIFIER;
use crate::model::{ArtifactId, FileRef, Version};

/// Packaging whose artifact *is* the POM, with no separate payload.
pub(super) const POM_PACKAGING: &str = "pom";

/// The longest a path segment may be.
///
/// Well past any real version; short enough that a corrupt index cannot
/// build a megabyte-long URL.
const MAX_SEGMENT: usize = 256;

/// Whether a file belongs to the repository rather than to an artifact.
///
/// The rule lives with the ecosystem, because an enumerator listing a version
/// directory needs it too; see [`crate::ecosystem::maven::is_repository_file`].
pub(super) fn is_repository_managed(name: &str) -> bool {
    crate::ecosystem::maven::is_repository_file(name)
}

/// Whether a coordinate part is safe to build a URL from.
///
/// Repositories carry genuinely corrupt index entries -- a version listed as
/// `1.0 / maven-metadata.xml` is real, and so are entries with embedded
/// newlines. Beyond being nonsense, a segment containing a slash escapes
/// the artifact's directory, so this is a traversal guard as much as a
/// tidiness one.
pub(super) fn is_safe_segment(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_SEGMENT
        && text != "."
        && text != ".."
        && !text.contains('/')
        && !text.contains('\\')
        && !text.contains('?')
        && !text.contains('#')
        && !text.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

impl MavenSource {
    /// `org.apache.commons` becomes `org/apache/commons`.
    pub(super) fn group_path(group: &str) -> String {
        group.replace('.', "/")
    }

    /// The directory holding every version of one artifact.
    pub(super) fn artifact_dir(&self, group: &str, artifact: &str) -> String {
        format!("{}/{}/{artifact}", self.base_url, Self::group_path(group))
    }

    /// The directory holding one version's files.
    pub(super) fn version_dir(&self, group: &str, artifact: &str, version: &str) -> String {
        format!("{}/{version}", self.artifact_dir(group, artifact))
    }

    /// `build` is the version the file is named with, which differs from
    /// `version` only for a timestamped snapshot.
    pub(super) fn pom_url(
        &self,
        group: &str,
        artifact: &str,
        version: &str,
        build: &str,
    ) -> String {
        format!(
            "{}/{artifact}-{build}.pom",
            self.version_dir(group, artifact, version)
        )
    }
    /// The group of an artifact, which Maven requires.
    ///
    /// A Maven coordinate without a group is not a coordinate, so this is
    /// an error rather than a lookup against an empty path.
    pub(super) fn group_of(id: &ArtifactId) -> Result<&str> {
        let group = id.namespace().ok_or_else(|| Error::BadRequest {
            ecosystem: "maven",
            text: id.purl(),
            detail: "a Maven artifact needs a groupId".to_owned(),
        })?;

        // A group becomes a directory path, so its dots are meaningful and
        // its slashes are not: one already containing a separator could
        // address anything in the repository.
        Self::safe(group, "groupId", id)?;
        Self::safe(id.name(), "artifactId", id)?;

        Ok(group)
    }

    /// Refuse a coordinate part that cannot safely become a URL segment.
    pub(super) fn safe(text: &str, what: &'static str, id: &ArtifactId) -> Result<()> {
        if is_safe_segment(text) {
            return Ok(());
        }

        Err(Error::BadRequest {
            ecosystem: "maven",
            text: id.purl(),
            detail: format!("the {what} {text:?} is not a usable path segment"),
        })
    }
    /// The files one version publishes, excluding every derived document.
    ///
    /// Always the POM, because Maven always publishes one and a consumer
    /// needs it. Plus the payload, unless the packaging *is* `pom`, in
    /// which case there is no separate payload to name twice.
    ///
    /// `maven-metadata.xml` is deliberately absent -- see the module
    /// documentation. So are the checksum sidecars, which `copy` fetches
    /// when it verifies, and the `.asc` signatures, which
    /// [`Source::metadata`] adds once it knows they exist.
    ///
    /// `build` names the files of a snapshot; see [`MavenSource::snapshot`].
    pub(super) fn files_of(
        &self,
        id: &ArtifactId,
        version: &Version,
        packaging: &str,
        build: &Snapshot,
    ) -> Result<Vec<FileRef>> {
        let group = Self::group_of(id)?;
        let artifact = id.name();
        let text = version.text();
        let dir = self.version_dir(group, artifact, text);

        let pom_build = build.value_for(text, None, POM_PACKAGING);
        let pom_name = format!("{artifact}-{pom_build}.pom");
        let mut files = vec![FileRef::new(&pom_name, format!("{dir}/{pom_name}"))];

        if packaging != POM_PACKAGING {
            let (classifier, extension) = payload_shape(id, packaging);
            let payload_build = build.value_for(text, classifier, extension);
            let name = file_name(artifact, &payload_build, classifier, extension);
            files.push(FileRef::new(&name, format!("{dir}/{name}")));
        }

        // The single enforcement point for "this belongs to the repository,
        // not to the artifact". Nothing constructed above should match it;
        // it is here so that the rule holds however these names come to be
        // built, rather than depending on the construction staying careful.
        files.retain(|file| !is_repository_managed(&file.name));

        Ok(files)
    }
}

/// The group, artifact, and version a layout directory names.
///
/// `org/apache/commons/commons-lang3/3.14.0` is `org.apache.commons`,
/// `commons-lang3`, `3.14.0`: the last two segments are the artifact and
/// version, and everything before them is the group with `/` for `.`.
/// `None` under three segments, which cannot name all three.
pub(in crate::repo) fn layout_of(directory: &str) -> Option<(String, &str, &str)> {
    let segments: Vec<&str> = directory
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    let [group @ .., artifact, version] = segments.as_slice() else {
        return None;
    };

    if group.is_empty() {
        return None;
    }

    Some((group.join("."), artifact, version))
}

/// The classifier and extension of the payload `id` names under
/// `packaging`: the type's own extension and implied classifier, which the
/// packaging names rather than is, with a classifier asked for winning.
///
/// Shared by the source naming a payload and the target looking for it, so
/// the two cannot disagree about which file an artifact's payload is.
pub(super) fn payload_shape<'a>(
    id: &'a ArtifactId,
    packaging: &'a str,
) -> (Option<&'a str>, &'a str) {
    let (extension, implied) = crate::ecosystem::maven::published_as(packaging);

    (id.qualifier(CLASSIFIER_QUALIFIER).or(implied), extension)
}

/// One file's name in a version directory.
///
/// `lib`, `1.0`, `sources`, `jar` is `lib-1.0-sources.jar`. `build` is the
/// version as the file spells it; see [`Snapshot::value_for`].
pub(super) fn file_name(
    artifact: &str,
    build: &str,
    classifier: Option<&str>,
    extension: &str,
) -> String {
    match classifier {
        Some(classifier) => format!("{artifact}-{build}-{classifier}.{extension}"),
        None => format!("{artifact}-{build}.{extension}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ext::testing::idle;

    use crate::repo::maven::testing::*;
    use crate::version::VersionHandler;

    use crate::ecosystem::maven::METADATA_DOCUMENT as METADATA_FILE;
    use crate::model::{ArtifactId, EcosystemId};

    use crate::repo::Source;
    use crate::repo::maven::MavenSource;

    #[test]
    fn layout_reads_group_artifact_version() {
        assert_eq!(
            layout_of("org/apache/commons/commons-lang3/3.14.0"),
            Some(("org.apache.commons".to_owned(), "commons-lang3", "3.14.0"))
        );
        assert_eq!(
            layout_of("/org/example/lib/1.0/"),
            Some(("org.example".to_owned(), "lib", "1.0"))
        );
    }

    #[test]
    fn layout_needs_three_segments() {
        assert_eq!(layout_of("lib/1.0"), None);
        assert_eq!(layout_of(""), None);
    }

    /// `maven-metadata.xml` belongs to the repository, not to any version
    /// in it. A target regenerates its own on upload, so copying a
    /// source's would advertise versions the target does not hold.
    #[tokio::test]
    async fn maven_metadata_never_artifact_file() {
        let f = fixture();
        let ctx = ctx();
        let version = f.subject.ecosystem.version("1.0");

        let artifact = f
            .subject
            .metadata(&id(), Some(&version), &ctx)
            .await
            .expect("read");

        assert!(
            !artifact
                .files
                .iter()
                .any(|file| file.name.contains(METADATA_FILE) || file.url.contains(METADATA_FILE)),
            "the discovery index must not be published as an artifact file: {:?}",
            artifact.files.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    /// It is still *read*, though -- inspection is its whole purpose.
    #[tokio::test]
    async fn maven_metadata_read_for_discovery() {
        let f = fixture();
        let ctx = ctx();

        f.subject.versions(&id(), &ctx).await.expect("read");

        assert_eq!(f.host.hits(&format!("{DIR}/maven-metadata.xml")), 1);
    }

    #[test]
    fn group_becomes_directory_path() {
        let source = MavenSource::new(REPO, idle());

        assert_eq!(
            source.artifact_dir("org.apache.commons", "commons-lang3"),
            "h://repo.test/maven2/org/apache/commons/commons-lang3"
        );
    }

    #[test]
    fn artifact_without_group_refused() {
        let groupless = ArtifactId::new(EcosystemId::maven(), None, "lib");

        let err = match MavenSource::group_of(&groupless) {
            Err(err) => err,
            Ok(_) => panic!("a Maven artifact needs a group"),
        };

        assert!(err.to_string().contains("groupId"));
    }

    #[test]
    fn path_segment_unusable_recognized() {
        assert!(is_safe_segment("1.0"));
        assert!(is_safe_segment("1.0-SNAPSHOT"));
        assert!(is_safe_segment("31.1-jre"));

        assert!(!is_safe_segment(""));
        assert!(!is_safe_segment("."));
        assert!(!is_safe_segment(".."));
        assert!(!is_safe_segment("1.0 / maven-metadata.xml"));
        assert!(!is_safe_segment("../../etc/passwd"));
        assert!(!is_safe_segment("a\\b"));
        assert!(!is_safe_segment("1.0\n"));
        assert!(!is_safe_segment("has space"));
        assert!(!is_safe_segment("q?x"));
        assert!(!is_safe_segment(&"x".repeat(MAX_SEGMENT + 1)));
    }

    /// A group or artifact carrying a separator could address anything in
    /// the repository, so it is refused before a URL is built.
    #[tokio::test]
    async fn coordinate_escaping_directory_refused() {
        let f = fixture();
        let ctx = ctx();

        let escaping = ArtifactId::new(EcosystemId::maven(), Some("org/../.."), "lib");

        assert!(f.subject.versions(&escaping, &ctx).await.is_err());
        assert!(f.host.requested().is_empty());
    }

    /// `_remote.repositories` records where one machine cached a file from.
    /// It describes a cache, not an artifact, and means nothing elsewhere.
    #[test]
    fn repository_managed_files_recognized() {
        assert!(is_repository_managed("maven-metadata.xml"));
        assert!(is_repository_managed("maven-metadata-central.xml"));
        assert!(is_repository_managed("maven-metadata-local.xml"));
        assert!(is_repository_managed("_remote.repositories"));
        assert!(is_repository_managed(
            "h://repo.test/x/_remote.repositories"
        ));

        assert!(!is_repository_managed("lib-1.0.jar"));
        assert!(!is_repository_managed("lib-1.0.pom"));
        assert!(!is_repository_managed("maven-metadata-tool-1.0.jar"));
    }
}
