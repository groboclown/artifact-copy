//! Turning a raw repository's paths into coordinates.
//!
//! A raw repository holds files under a path and nothing else. There is no
//! group, no version, no metadata document -- Nexus and Artifactory both
//! offer one, and what it means is entirely up to whoever uploads into it.
//!
//! So the coordinate scheme is the **user's** to declare, and this is where
//! that declaration is applied. Everything here is pure: a path goes in and
//! a coordinate comes out, with no repository involved, which is what makes
//! the rules testable against the paths a person actually has.
//!
//! # Why not a regular expression
//!
//! The mapping this is wanted for is usually written as
//! `^(.*?)/([^/]+)/([^/]+)$` -- name, version, file name. Read again, that
//! is not a pattern: it is "split off the last two segments", which needs
//! no engine and cannot be written wrong. A genuinely irregular layout will
//! want a real expression one day, and that can be a third variant when
//! somebody has one; adding a regex dependency to express a `rsplit` would
//! be paying for generality nobody has asked for.

use crate::core::error::{Error, Result};

/// How a raw repository's paths become coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mapping {
    /// Each directory is an artifact and the files in it are its files.
    ///
    /// The basic reading, and the one that matches how people actually use
    /// a raw repository: `tools/cli/1.2.0/cli.tar.gz` and
    /// `tools/cli/1.2.0/cli.tar.gz.sha256` are two files of one artifact.
    ///
    /// **A sub-directory is a different artifact**, not part of its parent.
    /// `a/b` and `a/b/c` are two, which is what keeps a deep tree from
    /// collapsing into one artifact holding everything beneath it.
    ///
    /// **Versioning is meaningless here**, and saying so is the point: a
    /// directory has no version to resolve, and inventing one from a path
    /// segment would make `copy` choose between files that are not versions
    /// of each other.
    #[default]
    Directory,

    /// Every file is its own artifact, named by its whole path.
    ///
    /// For a repository where neighbouring files are unrelated -- a backup
    /// dump, a share -- and grouping them would publish a release nobody
    /// assembled.
    AsIs,

    /// `.../name/version/file`, which is how most people lay one out.
    ///
    /// The name is everything before the last two segments, so
    /// `tools/acme/cli/1.2.0/cli.tar.gz` is `tools/acme/cli` at `1.2.0`.
    /// A path with fewer than three segments does not fit and is reported
    /// rather than forced.
    NameVersionFile,
}

impl Mapping {
    pub fn as_str(self) -> &'static str {
        match self {
            Mapping::Directory => "directory",
            Mapping::AsIs => "as-is",
            Mapping::NameVersionFile => "name-version-file",
        }
    }

    /// Every spelling, for an error that names the alternatives.
    pub fn names() -> &'static [&'static str] {
        &["directory", "as-is", "name-version-file"]
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text.trim() {
            "directory" => Ok(Mapping::Directory),
            "as-is" => Ok(Mapping::AsIs),
            "name-version-file" => Ok(Mapping::NameVersionFile),

            other => Err(Error::UnknownKind {
                collection: "raw repository path mapping",
                kind: other.to_owned(),
            }),
        }
    }

    /// Read one repository path as a coordinate.
    ///
    /// `None` when the path does not fit the declared layout. Not an error:
    /// a raw repository holds whatever somebody put in it, and one stray
    /// file at the root must not fail a walk of a million that are laid out
    /// correctly. The caller reports it and moves on.
    pub fn read(self, path: &str) -> Option<Coordinate> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            return None;
        }

        match self {
            // The directory the file sits in. A file at the **root** has no
            // directory to share, so it is its own artifact -- the root is
            // not a directory anybody named, and dropping the file instead
            // would lose it from a migration silently.
            //
            // Reachable, though only through one door: Nexus refuses a
            // component upload with no directory, and accepts a plain PUT
            // to the repository root. Measured, not assumed.
            Mapping::Directory => Some(Coordinate {
                name: match path.rsplit_once('/') {
                    Some((directory, _)) => directory.to_owned(),
                    None => path.to_owned(),
                },
                version: None,
                file: path.rsplit('/').next().unwrap_or(path).to_owned(),
            }),

            Mapping::AsIs => Some(Coordinate {
                name: path.to_owned(),
                version: None,
                file: path.rsplit('/').next().unwrap_or(path).to_owned(),
            }),

            Mapping::NameVersionFile => {
                let (rest, file) = path.rsplit_once('/')?;
                let (name, version) = rest.rsplit_once('/')?;

                // A leading segment is the name, so all three have to be
                // there. `acme/1.0/x.tgz` has no name left once the version
                // and the file are taken off it.
                if name.is_empty() || version.is_empty() || file.is_empty() {
                    return None;
                }

                Some(Coordinate {
                    name: name.to_owned(),
                    version: Some(version.to_owned()),
                    file: file.to_owned(),
                })
            }
        }
    }

    /// Rebuild the path one coordinate names.
    ///
    /// The inverse of [`Mapping::read`], for a target that has to decide
    /// where to put a file. Round-tripping is what keeps a copy from
    /// landing an artifact somewhere the next artifact enumeration will not
    /// recognize.
    pub fn path(self, at: &Coordinate) -> String {
        match (self, &at.version) {
            // A root-level file names itself, so joining would double it.
            (Mapping::Directory, _) if at.name == at.file => at.file.clone(),
            (Mapping::Directory, _) => format!("{}/{}", at.name, at.file),

            (Mapping::AsIs, _) => at.name.clone(),
            (Mapping::NameVersionFile, None) => format!("{}/{}", at.name, at.file),

            (Mapping::NameVersionFile, Some(version)) => {
                format!("{}/{version}/{}", at.name, at.file)
            }
        }
    }
}

/// What a repository path says about the artifact it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coordinate {
    /// The artifact's name, which for a raw repository is a path fragment
    /// rather than a registry identifier.
    pub name: String,

    /// `None` under a mapping that declares there are no versions.
    pub version: Option<String>,

    /// The file's own name, which is what gets published.
    pub file: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(mapping: Mapping, path: &str) -> Option<(String, Option<String>, String)> {
        mapping.read(path).map(|at| (at.name, at.version, at.file))
    }

    /// **The basic reading.** Files in one directory are one artifact's
    /// files; a sub-directory is a different artifact rather than part of
    /// its parent.
    #[test]
    fn directory_is_one_artifact_with_own_files() {
        let group = |path| read(Mapping::Directory, path);

        assert_eq!(
            group("tools/cli/1.2.0/cli.tar.gz"),
            Some(("tools/cli/1.2.0".to_owned(), None, "cli.tar.gz".to_owned()))
        );

        // Two files in one directory share a name, which is what makes them
        // one artifact's files.
        assert_eq!(
            group("tools/cli/1.2.0/cli.tar.gz.sha256").map(|at| at.0),
            Some("tools/cli/1.2.0".to_owned())
        );

        // A sub-directory is its own artifact, not part of the one above.
        assert_ne!(
            group("a/b/x.tgz").map(|at| at.0),
            group("a/b/c/y.tgz").map(|at| at.0)
        );
    }

    /// A file at the repository root has no directory to share. It is its
    /// own artifact rather than being dropped, because losing a file from a
    /// migration silently is the worse answer.
    #[test]
    fn root_file_is_own_artifact() {
        assert_eq!(
            read(Mapping::Directory, "readme.txt"),
            Some(("readme.txt".to_owned(), None, "readme.txt".to_owned()))
        );

        let at = Mapping::Directory.read("readme.txt").expect("read");

        assert_eq!(Mapping::Directory.path(&at), "readme.txt");
    }

    /// The layout most people have, and the one the mapping exists for.
    #[test]
    fn name_version_file_splits_from_right() {
        assert_eq!(
            read(Mapping::NameVersionFile, "tools/acme/cli/1.2.0/cli.tar.gz"),
            Some((
                "tools/acme/cli".to_owned(),
                Some("1.2.0".to_owned()),
                "cli.tar.gz".to_owned()
            ))
        );

        // The shortest path that fits: one name segment, one version, one
        // file.
        assert_eq!(
            read(Mapping::NameVersionFile, "acme/1.0/x.tgz"),
            Some((
                "acme".to_owned(),
                Some("1.0".to_owned()),
                "x.tgz".to_owned()
            ))
        );
    }

    /// A raw repository holds whatever somebody put in it, so a path that
    /// does not fit is a finding rather than a failure. One stray file must
    /// not fail a walk of a million laid out correctly.
    #[test]
    fn path_misfit_not_error() {
        for path in ["readme.txt", "acme/x.tgz", "", "/", "///"] {
            assert_eq!(read(Mapping::NameVersionFile, path), None, "{path:?}");
        }
    }

    /// **Versioning is meaningless as-is**, and saying so is the point: a
    /// version invented from a filename would make a copy choose between
    /// files that are not versions of each other.
    #[test]
    fn as_is_names_whole_path_without_version() {
        assert_eq!(
            read(Mapping::AsIs, "tools/acme/cli/1.2.0/cli.tar.gz"),
            Some((
                "tools/acme/cli/1.2.0/cli.tar.gz".to_owned(),
                None,
                "cli.tar.gz".to_owned()
            ))
        );

        assert_eq!(
            read(Mapping::AsIs, "readme.txt"),
            Some(("readme.txt".to_owned(), None, "readme.txt".to_owned()))
        );
    }

    /// A copy has to put a file back where the next artifact enumeration
    /// will find it.
    #[test]
    fn coordinate_rebuilds_own_path() {
        let paths = [
            (Mapping::Directory, "tools/acme/cli/1.2.0/cli.tar.gz"),
            (Mapping::Directory, "readme.txt"),
            (Mapping::NameVersionFile, "tools/acme/cli/1.2.0/cli.tar.gz"),
            (Mapping::NameVersionFile, "acme/1.0/x.tgz"),
            (Mapping::AsIs, "tools/acme/cli/1.2.0/cli.tar.gz"),
            (Mapping::AsIs, "readme.txt"),
        ];

        for (mapping, path) in paths {
            let at = mapping.read(path).expect(path);

            assert_eq!(mapping.path(&at), path, "{mapping:?} {path}");
        }
    }

    /// Leading and trailing separators are noise: Nexus reports a path with
    /// a leading slash and Artifactory without one, and the same file must
    /// not read as two artifacts depending on which answered.
    #[test]
    fn separators_surrounding_keep_coordinate() {
        let bare = read(Mapping::NameVersionFile, "acme/1.0/x.tgz");

        assert_eq!(read(Mapping::NameVersionFile, "/acme/1.0/x.tgz"), bare);
        assert_eq!(read(Mapping::NameVersionFile, "acme/1.0/x.tgz/"), bare);
    }

    #[test]
    fn every_name_parses_back_to_its_value() {
        for name in Mapping::names() {
            assert_eq!(Mapping::parse(name).expect(name).as_str(), *name);
        }

        assert!(Mapping::parse("regex").is_err());
    }
}
