//! The PyPI index.
//!
//! Two endpoints, used for different things:
//!
//! - **`/simple/{name}/`** with the PEP 691 JSON `Accept` header gives every
//!   version, every file, its hashes, its size and its upload time. One
//!   request, and it is the endpoint PyPI asks integrators to use.
//! - **`/pypi/{name}/{version}/json`** gives the license, which the simple
//!   index does not carry.
//!
//! Dependencies come from PEP 658: when a file advertises `core-metadata`,
//! `GET {file.url}.metadata` returns the `METADATA` without downloading the
//! wheel. That is the cheap path and the one to prefer.
//!
//! References: [PEP 658](https://peps.python.org/pep-0658/), [PEP 691](https://peps.python.org/pep-0691/).

use std::sync::Arc;

use self::simple::SimpleIndex;
use super::kind::{EnumeratorKind, Kinds, SourceKind, TargetKind};
use super::{Source, Target};
use crate::core::ctx::Ctx;
use crate::core::error::Result;
use crate::ext::{ExtHost, Options};
use crate::model::EcosystemId;
use crate::net::{ByteLimit, Req};

mod attestation;
mod core_metadata;
mod detail;
mod enumerator;
mod metadata;
pub(crate) mod pep503;
mod sdist;
mod simple;
mod source;
mod target;
mod wheel;

pub use enumerator::PyPiEnumerator;
pub use source::PyPiSource;
pub use target::{LegacyDists, PyPiTarget};

/// The kinds this server offers.
pub(super) const KINDS: Kinds = Kinds {
    source: Some(SourceKind::new("pypi", open_source)),
    target: Some(TargetKind {
        name: "pypi",
        open: open_target,
    }),
    enumerators: &[
        EnumeratorKind::new("pypi-simple", open_enumerator).native_for(EcosystemId::PYPI)
    ],
};

/// The index at `base_url`, checking attestations against `trust`'s
/// Sigstore root.
fn open_source(
    base_url: &str,
    _options: &Options,
    host: Arc<dyn ExtHost>,
    trust: super::Trust,
) -> Result<Arc<dyn Source>> {
    Ok(Arc::new(
        PyPiSource::new(base_url, host).with_sigstore(trust.sigstore),
    ))
}

/// Uploading to the index at `base_url`.
fn open_target(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn Target>> {
    Ok(Arc::new(PyPiTarget::open(base_url, options, host)?))
}

/// Walking the index's project list.
fn open_enumerator(
    base_url: &str,
    options: &Options,
    host: Arc<dyn ExtHost>,
) -> Result<Arc<dyn super::enumerate::Enumerator>> {
    Ok(Arc::new(PyPiEnumerator::open(base_url, options, host)?))
}

/// The PEP 691 content negotiation header.
///
/// Without it the index answers HTML, which would mean parsing anchors for
/// data the JSON form states outright.
const SIMPLE_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// A project's `/simple/` document.  Large for a package with a long
/// history, but nothing like a packument.
const SIMPLE_LIMIT: ByteLimit = ByteLimit::mib(32);

/// A PEP 658 `.metadata` sidecar: RFC 822 headers, not a wheel.
const METADATA_LIMIT: ByteLimit = ByteLimit::mib(4);

/// A project's simple index, in whichever form the server answers.
///
/// Shared by the source and the target, which read the same page.
async fn fetch_simple(host: &dyn ExtHost, url: &str, ctx: &Ctx) -> Result<SimpleIndex> {
    let req = Req::get(url).accept(SIMPLE_ACCEPT);
    let body = host.fetch(&req, SIMPLE_LIMIT, ctx).await?;

    parse_simple(&body, url)
}

/// A simple index page fetched from `url`, parsed.
fn parse_simple(body: &[u8], url: &str) -> Result<SimpleIndex> {
    SimpleIndex::parse(body).map_err(|detail| crate::core::error::Error::Malformed {
        what: "PyPI simple index",
        url: url.to_owned(),
        detail,
    })
}

/// Built distributions put the version in the second `-` field, after a
/// name that escapes its own `-`: `echo_lib-1.0-py3-none-any.whl`.
const BUILT_SUFFIXES: [&str; 2] = [".whl", ".egg"];

/// Source distributions end in the version, after a name that may keep its
/// `-`: `echo-lib-1.0.tar.gz`. bdist_dumb shares the suffixes and adds a
/// platform: `echo-1.0.linux-x86_64.tar.gz`.
const SDIST_SUFFIXES: [&str; 6] = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"];

/// Windows installers name the platform after the version:
/// `echo-1.0.win32.exe`, `echo-1.0.win-amd64-py3.8.msi`.
const INSTALLER_SUFFIXES: [&str; 2] = [".exe", ".msi"];

/// `{name}-{version}-{release}.{arch}.rpm`: `echo-1.0-1.noarch.rpm`.
const RPM_SUFFIX: &str = ".rpm";

/// Where a platform begins after the version, as distutils spells it. A
/// version never holds one, so the stem is cut at the first found.
const PLATFORM_MARKERS: [&str; 7] = [
    ".win32",
    ".win-amd64",
    ".win-arm64",
    ".linux-",
    ".macosx-",
    ".cygwin-",
    ".freebsd-",
];

/// The version a distribution filename carries, when it is a known kind.
///
/// Shared by the HTML index reader, which derives versions from names, and
/// by the source and target, which match files to a version. Comparing the
/// parsed field keeps `1.0` from claiming `1.0.1`, and a wheel's build tag
/// from claiming version `1`.
pub(crate) fn version_of(filename: &str) -> Option<&str> {
    let version = if let Some(stem) = strip_any(filename, &BUILT_SUFFIXES) {
        stem.split('-').nth(1)
    } else if let Some(stem) = strip_any(filename, &INSTALLER_SUFFIXES) {
        installer_version(stem)
    } else if let Some(stem) = filename.strip_suffix(RPM_SUFFIX) {
        rpm_version(stem)
    } else if let Some(stem) = strip_any(filename, &SDIST_SUFFIXES) {
        last_field(without_platform(stem))
    } else {
        None
    };

    version.filter(|version| !version.is_empty())
}

/// `filename` without the first of `suffixes` it ends in.
fn strip_any<'a>(filename: &'a str, suffixes: &[&str]) -> Option<&'a str> {
    suffixes
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))
}

/// `echo-1.0.win-amd64-py3.8`: an installer without a known platform is
/// not guessed at.
fn installer_version(stem: &str) -> Option<&str> {
    let cut = without_platform(stem);

    if cut.len() == stem.len() {
        return None;
    }

    last_field(cut)
}

/// `echo-1.0-1.noarch`: drop the arch, then the release.
fn rpm_version(stem: &str) -> Option<&str> {
    let (package, _arch) = stem.rsplit_once('.')?;
    let (name_version, _release) = package.rsplit_once('-')?;

    last_field(name_version)
}

/// `echo-1.0.linux-x86_64` is `echo-1.0`; a stem without a platform is
/// itself.
fn without_platform(stem: &str) -> &str {
    let at = PLATFORM_MARKERS
        .iter()
        .filter_map(|marker| stem.find(marker))
        .min();

    at.map_or(stem, |at| &stem[..at])
}

/// The field after the last `-`: `zope-interface-5.4.0` is `5.4.0`.
fn last_field(stem: &str) -> Option<&str> {
    stem.rsplit_once('-').map(|(_, version)| version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every distribution kind an index holds yields its version.
    #[test]
    fn version_of_each_kind() {
        let cases = [
            ("requests-2.31.0-py3-none-any.whl", Some("2.31.0")),
            ("pkg-1.0-1-py3-none-any.whl", Some("1.0")),
            ("pkg-1.0-py3.8.egg", Some("1.0")),
            ("pkg-1.0-py2.7-linux-x86_64.egg", Some("1.0")),
            ("pkg-1.0.tar.gz", Some("1.0")),
            ("pkg-1.0.tar.bz2", Some("1.0")),
            ("pkg-1.0.tar.xz", Some("1.0")),
            ("pkg-1.0.tgz", Some("1.0")),
            ("pkg-1.0.zip", Some("1.0")),
            ("pkg-1.0.tar", Some("1.0")),
            ("zope-interface-5.4.0.tar.gz", Some("5.4.0")),
            ("pkg-1.0.win32.exe", Some("1.0")),
            ("pkg-1.0.win-amd64-py3.8.msi", Some("1.0")),
            ("pkg-1.0-1.noarch.rpm", Some("1.0")),
            ("pkg-1.0.linux-x86_64.tar.gz", Some("1.0")),
            ("pkg-1.0.dmg", None),
            ("pkg-1.0.exe", None),
            ("pkg.tar.gz", None),
        ];

        for (filename, expected) in cases {
            assert_eq!(version_of(filename), expected, "{filename}");
        }
    }

    /// `1.0` must not claim `1.0.1`, nor a wheel's build tag version `1`.
    #[test]
    fn version_of_only_own() {
        assert_ne!(version_of("requests-2.31.01.tar.gz"), Some("2.31.0"));
        assert_ne!(version_of("requests-2.31.0.tar.gz"), Some("2.31"));
        assert_ne!(version_of("pkg-1.0-1-py3-none-any.whl"), Some("1"));
    }
}
