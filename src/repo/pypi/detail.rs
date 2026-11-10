//! What `/pypi/{name}/{version}/json` returns.
//!
//! Consulted only for what the simple index does not carry: the license,
//! and the static dependency list when no PEP 658 sidecar was advertised.
//!
//! The license arrives three ways, in descending order of trust, and all
//! three are kept because most projects still supply only the weakest:
//! `license_expression` is real SPDX (PEP 639) and null for most projects
//! even now, a `License ::` classifier is a fixed vocabulary, and `license`
//! is free text that ranges from `MIT` to an entire license body.
//!
//! References: [PEP 639](https://peps.python.org/pep-0639/), [SPDX license expressions](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/).

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct Detail {
    pub(super) info: DetailInfo,
}

#[derive(Debug, Deserialize)]
pub(super) struct DetailInfo {
    /// PEP 639.  Real SPDX, and null for most projects even now.
    #[serde(default)]
    pub(super) license_expression: Option<String>,

    /// Free text: anything from `MIT` to a whole license body.
    #[serde(default)]
    pub(super) license: Option<String>,

    #[serde(default)]
    pub(super) classifiers: Vec<String>,

    /// `None` means no static metadata at all, which is different from an
    /// empty list meaning no dependencies.
    #[serde(default)]
    pub(super) requires_dist: Option<Vec<String>>,
}
