//! Redirects, recognized here and followed by the capability.
//!
//! A client never follows one itself. Whether the next hop may be reached,
//! and with whose credentials, is the capability's question -- see
//! [`crate::ext::HostedExt`] -- so a client reports a redirect as
//! [`Error::Redirected`] and leaves it there.

use http::StatusCode;

use crate::core::error::{Error, Result};

/// The redirect `status` and `location` describe, if they describe one.
///
/// A redirect status with no `Location` is not a redirect anybody can
/// follow, so it is left to the caller's ordinary status handling. `304 Not
/// Modified` is not a redirect at all.
pub(crate) fn redirected(url: &str, status: StatusCode, location: Option<&str>) -> Option<Error> {
    let redirect = matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    );

    match (redirect, location) {
        (true, Some(location)) => Some(Error::Redirected {
            url: url.to_owned(),
            status,
            location: location.to_owned(),
        }),

        _ => None,
    }
}

/// Whether a redirect with `status` repeats the request as it was sent.
///
/// Only 307 and 308 promise that. The others let a client switch to `GET`,
/// which for an upload would silently drop the body.
pub(crate) fn keeps_method(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT
    )
}

/// The absolute URL `location` names, relative to `url`.
///
/// `Location` may be relative: `/b` from `https://h.test/a` is
/// `https://h.test/b`.
pub(crate) fn target(url: &str, location: &str) -> Result<String> {
    let malformed = |detail: String| Error::Malformed {
        what: "redirect location",
        url: url.to_owned(),
        detail,
    };

    let base = ::url::Url::parse(url).map_err(|source| malformed(source.to_string()))?;
    let joined = base
        .join(location)
        .map_err(|source| malformed(format!("{location:?}: {source}")))?;

    Ok(joined.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_relative_resolves_against_request() {
        assert_eq!(
            target("https://h.test/repository/a/x.jar", "/repository/b/x.jar").expect("joined"),
            "https://h.test/repository/b/x.jar"
        );
    }

    #[test]
    fn location_absolute_replaces_request() {
        assert_eq!(
            target("https://github.com/o/r", "https://codeload.github.com/o/r").expect("joined"),
            "https://codeload.github.com/o/r"
        );
    }

    #[test]
    fn redirect_excludes_not_modified() {
        assert!(redirected("https://h.test/", StatusCode::NOT_MODIFIED, Some("/x")).is_none());
    }

    #[test]
    fn redirect_without_location_not_followable() {
        assert!(redirected("https://h.test/", StatusCode::FOUND, None).is_none());
    }

    #[test]
    fn redirect_only_307_and_308_keep_method() {
        assert!(keeps_method(StatusCode::TEMPORARY_REDIRECT));
        assert!(keeps_method(StatusCode::PERMANENT_REDIRECT));
        assert!(!keeps_method(StatusCode::FOUND));
        assert!(!keeps_method(StatusCode::SEE_OTHER));
    }
}
