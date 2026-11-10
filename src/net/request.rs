//! What a request is: its method, URL, headers, and body or form parts.

use std::path::Path;

/// HTTP methods this tool issues.
///
/// `HEAD` earns its place: it is how a Maven publish timestamp is read
/// without pulling the artifact.
///
/// `POST` earns its place too, and only just -- reading a repository ought
/// to be a matter of `GET`. But a repository manager's query language is a
/// document, not a path: Artifactory's AQL is a query body sent to one
/// endpoint, and there is no `GET` that enumerates a repository with its
/// download statistics. A search that happens to be spelled as a `POST` is
/// still a read, and the alternative is a request per artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,

    /// Replace a resource. What a registry's publish endpoint takes.
    Put,
}

/// One request.
#[derive(Debug, Clone)]
pub struct Req {
    pub url: String,
    pub method: Method,

    /// Extra headers.  Registries key content negotiation off `Accept`:
    /// PyPI's PEP 691 JSON and npm's abbreviated packument both live there.
    pub headers: Vec<(String, String)>,

    /// The request body, for the methods that carry one.
    ///
    /// Bounded by construction: the only bodies this tool sends are query
    /// documents it wrote itself, so there is no call site where this could
    /// grow with the size of a repository.
    pub body: Option<String>,
}

impl Req {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: Method::Get,
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn head(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: Method::Head,
            headers: Vec::new(),
            body: None,
        }
    }

    /// A query sent as a body.
    ///
    /// For a search endpoint that takes a document rather than a path. It
    /// is still a read: nothing in this tool posts in order to change
    /// anything, and `copy` will upload through the `Target` trait rather
    /// than through here.
    pub fn post(url: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: Method::Post,
            headers: Vec::new(),
            body: Some(body.into()),
        }
    }

    /// Replace a resource, with the body supplied separately.
    ///
    /// The body is **not** carried on the request: a publish body can be
    /// the size of the artifact, and [`Req::body`] is documented as bounded
    /// by construction. An upload names a file instead -- see
    /// [`HttpClient::send_file`](super::HttpClient::send_file).
    pub fn put(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: Method::Put,
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn accept(mut self, value: impl Into<String>) -> Self {
        self.headers.push(("accept".into(), value.into()));
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// One field of a `multipart/form-data` request.
///
/// The two shapes `curl -F` takes: `name=value` writes a literal, and
/// `name=@file` sends a file's contents. A registry upload is usually a
/// handful of the first and exactly one of the second.
///
/// Borrowed rather than owned because a caller builds these immediately
/// before sending and nothing keeps them -- and because a `File` part must
/// not carry the bytes, only the path. The file is **streamed** when the
/// request is sent, so a multi-gigabyte payload never lands in memory.
#[derive(Debug, Clone)]
pub enum FormPart<'a> {
    /// `name=value`.
    Text { name: &'a str, value: &'a str },

    /// `name=@path`, streamed from disk.
    File {
        name: &'a str,
        path: &'a Path,

        /// The name the server is told, which need not be the name on
        /// disk. A file is kept under whatever name was convenient; a
        /// registry wants the artifact's own.
        filename: Option<&'a str>,

        content_type: Option<&'a str>,
    },
}

impl<'a> FormPart<'a> {
    /// `curl -F name=value`.
    pub fn text(name: &'a str, value: &'a str) -> Self {
        Self::Text { name, value }
    }

    /// `curl -F name=@path`.
    pub fn file(name: &'a str, path: &'a Path) -> Self {
        Self::File {
            name,
            path,
            filename: None,
            content_type: None,
        }
    }

    /// Tell the server a different filename from the one on disk.
    pub fn named(mut self, as_name: &'a str) -> Self {
        if let Self::File { filename, .. } = &mut self {
            *filename = Some(as_name);
        }

        self
    }

    pub fn typed(mut self, mime: &'a str) -> Self {
        if let Self::File { content_type, .. } = &mut self {
            *content_type = Some(mime);
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_header_recorded() {
        let req =
            Req::get("h://example.test/simple/x/").accept("application/vnd.pypi.simple.v1+json");

        assert_eq!(req.method, Method::Get);
        assert_eq!(req.headers[0].0, "accept");
    }
}
