//! Streaming integrity verification.
//!
//! Hashes are computed as bytes arrive, so nothing buffers a whole artifact
//! in order to check it afterwards.  This is *integrity* only -- whether the
//! bytes match what was declared.  Whether the artifact is known-malicious is
//! a separate question with a separate answer, and the advisory extension
//! point that will answer it is not built yet.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};

use crate::core::error::{Error, Result};
use crate::model::{Digest, DigestAlg};

/// What a download is expected to be.
///
/// An empty expectation verifies nothing and succeeds, which is correct for
/// the many registry responses that declare no checksum at all.
#[derive(Debug, Clone, Default)]
pub struct Expectation {
    size: Option<u64>,
    digests: Vec<Digest>,
}

impl Expectation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_digest(mut self, digest: Digest) -> Self {
        self.digests.push(digest);
        self
    }

    pub fn with_digests(mut self, digests: impl IntoIterator<Item = Digest>) -> Self {
        self.digests.extend(digests);
        self
    }

    /// Whether there is anything at all to check.
    pub fn is_empty(&self) -> bool {
        self.size.is_none() && self.digests.is_empty()
    }

    /// Start verifying a stream against this expectation.
    pub fn verifier(&self) -> Verifier {
        Verifier::new(self.clone())
    }
}

/// Accumulates a stream and checks it against an [`Expectation`].
///
/// Only the algorithms actually expected are computed, so a file declaring
/// one sha256 does not pay for four hashers.
pub struct Verifier {
    expect: Expectation,
    seen: u64,
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("expect", &self.expect)
            .field("seen", &self.seen)
            .finish()
    }
}

impl Verifier {
    fn new(expect: Expectation) -> Self {
        let wants = |alg: DigestAlg| expect.digests.iter().any(|d| d.alg == alg);

        Self {
            md5: wants(DigestAlg::Md5).then(Md5::default),
            sha1: wants(DigestAlg::Sha1).then(Sha1::default),
            sha256: wants(DigestAlg::Sha256).then(Sha256::default),
            sha512: wants(DigestAlg::Sha512).then(Sha512::default),
            expect,
            seen: 0,
        }
    }

    /// Feed the next chunk.
    pub fn update(&mut self, chunk: &[u8]) {
        self.seen += chunk.len() as u64;

        if let Some(h) = &mut self.md5 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha512 {
            h.update(chunk);
        }
    }

    /// How many bytes have been seen.
    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// Check the completed stream.  Consumes the verifier: a partial check
    /// is meaningless, so there is no way to ask for one.
    pub fn finish(self) -> Result<()> {
        if let Some(expected) = self.expect.size
            && expected != self.seen
        {
            return Err(Error::Integrity(format!(
                "expected {expected} bytes, received {}",
                self.seen
            )));
        }

        let actual = Actual {
            md5: self.md5.map(|h| hex::encode(h.finalize())),
            sha1: self.sha1.map(|h| hex::encode(h.finalize())),
            sha256: self.sha256.map(|h| hex::encode(h.finalize())),
            sha512: self.sha512.map(|h| hex::encode(h.finalize())),
        };

        for expected in &self.expect.digests {
            let computed = actual
                .get(expected.alg)
                .ok_or_else(|| Error::Integrity(format!("{} was not computed", expected.alg)))?;

            if computed != expected.hex {
                return Err(Error::Integrity(format!(
                    "{} mismatch: expected {}, computed {computed}",
                    expected.alg, expected.hex
                )));
            }
        }

        Ok(())
    }
}

/// Computed hashes, one per algorithm that was asked for.
struct Actual {
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
}

impl Actual {
    fn get(&self, alg: DigestAlg) -> Option<&str> {
        match alg {
            DigestAlg::Md5 => self.md5.as_deref(),
            DigestAlg::Sha1 => self.sha1.as_deref(),
            DigestAlg::Sha256 => self.sha256.as_deref(),
            DigestAlg::Sha512 => self.sha512.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sha256("abc")`, from the FIPS 180-4 test vectors.
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";

    fn verify(expect: Expectation, body: &[u8]) -> Result<()> {
        let mut v = expect.verifier();
        v.update(body);
        v.finish()
    }

    #[test]
    fn digest_matching_passes() {
        let expect = Expectation::new().with_digest(Digest::new(DigestAlg::Sha256, ABC_SHA256));

        assert!(verify(expect, b"abc").is_ok());
    }

    #[test]
    fn body_corrupted_fails() {
        let expect = Expectation::new().with_digest(Digest::new(DigestAlg::Sha256, ABC_SHA256));

        let err = verify(expect, b"abd").unwrap_err();

        assert_eq!(err.code(), crate::core::problem::Code::ChecksumMismatch);
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn body_truncated_fails_on_size() {
        let expect = Expectation::new().with_size(3);

        let err = verify(expect, b"ab").unwrap_err();

        assert!(err.to_string().contains("expected 3 bytes, received 2"));
    }

    /// Chunk boundaries must not change the result.
    #[test]
    fn chunking_does_not_affect_hash() {
        let expect = Expectation::new().with_digest(Digest::new(DigestAlg::Sha256, ABC_SHA256));

        let mut v = expect.verifier();
        v.update(b"a");
        v.update(b"b");
        v.update(b"c");

        assert!(v.finish().is_ok());
    }

    #[test]
    fn algorithms_several_all_checked() {
        let expect = Expectation::new().with_size(3).with_digests([
            Digest::new(DigestAlg::Sha256, ABC_SHA256),
            Digest::new(DigestAlg::Sha1, ABC_SHA1),
        ]);

        assert!(verify(expect, b"abc").is_ok());
    }

    /// Upper-case hex in a registry response must still match.
    #[test]
    fn expectation_hex_case_normalized() {
        let expect = Expectation::new()
            .with_digest(Digest::new(DigestAlg::Sha256, ABC_SHA256.to_uppercase()));

        assert!(verify(expect, b"abc").is_ok());
    }

    /// Most registry responses declare nothing; that must not be an error.
    #[test]
    fn expectation_empty_verifies_anything() {
        assert!(Expectation::new().is_empty());
        assert!(verify(Expectation::new(), b"whatever").is_ok());
    }
}
