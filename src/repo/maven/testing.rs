//! Fixtures and signing helpers shared by the Maven tests.
//!
//! Keys are generated per test rather than embedded, so a test exercises
//! the whole path -- parse a key, parse a signature, verify -- instead of
//! asserting against a blob nobody can check by eye. Ed25519 keeps
//! generation to microseconds.

use pgp::composed::{
    DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails as _, Password};

use crate::core::ctx::Ctx;
use crate::ext::testing::Fixture;
use crate::model::{ArtifactId, ArtifactRequest, Cause, EcosystemId, VersionSpec};
use crate::net::sig::RegistryKey;
use crate::net::{Canned, FixtureClient};

use super::MavenSource;
pub(super) use super::metadata::SAMPLE as METADATA;

/// A real signing key.
pub(super) fn signing_key() -> SignedSecretKey {
    SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Maven Signer <signer@example.test>".into())
        .passphrase(None)
        .build()
        .expect("params")
        .generate(rand::thread_rng())
        .expect("generated")
}

/// An armored detached signature over `payload`, as a `.asc` holds.
pub(super) fn detached_signature(secret: &SignedSecretKey, payload: impl AsRef<[u8]>) -> String {
    DetachedSignature::sign_binary_data(
        rand::thread_rng(),
        &secret.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        payload.as_ref(),
    )
    .expect("signed")
    .to_armored_string(Default::default())
    .expect("armored")
}

/// The public half of `secret`, pinned as a configured key would be.
pub(super) fn public_key_of(secret: &SignedSecretKey) -> RegistryKey {
    RegistryKey::pinned(
        hex::encode(secret.primary_key.fingerprint().as_bytes()),
        SignedPublicKey::from(secret.clone())
            .to_armored_string(Default::default())
            .expect("armored"),
    )
}

// A small repository: lib 1.0 and 1.10 under one parent POM.

pub(super) const REPO: &str = "h://repo.test/maven2";
pub(super) const DIR: &str = "h://repo.test/maven2/org/example/lib";

pub(super) const LIB_POM: &str = r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
      <parent>
        <groupId>org.example</groupId>
        <artifactId>parent</artifactId>
        <version>5.0</version>
      </parent>
      <artifactId>lib</artifactId>
      <properties><guava.version>32.1.3-jre</guava.version></properties>
      <dependencies>
        <dependency>
          <groupId>com.google.guava</groupId>
          <artifactId>guava</artifactId>
          <version>${guava.version}</version>
        </dependency>
        <dependency>
          <groupId>org.slf4j</groupId>
          <artifactId>slf4j-api</artifactId>
        </dependency>
        <dependency>
          <groupId>junit</groupId>
          <artifactId>junit</artifactId>
          <version>4.13.2</version>
          <scope>test</scope>
        </dependency>
        <dependency>
          <groupId>local</groupId>
          <artifactId>thing</artifactId>
          <version>1.0</version>
          <scope>system</scope>
        </dependency>
      </dependencies>
    </project>"#;

pub(super) const PARENT_POM: &str = r#"<project>
      <groupId>org.example</groupId>
      <artifactId>parent</artifactId>
      <version>5.0</version>
      <packaging>pom</packaging>
      <licenses>
        <license>
          <name>Apache License, Version 2.0</name>
          <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
        </license>
      </licenses>
      <dependencyManagement><dependencies>
        <dependency>
          <groupId>org.slf4j</groupId>
          <artifactId>slf4j-api</artifactId>
          <version>2.0.9</version>
        </dependency>
      </dependencies></dependencyManagement>
    </project>"#;

pub(super) fn client() -> FixtureClient {
    FixtureClient::new()
        .with_body(format!("{DIR}/maven-metadata.xml"), METADATA)
        .with_body(format!("{DIR}/1.0/lib-1.0.pom"), LIB_POM)
        .with_body(
            format!("{REPO}/org/example/parent/5.0/parent-5.0.pom"),
            PARENT_POM,
        )
        .with(
            format!("{DIR}/1.0/lib-1.0.jar"),
            Canned::ok("").header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
        )
        .with_body(format!("{DIR}/1.10/lib-1.10.pom"), LIB_POM)
        .with_body(format!("{DIR}/1.10/lib-1.10.jar"), "")
}

pub(super) fn fixture_from(client: FixtureClient) -> Fixture<MavenSource> {
    Fixture::build(client, |host| MavenSource::new(REPO, host))
}

pub(super) fn fixture() -> Fixture<MavenSource> {
    fixture_from(client())
}

pub(super) fn ctx() -> Ctx {
    Ctx::for_test(Cause::Requested {
        arg: "org.example:lib:1.0".into(),
    })
}

pub(super) fn id() -> ArtifactId {
    ArtifactId::new(EcosystemId::maven(), Some("org.example"), "lib")
}

pub(super) fn exact(text: &str, ctx: &Ctx) -> ArtifactRequest {
    ArtifactRequest {
        id: id(),
        spec: VersionSpec::Exact(text.into()),
        prov: ctx.prov().clone(),
    }
}
