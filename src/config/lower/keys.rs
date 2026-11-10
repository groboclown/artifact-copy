//! The configuration keys lowering reads and writes.

pub(super) const SERVERS: &str = "servers";
pub(super) const REPOSITORIES: &str = "repositories";
pub(super) const SETUP: &str = "setup";
pub(super) const SERVER_KINDS_DIR: &str = "server-kinds-dir";
pub(super) const OVERRIDE_TEMPLATE: &str = "override-template";

pub(super) const KIND: &str = "kind";
pub(super) const URL: &str = "url";
pub(super) const NAME: &str = "name";
pub(super) const SERVER: &str = "server";
pub(super) const ACCESS: &str = "access";
pub(super) const VALUES: &str = "values";
pub(super) const AUTHENTICATION: &str = "authentication";
pub(super) const INSECURE_TRANSPORT: &str = "insecure-transport";
pub(super) const RETRY: &str = "retry";
pub(super) const ON_STATUS: &str = "on-status";
pub(super) const HOST: &str = "host";
pub(super) const DEFAULT_REPOSITORY: &str = "default-repository";

/// What a server template may render.
pub(super) const SERVER_KEYS: [&str; 3] = [HOST, ACCESS, DEFAULT_REPOSITORY];
