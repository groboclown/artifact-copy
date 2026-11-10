//! The collections lowering writes, and the roles and access a repository
//! asks for.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::config::model::{Enumerator, Host, Source, Target};

/// A low-level collection lowering may add to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Collection {
    Hosts,
    Sources,
    Targets,
    Enumerators,
}

impl Collection {
    pub(super) const ALL: [Collection; 4] = [
        Collection::Hosts,
        Collection::Sources,
        Collection::Targets,
        Collection::Enumerators,
    ];

    pub(super) fn key(self) -> &'static str {
        match self {
            Collection::Hosts => "hosts",
            Collection::Sources => "sources",
            Collection::Targets => "targets",
            Collection::Enumerators => "enumerators",
        }
    }

    pub(super) fn singular(self) -> &'static str {
        match self {
            Collection::Hosts => "host",
            Collection::Sources => "source",
            Collection::Targets => "target",
            Collection::Enumerators => "enumerator",
        }
    }

    /// Whether `entry` deserializes as this collection's type, so a bad
    /// template is reported against the template rather than the merge.
    pub(super) fn check(self, entry: &Value) -> std::result::Result<(), String> {
        let entry = entry.clone();

        let result = match self {
            Collection::Hosts => serde_json::from_value::<Host>(entry).map(drop),
            Collection::Sources => serde_json::from_value::<Source>(entry).map(drop),
            Collection::Targets => serde_json::from_value::<Target>(entry).map(drop),
            Collection::Enumerators => serde_json::from_value::<Enumerator>(entry).map(drop),
        };

        result.map_err(|err| err.to_string())
    }
}

/// What a repository may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Access {
    Read,
    Write,
}

/// A repository's access, as written: `read`, `write`, or `read-write`.
pub(super) fn parse_access(text: &str) -> Option<BTreeSet<Access>> {
    match text {
        "read" => Some(BTreeSet::from([Access::Read])),
        "write" => Some(BTreeSet::from([Access::Write])),
        "read-write" => Some(BTreeSet::from([Access::Read, Access::Write])),
        _ => None,
    }
}

/// The spelling [`parse_access`] reads, for a template's context.
pub(super) fn access_text(access: &BTreeSet<Access>) -> &'static str {
    match (
        access.contains(&Access::Read),
        access.contains(&Access::Write),
    ) {
        (true, true) => "read-write",
        (false, true) => "write",
        _ => "read",
    }
}

/// One role a repository's template may fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Role {
    Source,
    Target,
    Enumerator,
}

impl Role {
    pub(super) const ALL: [Role; 3] = [Role::Source, Role::Target, Role::Enumerator];

    pub(super) fn key(self) -> &'static str {
        self.collection().singular()
    }

    pub(super) fn collection(self) -> Collection {
        match self {
            Role::Source => Collection::Sources,
            Role::Target => Collection::Targets,
            Role::Enumerator => Collection::Enumerators,
        }
    }

    pub(super) fn access(self) -> Access {
        match self {
            Role::Target => Access::Write,
            Role::Source | Role::Enumerator => Access::Read,
        }
    }
}
