//! Deciding a license expression against a policy: aliases, per-artifact
//! rules, and per-usage decisions.
//!
//! References: [SPDX license expressions](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/).

use crate::core::license::{Decision, Verdict};
use crate::core::message::Message;
use crate::core::problem::Code;
use crate::message;

use super::matching::{purl_matches, url_matches};
use super::{ArtifactPolicy, ArtifactRule, LicenseDeclaration, LicensePolicy, SpdxRef};

impl LicensePolicy {
    /// Resolve declared text to an SPDX expression.
    ///
    /// Tried in order: the text is already an expression; it matches an
    /// alias name; it matches an alias URL.
    pub(super) fn resolve(&self, declared: &str) -> Option<String> {
        if spdx::Expression::parse(declared).is_ok() {
            return Some(declared.to_owned());
        }

        // npm's `UNLICENSED` and `SEE LICENSE IN ...` are not SPDX and mean
        // "look at the file", which is the unknown branch, not an alias.
        for (expression, alias) in &self.aliases {
            let matched = alias
                .names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(declared))
                || alias.urls.iter().any(|url| url_matches(url, declared));

            if matched {
                return Some(expression.clone());
            }
        }

        None
    }

    /// Apply the allow and forbid tables to a resolved expression.
    pub(super) fn judge(&self, expression: &str) -> Verdict {
        let Ok(parsed) = spdx::Expression::parse(expression) else {
            return Verdict::plain(
                self.unknown_license,
                None,
                message!(
                    "license-expression-invalid",
                    "{expression:?} is not a valid SPDX expression",
                    expression = expression,
                ),
                Some(Code::LicenseUnmatched),
            );
        };

        // Forbidden first: an expression that cannot be satisfied without a
        // forbidden license is forbidden, even if it also offers an allowed
        // one under `AND`.
        if !self.forbidden_licenses.is_empty()
            && !parsed.evaluate(|req| !self.listed(&self.forbidden_licenses, req))
        {
            return Verdict::plain(
                Decision::Forbid,
                Some(expression.to_owned()),
                message!(
                    "license-forbidden",
                    "{expression} requires a forbidden license",
                    expression = expression,
                ),
                Some(Code::LicenseForbidden),
            );
        }

        // Satisfiable using only allowed licenses: `MIT OR GPL-3.0-only`
        // passes when MIT is allowed, because the choice is the user's.
        if !self.allowed_licenses.is_empty()
            && parsed.evaluate(|req| self.listed(&self.allowed_licenses, req))
        {
            return Verdict::plain(
                Decision::Allow,
                Some(expression.to_owned()),
                message!(
                    "license-allowed",
                    "{expression} is satisfied by the allowed licenses",
                    expression = expression,
                ),
                None,
            );
        }

        Verdict::plain(
            self.default_behavior,
            Some(expression.to_owned()),
            message!(
                "license-default-applied",
                "{expression} matched no rule; the default applies",
                expression = expression,
            ),
            (self.default_behavior == Decision::Forbid).then_some(Code::LicenseForbidden),
        )
    }

    /// Resolve a rule's `usage` map to one decision.
    ///
    /// **Any `allow` wins, however many `forbid` entries sit beside it.**
    /// That looks permissive until you remember what this tool decides: not
    /// whether code may be linked against, but whether the artifact must
    /// exist in the target repository at all.  An artifact cleared for test
    /// use has to be mirrored, or the tests cannot run -- so
    /// `{"runtime": "forbid", "test": "allow"}` means "mirror it", and the
    /// map is carried into the report so the runtime prohibition is not
    /// lost.
    ///
    /// Enforcing the per-usage split is the build's job, not the mirror's.
    pub(super) fn judge_usage(&self, rule: &ArtifactRule, reason: Message) -> Verdict {
        let allowed = rule
            .usage
            .iter()
            .filter(|(_, decision)| **decision == Decision::Allow)
            .map(|(kind, _)| kind.to_string())
            .collect::<Vec<_>>();

        let decision = if allowed.is_empty() {
            Decision::Forbid
        } else {
            Decision::Allow
        };

        let detail = if allowed.is_empty() {
            "every usage is forbidden".to_owned()
        } else {
            format!("allowed for {} usage", allowed.join(", "))
        };

        Verdict {
            decision,
            spdx: rule
                .license
                .as_ref()
                .map(|license| license.spdx().to_owned()),
            reason: message!(
                "license-usage-decided",
                "{written} ({detail})",
                written = reason.render(),
                detail = detail,
            ),
            problem: (decision == Decision::Forbid).then_some(Code::LicenseForbidden),
            usage: rule.usage.clone(),
        }
    }

    /// Whether one license requirement appears in a policy list.
    pub(super) fn listed(&self, list: &[SpdxRef], req: &spdx::LicenseReq) -> bool {
        list.iter().any(|entry| {
            spdx::Expression::parse(entry.spdx())
                .map(|parsed| parsed.requirements().any(|listed| listed.req == *req))
                .unwrap_or(false)
        })
    }

    /// The rule covering an artifact.
    ///
    /// **First match wins**, matching the configuration's own first-wins
    /// merge.  Globs make rules overlap easily, so order is now load-bearing:
    /// put the narrow `pkg:npm/foo@2.*` above the broad `pkg:npm/foo`, or the
    /// broad one shadows it.
    pub(super) fn rule_for(&self, purl: &str) -> Option<&ArtifactRule> {
        self.artifacts
            .iter()
            .find(|rule| rule.purl.as_deref().is_some_and(|p| purl_matches(p, purl)))
    }

    /// A rule may decide outright, or only supply the license and let the
    /// general tables judge it.
    pub(super) fn apply_rule(
        &self,
        rule: &ArtifactRule,
        declared: Option<&str>,
    ) -> Option<Verdict> {
        // The explanation is prose the *user* wrote in their policy file.
        // It is data, not one of our messages, so it travels as an argument
        // rather than being translated.
        let reason = match rule
            .reason
            .clone()
            .or_else(|| rule.reasons.first().cloned())
        {
            Some(written) => message!("license-rule-reason", "{written}", written = written,),

            None => message!(
                "license-rule-unexplained",
                "a policy rule names this artifact",
            ),
        };

        // A usage map is the more precise statement, so it outranks the
        // blanket `policy` on the same rule.
        if !rule.usage.is_empty() {
            return Some(self.judge_usage(rule, reason));
        }

        match rule.policy {
            ArtifactPolicy::Allow => Some(Verdict::plain(
                Decision::Allow,
                rule.license
                    .as_ref()
                    .map(|license| license.spdx().to_owned()),
                reason,
                None,
            )),

            ArtifactPolicy::Forbid => Some(Verdict::plain(
                Decision::Forbid,
                rule.license
                    .as_ref()
                    .map(|license| license.spdx().to_owned()),
                reason,
                Some(Code::LicenseForbidden),
            )),

            // The rule corrects a wrong or missing declaration; the tables
            // still decide.
            ArtifactPolicy::Default => rule
                .license
                .as_ref()
                .map(LicenseDeclaration::spdx)
                .or(declared)
                .map(|license| self.judge(license)),
        }
    }
}
