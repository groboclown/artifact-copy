//! What to do about one failed attempt, decided per status code.
//!
//! One back-off curve cannot serve every failure, because the failures do
//! not mean the same thing. A 504 often means a gateway is restarting, so
//! minutes of patience is right and three seconds is not. A 429 means the
//! server is stating the rate it will accept, so the useful response is to
//! believe it rather than guess. A 500 is transient on one system and
//! permanent on another, and only whoever runs that system knows which.
//!
//! So the policy is a **mapping**: a base rule, overridden per exact status
//! (`504`) or per class (`5xx`), with a documented default set underneath.
//!
//! ```text
//!   on-status exact (503)  >  on-status class (5xx)  >  default set  >  base
//! ```
//!
//! Nothing here performs a request or waits. A [`Plan`] answers what should
//! happen and [`super::client`] is what makes it happen, which is what lets
//! every rule above be tested as arithmetic.
//!
//! References: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), [RateLimit headers draft](https://ietf-wg-httpapi.github.io/ratelimit-headers/draft-ietf-httpapi-ratelimit-headers.html).

use http::StatusCode;
use std::collections::BTreeMap;
use std::time::Duration;

use crate::config::{Retry, RetryRule};
use crate::core::error::{Error, Result};

/// Statuses that retry when nothing says otherwise.
///
/// Deliberately short. A blanket "retry every failure" turns a
/// misconfiguration into a *slow* misconfiguration: a 401 retried four times
/// is four times the wait before the user learns their token is wrong, and a
/// 404 retried at all is pure delay.
pub const DEFAULT_RETRYABLE: [StatusCode; 6] = [
    StatusCode::REQUEST_TIMEOUT,
    StatusCode::TOO_MANY_REQUESTS,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
    StatusCode::SERVICE_UNAVAILABLE,
    StatusCode::GATEWAY_TIMEOUT,
];

const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const DEFAULT_MAXIMUM_DELAY: Duration = Duration::from_secs(30);
const DEFAULT_BUDGET: Duration = Duration::from_secs(300);

/// What happened to one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The server answered.
    Status(StatusCode),

    /// Nothing answered: a refused connection, a DNS failure, a TLS
    /// handshake error.
    Transport,
}

/// Whether to try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Wait(Duration),
    GiveUp,
}

/// How the delay grows between attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackOff {
    Fixed,
    Incremental(Duration),
    Exponential,
}

/// One resolved policy, with every field decided.
#[derive(Debug, Clone, Copy)]
struct Rule {
    retry: bool,
    max_retries: u32,
    initial_delay: Duration,
    maximum_delay: Duration,
    budget: Duration,
    back_off: BackOff,
    honor_retry_after: bool,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            retry: false,
            max_retries: DEFAULT_MAX_RETRIES,
            initial_delay: DEFAULT_INITIAL_DELAY,
            maximum_delay: DEFAULT_MAXIMUM_DELAY,
            budget: DEFAULT_BUDGET,

            // Exponential by default.  Both Maven Central and PyPI ask
            // integrators to back off rather than retry at a constant rate,
            // and a fixed one-second retry against a struggling server is
            // closer to a denial of service than to politeness.
            back_off: BackOff::Exponential,

            honor_retry_after: true,
        }
    }
}

impl Rule {
    /// Layer a configured rule over this one, keeping what it does not say.
    ///
    /// Inheritance is what makes a per-status override readable: setting a
    /// longer delay for 504 should not mean restating the retry count, the
    /// budget and the back-off curve.
    fn apply(mut self, rule: &RetryRule) -> Self {
        if let Some(retry) = rule.retry {
            self.retry = retry;
        }
        if let Some(max) = rule.max_retries {
            self.max_retries = max;
        }
        if let Some(delay) = rule.initial_delay {
            self.initial_delay = delay.get();
        }
        if let Some(delay) = rule.maximum_delay {
            self.maximum_delay = delay.get();
        }
        if let Some(budget) = rule.maximum_total_retry_seconds {
            self.budget = budget.get();
        }
        if let Some(honor) = rule.honor_retry_after {
            self.honor_retry_after = honor;
        }

        // An explicit incremental step wins over the exponential flag: it is
        // the more specific statement of the two.
        if let Some(step) = rule.incremental_delay {
            self.back_off = BackOff::Incremental(step.get());
        } else if let Some(exponential) = rule.exponential_back_off {
            self.back_off = match exponential {
                true => BackOff::Exponential,
                false => BackOff::Fixed,
            };
        }

        self
    }

    /// How long to wait before attempt `attempt + 1`.
    fn delay(&self, attempt: u32) -> Duration {
        let raw = match self.back_off {
            BackOff::Fixed => self.initial_delay,

            BackOff::Incremental(step) => self.initial_delay + step * attempt,

            // Saturating, because 2^32 nanoseconds is not a wait anyone
            // wants and an overflow panic is worse.
            BackOff::Exponential => self
                .initial_delay
                .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX)),
        };

        raw.min(self.maximum_delay)
    }
}

/// What the base's `retry` says every rule inherits: retry, unless the
/// configured base says `retry: false`.
fn inherited_retry(retry: Option<&Retry>) -> bool {
    retry.and_then(|r| r.base.retry).unwrap_or(true)
}

/// Which statuses a rule covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StatusMatch {
    /// `504`
    Exact(StatusCode),

    /// `5xx`
    Class(u8),
}

impl StatusMatch {
    /// Parse a mapping key.
    fn parse(key: &str) -> Option<Self> {
        let key = key.trim();

        if let Some(class) = key.strip_suffix("xx").or_else(|| key.strip_suffix("XX")) {
            let digit = class.parse::<u8>().ok()?;

            return (1..=5)
                .contains(&digit)
                .then_some(StatusMatch::Class(digit));
        }

        let exact = key.parse::<u16>().ok()?;

        if !(100..=599).contains(&exact) {
            return None;
        }

        StatusCode::from_u16(exact).ok().map(StatusMatch::Exact)
    }
}

/// A host's retry policy.
#[derive(Debug, Clone)]
pub struct Plan {
    base: Rule,
    exact: BTreeMap<StatusCode, Rule>,
    class: BTreeMap<u8, Rule>,

    /// [`DEFAULT_RETRYABLE`], below any configured rule, so a `5xx` rule
    /// reaches 500, 502, 503, and 504 too.
    defaults: BTreeMap<StatusCode, Rule>,

    transport: Rule,
}

impl Default for Plan {
    fn default() -> Self {
        Self::from_config(None).expect("the default plan is valid")
    }
}

impl Plan {
    /// Build a plan from a host's configuration.
    ///
    /// `None` gives the defaults, which is what a host that says nothing
    /// about retries gets.
    pub fn from_config(retry: Option<&Retry>) -> Result<Self> {
        let base = Rule::default().apply(retry.map(|r| &r.base).unwrap_or(&RetryRule::default()));

        // The base's `retry` is what every rule inherits: `false` turns off
        // each retry a rule does not switch back on. A status no rule names
        // never retries, so the base itself never says "retry".
        let inherited = inherited_retry(retry);
        let base = Rule {
            retry: false,
            ..base
        };

        let mut exact = BTreeMap::new();
        let mut class = BTreeMap::new();
        let mut defaults = BTreeMap::new();

        let use_defaults = retry.and_then(|r| r.use_default_statuses).unwrap_or(true);

        if use_defaults && inherited {
            for status in DEFAULT_RETRYABLE {
                defaults.insert(
                    status,
                    Rule {
                        retry: true,
                        ..base
                    },
                );
            }
        }

        for (key, rule) in retry.map(|r| &r.on_status).into_iter().flatten() {
            let Some(matcher) = StatusMatch::parse(key) else {
                return Err(Error::Config(format!(
                    "{key:?} is not an HTTP status code or class; \
                     write an exact code such as 504, or a class such as 5xx"
                )));
            };

            // A rule that names a status means it, so it retries unless it,
            // or the base, says `retry: false`.
            let resolved = Rule {
                retry: inherited,
                ..base
            }
            .apply(rule);

            match matcher {
                StatusMatch::Exact(status) => {
                    exact.insert(status, resolved);
                }
                StatusMatch::Class(digit) => {
                    class.insert(digit, resolved);
                }
            }
        }

        let transport = Rule {
            retry: inherited,
            ..base
        }
        .apply(
            retry
                .and_then(|r| r.on_transport_error.as_ref())
                .unwrap_or(&RetryRule::default()),
        );

        Ok(Self {
            base,
            exact,
            class,
            defaults,
            transport,
        })
    }

    /// The rule governing one outcome.
    ///
    /// An exact code beats a class, a class beats the default set, and the
    /// default set beats the base -- so `5xx` can set a patient default
    /// for every 5xx, 503 included, while `503: {...}` stays sharp.
    fn rule_for(&self, outcome: Outcome) -> Rule {
        let status = match outcome {
            Outcome::Transport => return self.transport,
            Outcome::Status(status) => status,
        };

        if let Some(rule) = self.exact.get(&status) {
            return *rule;
        }

        if let Some(rule) = self.class.get(&((status.as_u16() / 100) as u8)) {
            return *rule;
        }

        if let Some(rule) = self.defaults.get(&status) {
            return *rule;
        }

        self.base
    }

    /// Whether to try again, and after how long.
    ///
    /// `attempt` counts attempts already made, so the first failure arrives
    /// as `0`. `elapsed` is the time spent retrying so far, which the budget
    /// is measured against.
    pub fn decide(
        &self,
        outcome: Outcome,
        attempt: u32,
        elapsed: Duration,
        retry_after: Option<Duration>,
    ) -> Decision {
        let rule = self.rule_for(outcome);

        if !rule.retry || attempt >= rule.max_retries {
            return Decision::GiveUp;
        }

        // A `Retry-After` is the server stating the rate it will accept.
        // It is not clamped to `maximum_delay`: clamping a stated 120
        // seconds down to 30 means ignoring the answer and hammering.
        let delay = match retry_after.filter(|_| rule.honor_retry_after) {
            Some(stated) => stated,
            None => rule.delay(attempt),
        };

        // The budget is a promise about total time, so a wait that would
        // break it means stopping rather than overrunning it.
        if elapsed + delay > rule.budget {
            return Decision::GiveUp;
        }

        Decision::Wait(delay)
    }
}

/// `Retry-After`: delta-seconds or an HTTP date (RFC 9110).
const RETRY_AFTER: &str = "retry-after";

/// `RateLimit-Reset`: delta-seconds (the IETF `RateLimit` header draft).
const RATELIMIT_RESET: &str = "ratelimit-reset";

/// `X-RateLimit-Remaining` and `X-RateLimit-Reset`: requests left in the
/// window, and the window's end in epoch seconds, as GitHub and GitLab
/// send them.
const X_RATELIMIT_REMAINING: &str = "x-ratelimit-remaining";
const X_RATELIMIT_RESET: &str = "x-ratelimit-reset";

/// When a failed response says to try again, from whichever convention it
/// uses.
///
/// `Retry-After` first, as the standard; then `RateLimit-Reset`; then
/// `X-RateLimit-Reset`, but only with `X-RateLimit-Remaining: 0` -- GitHub
/// sends the pair on every response, and a reset on a request that still
/// had budget left says nothing about this failure.
///
/// ```text
///   Retry-After: 120                             now + 120 s
///   RateLimit-Reset: 30                          now + 30 s
///   X-RateLimit-Remaining: 0
///   X-RateLimit-Reset: 1791936000                2026-10-14T00:00:00Z
/// ```
///
/// `header` looks up a header by lowercase name.
pub fn retry_at<'h>(
    header: impl Fn(&str) -> Option<&'h str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let after = |wait: Duration| chrono::Duration::from_std(wait).ok().map(|wait| now + wait);

    if let Some(wait) = header(RETRY_AFTER).and_then(|value| parse_retry_after(value, now)) {
        return after(wait);
    }

    if let Some(seconds) = header(RATELIMIT_RESET).and_then(|value| value.trim().parse().ok()) {
        return after(Duration::from_secs(seconds));
    }

    let exhausted = header(X_RATELIMIT_REMAINING).is_some_and(|value| value.trim() == "0");

    if !exhausted {
        return None;
    }

    header(X_RATELIMIT_RESET)
        .and_then(|value| value.trim().parse::<i64>().ok())
        .and_then(|epoch| chrono::DateTime::from_timestamp(epoch, 0))
}

/// Parse a `Retry-After` header.
///
/// Both forms the spec allows: delta-seconds, and an HTTP date. A date in
/// the past means no wait rather than an error.
pub fn parse_retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let when = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let delta = when.with_timezone(&chrono::Utc) - now;

    Some(delta.to_std().unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(json: &str) -> RetryRule {
        serde_json::from_str(json).expect("parses")
    }

    fn retry(json: &str) -> Retry {
        serde_json::from_str(json).expect("parses")
    }

    fn plan(json: &str) -> Plan {
        Plan::from_config(Some(&retry(json))).expect("valid")
    }

    fn headers<'h>(pairs: &'h [(&'h str, &'h str)]) -> impl Fn(&str) -> Option<&'h str> {
        move |wanted| {
            pairs
                .iter()
                .find(|(name, _)| *name == wanted)
                .map(|(_, value)| *value)
        }
    }

    fn at(text: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(text)
            .expect("parses")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn retry_at_reads_each_convention() {
        let now = at("2026-10-06T00:00:00Z");

        assert_eq!(
            retry_at(headers(&[("retry-after", "120")]), now),
            Some(at("2026-10-06T00:02:00Z"))
        );
        assert_eq!(
            retry_at(headers(&[("ratelimit-reset", "30")]), now),
            Some(at("2026-10-06T00:00:30Z"))
        );
        assert_eq!(
            retry_at(
                headers(&[
                    ("x-ratelimit-remaining", "0"),
                    ("x-ratelimit-reset", "1791936000")
                ]),
                now
            ),
            chrono::DateTime::from_timestamp(1_791_936_000, 0)
        );
    }

    /// GitHub sends the reset on every response; only an exhausted window
    /// says this failure was the limit.
    #[test]
    fn retry_at_ignores_reset_with_budget_left() {
        let now = at("2026-10-06T00:00:00Z");
        let pairs = [
            ("x-ratelimit-remaining", "12"),
            ("x-ratelimit-reset", "1791936000"),
        ];

        assert_eq!(retry_at(headers(&pairs), now), None);
    }

    #[test]
    fn retry_after_wins_over_rate_limit_headers() {
        let now = at("2026-10-06T00:00:00Z");
        let pairs = [
            ("retry-after", "5"),
            ("ratelimit-reset", "60"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "1791936000"),
        ];

        assert_eq!(
            retry_at(headers(&pairs), now),
            Some(at("2026-10-06T00:00:05Z"))
        );
    }

    #[test]
    fn defaults_retry_transient_failures_only() {
        let plan = Plan::default();

        for status in DEFAULT_RETRYABLE {
            assert!(
                matches!(
                    plan.decide(Outcome::Status(status), 0, Duration::ZERO, None),
                    Decision::Wait(_)
                ),
                "{status} should retry"
            );
        }
    }

    /// The reason the default set is short: retrying these only delays the
    /// moment the user learns what is actually wrong.
    #[test]
    fn failure_permanent_never_retries() {
        let plan = Plan::default();

        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::GONE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert_eq!(
                plan.decide(Outcome::Status(status), 0, Duration::ZERO, None),
                Decision::GiveUp,
                "{status} must not retry"
            );
        }
    }

    #[test]
    fn failure_transport_retries() {
        assert!(matches!(
            Plan::default().decide(Outcome::Transport, 0, Duration::ZERO, None),
            Decision::Wait(_)
        ));
    }

    /// The motivating case: a gateway that is restarting deserves patience
    /// that the base policy does not give it.
    #[test]
    fn status_own_patience() {
        let plan = plan(
            r#"{
                "max-retries": 3,
                "initial-delay": "1 sec",
                "on-status": {
                    "504": {
                        "max-retries": 10,
                        "initial-delay": "30 sec",
                        "maximum-delay": "5 min",
                        "maximum-total-retry-seconds": "1 hr"
                    }
                }
            }"#,
        );

        // 504 waits half a minute on the first failure and keeps going well
        // past the base's three attempts.
        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::GATEWAY_TIMEOUT),
                0,
                Duration::ZERO,
                None
            ),
            Decision::Wait(Duration::from_secs(30))
        );

        // By the sixth it would want 30 * 2^5, and the 5-minute ceiling
        // holds it there.
        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::GATEWAY_TIMEOUT),
                5,
                Duration::from_secs(60),
                None
            ),
            Decision::Wait(Duration::from_secs(300))
        );

        // 502 still follows the base policy.
        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::BAD_GATEWAY),
                5,
                Duration::ZERO,
                None
            ),
            Decision::GiveUp
        );
    }

    /// Turning one status off is the point of `retry: false`; a delay
    /// setting cannot express it.
    #[test]
    fn status_switched_off() {
        let plan = plan(r#"{"on-status": {"500": {"retry": false}}}"#);

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::INTERNAL_SERVER_ERROR),
                0,
                Duration::ZERO,
                None
            ),
            Decision::GiveUp
        );

        // Its neighbours are untouched.
        assert!(matches!(
            plan.decide(
                Outcome::Status(StatusCode::BAD_GATEWAY),
                0,
                Duration::ZERO,
                None
            ),
            Decision::Wait(_)
        ));
    }

    /// For a system whose status codes do not mean what the registry says.
    #[test]
    fn defaults_dropped_entirely() {
        let plan = plan(r#"{"use-default-statuses": false, "on-status": {"418": {}}}"#);

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                0,
                Duration::ZERO,
                None
            ),
            Decision::GiveUp
        );

        assert!(matches!(
            plan.decide(
                Outcome::Status(StatusCode::IM_A_TEAPOT),
                0,
                Duration::ZERO,
                None
            ),
            Decision::Wait(_)
        ));
    }

    #[test]
    fn status_exact_code_beats_class() {
        let plan = plan(
            r#"{
                "on-status": {
                    "5xx": {"initial-delay": "10 sec"},
                    "503": {"initial-delay": "1 sec"}
                }
            }"#,
        );

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                0,
                Duration::ZERO,
                None
            ),
            Decision::Wait(Duration::from_secs(1))
        );

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::INSUFFICIENT_STORAGE),
                0,
                Duration::ZERO,
                None
            ),
            Decision::Wait(Duration::from_secs(10))
        );
    }

    /// A class reaches the default statuses in it: `5xx` sets 500's delay,
    /// and `5xx: {retry: false}` stops 503.
    #[test]
    fn status_class_beats_defaults() {
        let patient = plan(r#"{"on-status": {"5xx": {"initial-delay": "10 sec"}}}"#);
        let off = plan(r#"{"on-status": {"5xx": {"retry": false}}}"#);
        let first =
            |plan: &Plan, status| plan.decide(Outcome::Status(status), 0, Duration::ZERO, None);

        assert_eq!(
            first(&patient, StatusCode::INTERNAL_SERVER_ERROR),
            Decision::Wait(Duration::from_secs(10))
        );
        assert_eq!(
            first(&off, StatusCode::SERVICE_UNAVAILABLE),
            Decision::GiveUp
        );

        // A default outside the class keeps the base policy.
        assert_eq!(
            first(&off, StatusCode::TOO_MANY_REQUESTS),
            Decision::Wait(DEFAULT_INITIAL_DELAY)
        );
    }

    /// A base `retry: false` turns off every retry a rule does not switch
    /// back on: the default statuses, transport failures, and a status
    /// rule that only sets a delay.
    #[test]
    fn base_retry_off_disables_all() {
        let plan = plan(
            r#"{
                "retry": false,
                "on-status": {
                    "504": {"initial-delay": "5 sec"},
                    "503": {"retry": true}
                }
            }"#,
        );
        let first = |outcome| plan.decide(outcome, 0, Duration::ZERO, None);

        assert_eq!(
            first(Outcome::Status(StatusCode::TOO_MANY_REQUESTS)),
            Decision::GiveUp
        );
        assert_eq!(
            first(Outcome::Status(StatusCode::GATEWAY_TIMEOUT)),
            Decision::GiveUp
        );
        assert_eq!(first(Outcome::Transport), Decision::GiveUp);
        assert_eq!(
            first(Outcome::Status(StatusCode::SERVICE_UNAVAILABLE)),
            Decision::Wait(DEFAULT_INITIAL_DELAY)
        );
    }

    #[test]
    fn status_key_unparseable_refused() {
        let err = Plan::from_config(Some(&retry(r#"{"on-status": {"oops": {}}}"#))).unwrap_err();

        assert!(err.to_string().contains("oops"));
        assert!(err.to_string().contains("5xx"));
    }

    #[test]
    fn backoff_grows_exponentially_by_default() {
        let plan = plan(r#"{"initial-delay": "1 sec", "max-retries": 10}"#);

        let delay = |attempt| match plan.decide(
            Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
            attempt,
            Duration::ZERO,
            None,
        ) {
            Decision::Wait(delay) => delay,
            Decision::GiveUp => panic!("should retry"),
        };

        assert_eq!(delay(0), Duration::from_secs(1));
        assert_eq!(delay(1), Duration::from_secs(2));
        assert_eq!(delay(2), Duration::from_secs(4));
        assert_eq!(delay(3), Duration::from_secs(8));
    }

    #[test]
    fn backoff_incremental_step_overrides_exponential() {
        let plan = plan(
            r#"{"initial-delay": "1 sec", "incremental-delay": "5 sec",
                "exponential-back-off": true, "max-retries": 10}"#,
        );

        let delay = |attempt| match plan.decide(
            Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
            attempt,
            Duration::ZERO,
            None,
        ) {
            Decision::Wait(delay) => delay,
            Decision::GiveUp => panic!("should retry"),
        };

        assert_eq!(delay(0), Duration::from_secs(1));
        assert_eq!(delay(1), Duration::from_secs(6));
        assert_eq!(delay(2), Duration::from_secs(11));
    }

    #[test]
    fn backoff_delay_capped() {
        let plan = plan(
            r#"{"initial-delay": "1 sec", "maximum-delay": "5 sec", "max-retries": 20,
                "maximum-total-retry-seconds": "1 hr"}"#,
        );

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                10,
                Duration::ZERO,
                None
            ),
            Decision::Wait(Duration::from_secs(5))
        );
    }

    /// The server is stating the rate it will accept.  Clamping its stated
    /// 120 seconds down to a local 30 would be ignoring the answer.
    #[test]
    fn retry_after_honored_above_max_delay() {
        let plan = plan(r#"{"maximum-delay": "30 sec", "maximum-total-retry-seconds": "1 hr"}"#);

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::TOO_MANY_REQUESTS),
                0,
                Duration::ZERO,
                Some(Duration::from_secs(120))
            ),
            Decision::Wait(Duration::from_secs(120))
        );
    }

    #[test]
    fn retry_after_ignored_per_status() {
        let plan = plan(
            r#"{"initial-delay": "1 sec",
                "on-status": {"429": {"honor-retry-after": false}}}"#,
        );

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::TOO_MANY_REQUESTS),
                0,
                Duration::ZERO,
                Some(Duration::from_secs(120))
            ),
            Decision::Wait(Duration::from_secs(1))
        );
    }

    /// The budget is a promise about total time, so a wait that would break
    /// it means stopping rather than overrunning.
    #[test]
    fn budget_stops_exceeding_wait() {
        let plan = plan(r#"{"maximum-total-retry-seconds": "10 sec", "max-retries": 20}"#);

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                0,
                Duration::from_secs(9),
                Some(Duration::from_secs(60))
            ),
            Decision::GiveUp
        );
    }

    #[test]
    fn attempts_bounded() {
        let plan = plan(r#"{"max-retries": 2, "maximum-total-retry-seconds": "1 hr"}"#);

        assert!(matches!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                1,
                Duration::ZERO,
                None
            ),
            Decision::Wait(_)
        ));

        assert_eq!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                2,
                Duration::ZERO,
                None
            ),
            Decision::GiveUp
        );
    }

    /// Inheritance is what keeps an override readable: this one states a
    /// delay and nothing else.
    #[test]
    fn status_rule_inherits_unstated() {
        let plan = plan(
            r#"{"max-retries": 7, "maximum-total-retry-seconds": "1 hr",
                "on-status": {"503": {"initial-delay": "2 sec"}}}"#,
        );

        // The inherited count, not the default three.
        assert!(matches!(
            plan.decide(
                Outcome::Status(StatusCode::SERVICE_UNAVAILABLE),
                6,
                Duration::ZERO,
                None
            ),
            Decision::Wait(_)
        ));
    }

    #[test]
    fn retry_after_parses_both_forms() {
        let now = chrono::Utc::now();

        assert_eq!(
            parse_retry_after("120", now),
            Some(Duration::from_secs(120))
        );

        let later = (now + chrono::Duration::seconds(60)).to_rfc2822();
        let parsed = parse_retry_after(&later, now).expect("a date parses");

        assert!(parsed.as_secs() >= 59 && parsed.as_secs() <= 60);
    }

    /// A date already past means go now, not an error.
    #[test]
    fn retry_after_in_past_means_no_wait() {
        let now = chrono::Utc::now();
        let earlier = (now - chrono::Duration::seconds(60)).to_rfc2822();

        assert_eq!(parse_retry_after(&earlier, now), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_nonsense_ignored() {
        assert_eq!(parse_retry_after("soon", chrono::Utc::now()), None);
    }

    /// A rule with nothing in it changes nothing.
    #[test]
    fn defaults_untouched_by_empty_rule() {
        let applied = Rule::default().apply(&rule("{}"));

        assert_eq!(applied.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(applied.initial_delay, DEFAULT_INITIAL_DELAY);
        assert_eq!(applied.back_off, BackOff::Exponential);
    }

    #[test]
    fn status_keys_parse_exact_codes_and_classes() {
        assert_eq!(
            StatusMatch::parse("504"),
            Some(StatusMatch::Exact(StatusCode::GATEWAY_TIMEOUT))
        );
        assert_eq!(StatusMatch::parse("5xx"), Some(StatusMatch::Class(5)));
        assert_eq!(StatusMatch::parse("5XX"), Some(StatusMatch::Class(5)));

        assert_eq!(StatusMatch::parse("99"), None);
        assert_eq!(StatusMatch::parse("600"), None);
        assert_eq!(StatusMatch::parse("xx"), None);
        assert_eq!(StatusMatch::parse(""), None);
    }

    /// Guards against an overflow panic on a long-running retry loop.
    #[test]
    fn attempts_large_count_no_overflow() {
        let rule = Rule {
            retry: true,
            maximum_delay: Duration::from_secs(60),
            ..Rule::default()
        };

        assert_eq!(rule.delay(64), Duration::from_secs(60));
        assert_eq!(rule.delay(u32::MAX), Duration::from_secs(60));
    }
}
