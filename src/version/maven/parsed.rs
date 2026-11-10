//! Maven's `ComparableVersion`, ported.
//!
//! This is the most correctness-critical function in the tool. Maven's
//! version order is not semver and not PEP 440; it disagrees with both in
//! ways that change which artifact gets migrated. `1.0` equals `1`, `1.0.1`
//! is *less* than `1.0-1`, and `2.0.1` is less than `2.0.1-xyz` but greater
//! than `2.0.1-rc1`. None of that falls out of a general-purpose comparator.
//!
//! No maintained Rust crate implements it -- `mvn_version` last shipped in
//! 2021 -- so it is ported here, from `maven-artifact`'s own
//! `ComparableVersion.java`, and tested against the vectors in that
//! project's `ComparableVersionTest`. Those vectors are the point: they
//! encode the accumulated bug reports (MNG-5568, MNG-6572, MNG-6964) that a
//! fresh implementation would rediscover the hard way.
//!
//! # How it works
//!
//! A version parses into a tree. `.` separates items at the current level;
//! `-` opens a nested level; a digit/non-digit transition acts as a
//! separator too, which is why `1a` and `1-a` are the same version. Trailing
//! "null" items -- a zero, an empty qualifier, an empty list -- are then
//! trimmed, which is what makes `1`, `1.0`, `1.0.0` and `1-0` one version.
//!
//! Comparison then walks the two trees, and the cross-type rules carry the
//! surprises: a number beats a qualifier (`1.1 > 1-sp`), a nested list beats
//! a qualifier but loses to a number (`1-sp < 1-1 < 1.1`), and a missing
//! item compares as the *release* qualifier rather than as zero, which is
//! how `1-rc < 1 < 1-sp` works.

use std::cmp::Ordering;

use crate::model::Release;

/// Qualifier precedence, lowest first.
///
/// The empty string sits between `snapshot` and `sp`: a plain release beats
/// every pre-release, and a service pack beats the release. This is the
/// ordering Maven documents and the one the plan states.
const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

/// Where the empty qualifier sits -- the "this is a release" mark.
const RELEASE_INDEX: usize = 5;

/// Qualifiers that mean "not finished yet".
///
/// Deliberately **not** "anything qualified". Blanket-rejecting qualified
/// versions would drop Guava's `31.1-jre` and every `-android`, `-jre`,
/// `-linux-x86_64` classifier-style version with it. An unrecognized
/// qualifier orders above a release but is generally available.
const PRE_RELEASE: [&str; 5] = ["alpha", "beta", "milestone", "rc", "snapshot"];

/// One node of a parsed version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// Digits with leading zeroes stripped, so `"0"` is the only spelling
    /// of zero.
    ///
    /// Kept as text rather than a `u64`: Maven uses a `BigInteger` here, and
    /// the `20190126.230843` versus `12345678901234567890.1H.5-beta` vector
    /// (MNG-6572) overflows 64 bits. Comparing by length and then
    /// lexically is exactly `BigInteger` order for non-negative integers,
    /// without the dependency.
    Number(String),

    /// A qualifier, lowercased and alias-resolved.
    Qualifier(String),

    /// A nested level, opened by `-`.
    List(Vec<Item>),
}

/// Maven's version order.
pub fn compare(a: &str, b: &str) -> Ordering {
    cmp_item(&parse(a), &parse(b))
}

/// Whether a version is a pre-release.
pub(crate) fn release_of(text: &str) -> Release {
    match has_pre_release_qualifier(&parse(text)) {
        true => Release::PreRelease,
        false => Release::General,
    }
}

/// A parsed version, kept so a sort parses each input once.
///
/// Sorting an 800-version `maven-metadata.xml` re-parses every string
/// `O(log n)` times otherwise, and the parse is the expensive half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed(Item);

impl Parsed {
    pub fn new(text: &str) -> Self {
        Self(parse(text))
    }
}

impl Ord for Parsed {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_item(&self.0, &other.0)
    }
}

impl PartialOrd for Parsed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// -- Parsing --------------------------------------------------------------

/// Parse a version into its item tree.
///
/// Follows `ComparableVersion.parseVersion` step for step. The Java keeps a
/// stack of lists and mutates the innermost through an aliased reference;
/// here the stack owns the levels and each is folded into its parent as it
/// unwinds. That is equivalent because parsing only ever descends -- once a
/// level is opened, nothing is appended to its parent again -- so a child is
/// always the last item of its parent either way.
fn parse(version: &str) -> Item {
    let lowered = version.to_ascii_lowercase();
    let chars: Vec<char> = lowered.chars().collect();

    let mut stack: Vec<Vec<Item>> = vec![Vec::new()];
    let mut is_digit = false;
    let mut start = 0usize;

    let text = |from: usize, to: usize| chars[from..to].iter().collect::<String>();

    for index in 0..chars.len() {
        let ch = chars[index];

        if ch == '.' {
            push(&mut stack, item_at(is_digit, &chars, start, index, &text));
            start = index + 1;
        } else if ch == '-' {
            push(&mut stack, item_at(is_digit, &chars, start, index, &text));
            start = index + 1;

            stack.push(Vec::new());
        } else if ch.is_ascii_digit() {
            // A digit straight after a qualifier separates as if a `-` had
            // been typed, which is what makes `1.0.0.x1` order below
            // `1.0.0-x2` rather than beside it.
            if !is_digit && index > start {
                if !stack.last().expect("a level is always open").is_empty() {
                    stack.push(Vec::new());
                }

                push(
                    &mut stack,
                    Item::Qualifier(qualifier(&text(start, index), true)),
                );
                start = index;

                stack.push(Vec::new());
            }

            is_digit = true;
        } else {
            if is_digit && index > start {
                push(&mut stack, number(&text(start, index)));
                start = index;

                stack.push(Vec::new());
            }

            is_digit = false;
        }
    }

    if chars.len() > start {
        // A trailing qualifier opens a level of its own, exactly as the
        // mid-string digit transition does. Without this, `11.a` would end
        // as `[11, a]` rather than `[11, [a]]` -- and since a list outranks
        // a qualifier, `11.a2` would then come out *above* `11.a` instead
        // of below it.
        if !is_digit && !stack.last().expect("a level is always open").is_empty() {
            stack.push(Vec::new());
        }

        let tail = text(start, chars.len());

        push(
            &mut stack,
            match is_digit {
                true => number(&tail),
                false => Item::Qualifier(qualifier(&tail, false)),
            },
        );
    }

    // Innermost first, matching the Java's LIFO unwind: a level must be
    // normalized before its emptiness can be judged by its parent.
    while stack.len() > 1 {
        let mut level = stack.pop().expect("more than one level");
        normalize(&mut level);

        stack
            .last_mut()
            .expect("a parent is always open")
            .push(Item::List(level));
    }

    let mut root = stack.pop().expect("the root level");
    normalize(&mut root);

    Item::List(root)
}

/// The item between two separators, or a zero where they are adjacent.
fn item_at(
    is_digit: bool,
    chars: &[char],
    start: usize,
    end: usize,
    text: &impl Fn(usize, usize) -> String,
) -> Item {
    let _ = chars;

    if end == start {
        // `1..2` and `1-.2` each carry an implicit zero, so that `1.0` and
        // `1..` stay comparable rather than one of them losing an item.
        return Item::Number("0".to_owned());
    }

    let value = text(start, end);

    match is_digit {
        true => number(&value),
        false => Item::Qualifier(qualifier(&value, false)),
    }
}

fn push(stack: &mut [Vec<Item>], item: Item) {
    stack.last_mut().expect("a level is always open").push(item);
}

/// Strip leading zeroes, so `007` and `7` are one number.
fn number(digits: &str) -> Item {
    let trimmed = digits.trim_start_matches('0');

    Item::Number(match trimmed.is_empty() {
        true => "0".to_owned(),
        false => trimmed.to_owned(),
    })
}

/// Resolve a qualifier to its canonical spelling.
///
/// Two rewrites, in this order. A single letter directly before a digit is
/// an abbreviation -- `1a1` is `1-alpha-1`, and this is why the
/// followed-by-digit flag has to be threaded through the parser at all.
/// Then the aliases: `ga`, `final` and `release` all mean "no qualifier",
/// and `cr` is the old spelling of `rc`.
fn qualifier(value: &str, followed_by_digit: bool) -> String {
    let expanded = match (followed_by_digit, value) {
        (true, "a") => "alpha",
        (true, "b") => "beta",
        (true, "m") => "milestone",
        _ => value,
    };

    match expanded {
        "ga" | "final" | "release" => String::new(),
        "cr" => "rc".to_owned(),
        other => other.to_owned(),
    }
}

/// Trim trailing null items, which is what makes `1`, `1.0` and `1-0` equal.
///
/// Scanning backwards: a null item is dropped, a non-null plain item stops
/// the scan, and a non-null *list* does not -- the scan continues past it.
/// That last clause looks like an oversight and is not: it is what makes
/// `1-0.alpha` order below `1` rather than equal to it (MNG-6964).
fn normalize(level: &mut Vec<Item>) {
    for index in (0..level.len()).rev() {
        match &level[index] {
            item if is_null(item) => {
                level.remove(index);
            }

            Item::List(_) => continue,

            _ => break,
        }
    }
}

/// Whether an item contributes nothing.
///
/// A qualifier is null when it *is* the release qualifier, not merely when
/// it is empty -- which is how `1ga` and `1` come out equal.
fn is_null(item: &Item) -> bool {
    match item {
        Item::Number(digits) => digits == "0",
        Item::Qualifier(value) => comparable(value) == release_key(),
        Item::List(items) => items.is_empty(),
    }
}

// -- Comparison -----------------------------------------------------------

/// A qualifier's sort key.
///
/// A string rather than a number, faithfully to upstream: a known qualifier
/// keys as its index and an unknown one as `7-<name>`, so every unknown
/// qualifier sorts above every known one and unknowns order among
/// themselves by name. Single-digit indices are what make the string
/// comparison agree with the numeric one.
fn comparable(qualifier: &str) -> String {
    match QUALIFIERS.iter().position(|known| *known == qualifier) {
        Some(index) => index.to_string(),
        None => format!("{}-{qualifier}", QUALIFIERS.len()),
    }
}

fn release_key() -> String {
    RELEASE_INDEX.to_string()
}

fn cmp_item(left: &Item, right: &Item) -> Ordering {
    match (left, right) {
        (Item::Number(a), Item::Number(b)) => cmp_number(a, b),
        (Item::Number(_), _) => Ordering::Greater,

        (Item::Qualifier(_), Item::Number(_)) => Ordering::Less,
        (Item::Qualifier(a), Item::Qualifier(b)) => comparable(a).cmp(&comparable(b)),
        (Item::Qualifier(_), Item::List(_)) => Ordering::Less,

        (Item::List(_), Item::Number(_)) => Ordering::Less,
        (Item::List(_), Item::Qualifier(_)) => Ordering::Greater,
        (Item::List(a), Item::List(b)) => cmp_list(a, b),
    }
}

/// `BigInteger` order without the bignum: shorter is smaller once leading
/// zeroes are gone, and equal lengths compare lexically.
fn cmp_number(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compare two levels, padding the shorter with absence.
///
/// Absence is not zero. A missing item compares as the release qualifier,
/// so `1-rc` sits below `1` while `1-sp` sits above it -- the single rule
/// that most often trips up a hand-rolled Maven comparator.
fn cmp_list(a: &[Item], b: &[Item]) -> Ordering {
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index);
        let right = b.get(index);

        let ordering = match (left, right) {
            (Some(l), Some(r)) => cmp_item(l, r),
            (Some(l), None) => cmp_to_absent(l),
            (None, Some(r)) => cmp_to_absent(r).reverse(),
            (None, None) => Ordering::Equal,
        };

        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    Ordering::Equal
}

/// How an item compares against nothing at all.
fn cmp_to_absent(item: &Item) -> Ordering {
    match item {
        Item::Number(digits) => match digits == "0" {
            true => Ordering::Equal,
            false => Ordering::Greater,
        },

        Item::Qualifier(value) => comparable(value).cmp(&release_key()),

        // Every item of the list is weighed, not just the first: a list
        // whose head is null can still carry something that matters.
        Item::List(items) => items
            .iter()
            .map(cmp_to_absent)
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or(Ordering::Equal),
    }
}

fn has_pre_release_qualifier(item: &Item) -> bool {
    match item {
        Item::Number(_) => false,
        Item::Qualifier(value) => PRE_RELEASE.contains(&value.as_str()),
        Item::List(items) => items.iter().any(has_pre_release_qualifier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(a: &str, b: &str) -> Ordering {
        compare(a, b)
    }

    /// Both directions, every time.  A comparator that answers `Less` in
    /// both directions passes a one-sided check and corrupts a sort.
    fn assert_below(lesser: &str, greater: &str) {
        assert_eq!(
            order(lesser, greater),
            Ordering::Less,
            "{lesser} should be below {greater}"
        );
        assert_eq!(
            order(greater, lesser),
            Ordering::Greater,
            "{greater} should be above {lesser}"
        );
    }

    fn assert_same(a: &str, b: &str) {
        assert_eq!(order(a, b), Ordering::Equal, "{a} should equal {b}");
        assert_eq!(order(b, a), Ordering::Equal, "{b} should equal {a}");
    }

    /// From `ComparableVersionTest.testVersionsEqual`.
    #[test]
    fn upstream_equality_vectors() {
        for (a, b) in [
            ("1", "1"),
            ("1", "1.0"),
            ("1", "1.0.0"),
            ("1.0", "1.0.0"),
            ("1", "1-0"),
            ("1", "1.0-0"),
            ("1.0", "1.0-0"),
            // No separator is needed between a number and a letter.
            ("1a", "1-a"),
            ("1a", "1.0-a"),
            ("1a", "1.0.0-a"),
            ("1.0a", "1-a"),
            ("1.0.0a", "1-a"),
            ("1x", "1-x"),
            ("1x", "1.0-x"),
            ("1x", "1.0.0-x"),
            ("1.0x", "1-x"),
            ("1.0.0x", "1-x"),
        ] {
            assert_same(a, b);
        }
    }

    /// `ga`, `final` and `release` all mean "no qualifier"; `cr` is the
    /// older spelling of `rc`.
    #[test]
    fn upstream_alias_vectors() {
        for (a, b) in [
            ("1ga", "1"),
            ("1release", "1"),
            ("1final", "1"),
            ("1cr", "1rc"),
        ] {
            assert_same(a, b);
        }
    }

    /// A single letter before a digit abbreviates a qualifier.
    #[test]
    fn qualifier_single_letter_expands_before_digit() {
        assert_same("1a1", "1-alpha-1");
        assert_same("1b2", "1-beta-2");
        assert_same("1m3", "1-milestone-3");

        // Only before a digit, and only when alone: `1a` is the qualifier
        // `a`, which is unknown and therefore not alpha at all.
        assert_below("1-alpha", "1a");
    }

    #[test]
    fn compare_case_insensitive() {
        for (a, b) in [
            ("1X", "1x"),
            ("1A", "1a"),
            ("1B", "1b"),
            ("1M", "1m"),
            ("1Ga", "1"),
            ("1GA", "1"),
            ("1RELEASE", "1"),
            ("1RELeaSE", "1"),
            ("1Final", "1"),
            ("1FINAL", "1"),
            ("1Cr", "1Rc"),
            ("1cR", "1rC"),
            ("1m3", "1Milestone3"),
            ("1m3", "1MileStone3"),
            ("1m3", "1MILESTONE3"),
        ] {
            assert_same(a, b);
        }
    }

    /// From `ComparableVersionTest.testVersionComparing`.
    #[test]
    fn upstream_ordering_vectors() {
        for (lesser, greater) in [
            ("1", "2"),
            ("1.5", "2"),
            ("1", "2.5"),
            ("1.0", "1.1"),
            ("1.1", "1.2"),
            ("1.0.0", "1.1"),
            ("1.0.1", "1.1"),
            ("1.1", "1.2.0"),
            ("1.0-alpha-1", "1.0"),
            ("1.0-alpha-1", "1.0-alpha-2"),
            ("1.0-alpha-1", "1.0-beta-1"),
            ("1.0-beta-1", "1.0-SNAPSHOT"),
            ("1.0-SNAPSHOT", "1.0"),
            ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
            ("1.0", "1.0-1"),
            ("1.0-1", "1.0-2"),
            ("1.0.0", "1.0-1"),
            ("2.0-1", "2.0.1"),
            ("2.0.1-klm", "2.0.1-lmn"),
            ("2.0.1", "2.0.1-xyz"),
            ("2.0.1", "2.0.1-123"),
            ("2.0.1-xyz", "2.0.1-123"),
        ] {
            assert_below(lesser, greater);
        }
    }

    /// The documented qualifier ladder, as one ascending run.
    ///
    /// From `ComparableVersionTest.VERSIONS_QUALIFIER`.  Every pair is
    /// checked, not just the neighbours, because a comparator can order
    /// adjacent items correctly and still be intransitive.
    #[test]
    fn order_qualifier_ladder_total() {
        let ladder = [
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ];

        assert_totally_ordered(&ladder);
    }

    /// From `ComparableVersionTest.VERSIONS_NUMBER`.
    #[test]
    fn order_numeric_ladder_total() {
        let ladder = [
            "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
            "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11",
            "11", "11.a", "11b", "11c", "11m",
        ];

        assert_totally_ordered(&ladder);
    }

    /// MNG-7644: `1.0.0.X1 < 1.0.0-X2` for any qualifier `X`, and
    /// `2-X`, `2.0.X` and `2.0.0.X` are all the same version.
    ///
    /// This is the vector that catches a missing nested level on a
    /// *trailing* qualifier -- without it, `2.0.a` parses as a flat item and
    /// stops being equal to `2-a`.
    #[test]
    fn mng_7644_dotted_qualifier_like_dashed() {
        for x in [
            "abc",
            "alpha",
            "a",
            "beta",
            "b",
            "def",
            "milestone",
            "m",
            "rc",
        ] {
            assert_below(&format!("1.0.0.{x}1"), &format!("1.0.0-{x}2"));

            assert_same(&format!("2-{x}"), &format!("2.0.{x}"));
            assert_same(&format!("2-{x}"), &format!("2.0.0.{x}"));
            assert_same(&format!("2.0.{x}"), &format!("2.0.0.{x}"));
        }
    }

    /// From `testLocaleIndependent`.  Rust has no locale to get wrong, but
    /// the vector is cheap and pins the case folding.
    #[test]
    fn whole_alphabet_folds() {
        assert_same(
            "1-abcdefghijklmnopqrstuvwxyz",
            "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        );
    }

    /// From `testVersionEqualWithLeadingZeroes` and
    /// `testVersionZeroEqualWithLeadingZeroes`: every length from 1 to 19
    /// must collapse to the same value.
    #[test]
    fn collapse_every_leading_zero_length() {
        for width in 1..=19usize {
            assert_same(&format!("{:0>width$}", "1"), "1");
            assert_same(&format!("{:0>width$}", "0"), "0");
        }
    }

    fn assert_totally_ordered(ladder: &[&str]) {
        for (i, lower) in ladder.iter().enumerate() {
            for higher in &ladder[i + 1..] {
                assert_below(lower, higher);
            }
        }
    }

    /// MNG-5568: an `H` in the middle used to make `6.1H.5-beta` sort above
    /// `6.1.0rc3`.
    #[test]
    fn mng_5568_letter_mid_version() {
        assert_below("6.1.0rc3", "6.1.0");
        assert_below("6.1.0rc3", "6.1H.5-beta");
        assert_below("6.1.0", "6.1H.5-beta");
    }

    /// MNG-6572: numbers past 64 bits.  This is the vector that fails if
    /// the numeric items are parsed into a `u64`.
    #[test]
    fn mng_6572_very_long_numbers() {
        let ladder = [
            "20190126.230843",
            "1234567890.12345",
            "123456789012345.1H.5-beta",
            "12345678901234567890.1H.5-beta",
        ];

        assert_totally_ordered(&ladder);
    }

    /// MNG-6964: `1-0.alpha` used to compare *equal* to `1`, because only
    /// the head of a trailing list was weighed against absence.
    #[test]
    fn mng_6964_whole_list_weighed_against_absence() {
        assert_below("1-0.alpha", "1");
        assert_below("1-0.beta", "1");
        assert_below("1-0.alpha", "1-0.beta");
    }

    #[test]
    fn collapse_leading_zeroes() {
        assert_same("0000000000000000001", "1");
        assert_same("0000000000000000001.0.0", "1.0.0");
        assert_same("1.0000000000000000001", "1.1");
        assert_same("000000000000000000000", "0");

        assert_below("0000000000000000001", "0000000000000000002");
    }

    /// The property the tool actually leans on: `select` sorts a whole
    /// `maven-metadata.xml`, and a non-transitive comparator would make the
    /// answer depend on the order the registry happened to list them in.
    #[test]
    fn order_stable_under_input_order() {
        let mut ascending = vec![
            "1.0-alpha-1",
            "1.0-SNAPSHOT",
            "1.0",
            "1.0-sp",
            "1.0-1",
            "1.1",
        ];
        let mut shuffled = vec![
            "1.1",
            "1.0-sp",
            "1.0-SNAPSHOT",
            "1.0-1",
            "1.0-alpha-1",
            "1.0",
        ];

        ascending.sort_by(|a, b| compare(a, b));
        shuffled.sort_by(|a, b| compare(a, b));

        assert_eq!(ascending, shuffled);
        assert_eq!(
            ascending,
            [
                "1.0-alpha-1",
                "1.0-SNAPSHOT",
                "1.0",
                "1.0-sp",
                "1.0-1",
                "1.1"
            ]
        );
    }

    // -- Pre-release classification ---------------------------------------

    #[test]
    fn qualifier_five_pre_release_recognized() {
        for text in [
            "1.0-alpha-1",
            "1.0-beta-2",
            "1.0-milestone-3",
            "1.0-rc1",
            "1.0-cr1",
            "1.0-SNAPSHOT",
            "1.0a1",
            "1.0b1",
            "1.0m1",
            "2.0.0-Alpha3",
        ] {
            assert_eq!(release_of(text), Release::PreRelease, "{text}");
        }
    }

    /// The rule that costs the most if it is wrong in the other direction.
    /// Guava publishes `31.1-jre` and `31.1-android` as its *only* releases
    /// -- treating a qualifier as a pre-release by default would make the
    /// tool refuse to migrate Guava at all.
    #[test]
    fn qualifier_unknown_not_pre_release() {
        for text in [
            "31.1-jre",
            "31.1-android",
            "1.0-sp",
            "1.0-ga",
            "1.0-final",
            "1.0-release",
            "1.0",
            "2.0.1-xyz",
            "1.7.36",
        ] {
            assert_eq!(release_of(text), Release::General, "{text}");
        }
    }

    /// A pre-parsed version orders identically to the string form, so the
    /// sort path can parse each input once instead of once per comparison.
    #[test]
    fn order_parsed_like_text() {
        let mut parsed: Vec<Parsed> = ["1.0-sp", "1.0", "1.0-SNAPSHOT"]
            .iter()
            .map(|text| Parsed::new(text))
            .collect();

        parsed.sort();

        assert_eq!(parsed[0], Parsed::new("1.0-SNAPSHOT"));
        assert_eq!(parsed[1], Parsed::new("1.0"));
        assert_eq!(parsed[2], Parsed::new("1.0-sp"));
    }

    /// Nothing here may panic: version text arrives from a registry, and a
    /// malformed `maven-metadata.xml` must produce a bad ordering at worst,
    /// never a crash mid-enumeration.
    #[test]
    fn odd_input_does_not_panic() {
        for text in [
            "",
            ".",
            "-",
            "...",
            "---",
            "1..2",
            "1--2",
            ".1",
            "-1",
            "1.",
            "1-",
            "..1..",
            "a",
            "-a-",
            "1.0-",
            "\u{00e9}1.0",
            "1.0.0.0.0.0.0.0.0.0",
        ] {
            let _ = release_of(text);
            let _ = compare(text, "1.0");
            let _ = compare("1.0", text);
            let _ = compare(text, text);
        }
    }

    /// Versions written by buggy uploaders.
    ///
    /// `1.0--SNAPSHOT`, with the doubled separator, is real and in the wild.
    /// The doubled `-` inserts an implicit zero and an extra nesting level,
    /// so it is **not** equal to `1.0-SNAPSHOT` -- and that is the correct
    /// answer, because it is what Maven itself computes. Agreeing with
    /// Maven matters more than tidying the input: a tool that "helpfully"
    /// normalized these would resolve a different artifact than the build
    /// it is mirroring.
    ///
    /// What must hold is that the version stays usable: still a
    /// pre-release, still below its release, still ordered against its
    /// siblings.
    #[test]
    fn order_doubled_separator_sensible() {
        assert_eq!(release_of("1.0--SNAPSHOT"), Release::PreRelease);

        assert_below("1.0--SNAPSHOT", "1.0");
        assert_below("1.0--SNAPSHOT", "1.1");
        assert_below("0.9", "1.0--SNAPSHOT");

        // Distinct from the well-formed spelling, exactly as Maven has it.
        assert_ne!(order("1.0--SNAPSHOT", "1.0-SNAPSHOT"), Ordering::Equal);

        // And two of the malformed spelling still agree with each other,
        // so a registry holding only these can still be sorted.
        assert_same("1.0--SNAPSHOT", "1.0--SNAPSHOT");
        assert_below("1.0--alpha", "1.0--beta");
    }

    /// The other malformed shapes that turn up in long-lived internal
    /// repositories. None may panic, and each must land somewhere
    /// defensible rather than at the top of the list.
    #[test]
    fn malformed_wild_versions_stay_usable() {
        for text in [
            "1.0--SNAPSHOT",
            "1.0---SNAPSHOT",
            "1..0",
            "1.0.",
            "1.0-",
            "-1.0",
            "1.0-SNAPSHOT-",
            "1.0..SNAPSHOT",
        ] {
            // Whatever it parses to, it must not outrank a real release.
            assert_eq!(
                order(text, "99.0"),
                Ordering::Less,
                "{text} should be below 99.0"
            );

            let _ = release_of(text);
        }
    }

    /// Empty, and a lone separator, are all the same nothing.
    #[test]
    fn collapse_empty_and_separator_only() {
        assert_same("", "0");
        assert_same("", "0.0");
        assert_same("1.", "1");
        assert_same("1-", "1");
        assert_below("", "1");
    }
}
