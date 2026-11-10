//! How far a paged listing may read: the `max-listing-rows` option.

use crate::core::error::{Error, Result};
use crate::ext::Options;

/// The option that caps the rows one paged listing may read.
const MAX_LISTING_ROWS_OPTION: &str = "max-listing-rows";

/// How many pages one paged listing may read before giving up.
///
/// A guard against a server that never stops paging, not a limit a real
/// repository should reach. One holding years of daily builds raises it
/// through `max-listing-rows`, counted in rows because page sizes differ
/// by server: 20,000 rows is 400 Nexus pages of 50, or 200 of 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageCap {
    pages: u32,
}

impl PageCap {
    /// The configured rows as pages of `per_page`, or `default_rows` when
    /// unset. A partial page counts as a whole one.
    pub fn from_options(options: &Options, per_page: u32, default_rows: u32) -> Result<Self> {
        let Some(rows) = options.integer(MAX_LISTING_ROWS_OPTION)? else {
            return Ok(Self::of_rows(default_rows, per_page));
        };

        let rows = u32::try_from(rows)
            .ok()
            .filter(|rows| *rows > 0)
            .ok_or_else(|| {
                Error::Config(format!(
                    "{MAX_LISTING_ROWS_OPTION} is {rows}, which is not between 1 and {}",
                    u32::MAX
                ))
            })?;

        Ok(Self::of_rows(rows, per_page))
    }

    pub fn of_rows(rows: u32, per_page: u32) -> Self {
        Self {
            pages: rows.div_ceil(per_page),
        }
    }

    pub fn pages(self) -> u32 {
        self.pages
    }

    /// Why a listing that reached the cap stopped, naming the option that
    /// raises it.
    pub fn exhausted(self) -> String {
        format!(
            "it did not end within {} pages; raise '{MAX_LISTING_ROWS_OPTION}' for a \
             repository that large",
            self.pages
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::problem::Code;

    fn page_cap(rows: serde_json::Value) -> Result<PageCap> {
        let options =
            crate::ext::testing::options(serde_json::json!({ MAX_LISTING_ROWS_OPTION: rows }));

        PageCap::from_options(&options, 50, 10_000)
    }

    #[test]
    fn page_cap_defaults_when_unset() {
        let cap = PageCap::from_options(&Options::default(), 50, 10_000).expect("default");

        assert_eq!(cap.pages(), 200);
    }

    #[test]
    fn page_cap_rounds_partial_page_up() {
        // 101 rows at 50 a page needs a third page for the last row.
        assert_eq!(page_cap(serde_json::json!(101)).expect("cap").pages(), 3);
        assert_eq!(
            page_cap(serde_json::json!(100_000)).expect("cap").pages(),
            2_000
        );
    }

    #[test]
    fn page_cap_refuses_non_positive_rows() {
        for rows in [0, -5] {
            let err = page_cap(serde_json::json!(rows)).expect_err("refused");

            assert_eq!(err.code(), Code::ConfigInvalid);
            assert!(err.to_string().contains(MAX_LISTING_ROWS_OPTION));
        }
    }

    #[test]
    fn page_cap_refuses_text() {
        assert!(page_cap(serde_json::json!("lots")).is_err());
    }

    #[test]
    fn page_cap_exhausted_names_option() {
        let cap = page_cap(serde_json::json!(100)).expect("cap");

        assert!(cap.exhausted().contains(MAX_LISTING_ROWS_OPTION));
    }
}
