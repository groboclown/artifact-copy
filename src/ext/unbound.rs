//! Capabilities that refuse every request, for a caller that will not fetch.

use std::sync::Arc;

use super::{Capabilities, DenyingHost, ExtHost};
use crate::core::error::Result;

/// Builds repositories without capabilities, for a caller that will not
/// fetch.
///
/// `validate-config` is the case: it asks whether everything configured can
/// be constructed, and starting an HTTP client per host to answer that
/// would be a side effect of checking a file.
///
/// Every host is one shared [`DenyingHost`], built on first use.
#[derive(Default)]
pub struct Unbound {
    denying: Option<Arc<DenyingHost>>,
}

impl Capabilities for Unbound {
    fn host(&mut self, _name: &str, _base: &str) -> Result<Arc<dyn ExtHost>> {
        self.denying()
    }

    fn keyservers(&mut self, _urls: &[String]) -> Result<Arc<dyn ExtHost>> {
        self.denying()
    }
}

impl Unbound {
    fn denying(&mut self) -> Result<Arc<dyn ExtHost>> {
        if let Some(denying) = &self.denying {
            return Ok(Arc::clone(denying) as Arc<dyn ExtHost>);
        }

        let denying = Arc::new(DenyingHost::new()?);

        self.denying = Some(Arc::clone(&denying));

        Ok(denying)
    }
}
