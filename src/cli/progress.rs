//! Progress bars on the terminal: the `ansi` rendering of
//! [`core::progress`](crate::core::progress).
//!
//! ```text
//!   copy [##########----------] 412/1030
//!     resolve pkg:npm/lodash
//! ```
//!
//! A node with a total renders as a bar; one without renders as an activity
//! line, and becomes a bar once its total grows. Children indent beneath
//! their parent.
//!
//! The bars start hidden. [`Logging`](super::logging::Logging) shows them
//! once the configuration says the output is `ansi` and the level is `warn`
//! or more verbose, and routes terminal log lines through [`Bars::suspend`]
//! so a line never tears through a bar.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::core::progress::{NodeId, ProgressSink, Unit};

/// Indentation per level of nesting.
const INDENT: &str = "  ";

/// Filled, current, and empty cells; plain ASCII.
const BAR_CHARS: &str = "##-";

const ITEMS_BAR: &str = "{prefix}{msg} [{bar:30}] {pos}/{len}";
const BYTES_BAR: &str = "{prefix}{msg} [{bar:30}] {bytes}/{total_bytes}";
const ITEMS_ACTIVITY: &str = "{prefix}{msg} {pos}";
const BYTES_ACTIVITY: &str = "{prefix}{msg} {bytes}";

/// Whether the bars draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Display {
    Shown,
    Hidden,
}

/// Whether a node knows its total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extent {
    Known,
    Unknown,
}

#[derive(Debug)]
struct Entry {
    bar: ProgressBar,
    depth: usize,
    unit: Unit,
}

/// The progress tree, drawn with `indicatif`.
#[derive(Debug)]
pub struct Bars {
    multi: MultiProgress,
    nodes: Mutex<HashMap<NodeId, Entry>>,
    next: AtomicU64,
}

impl Bars {
    pub(super) fn hidden() -> Self {
        Self {
            multi: MultiProgress::with_draw_target(ProgressDrawTarget::hidden()),
            nodes: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
        }
    }

    /// Draw to standard error, or not at all.
    ///
    /// `indicatif` draws nothing to standard error when it is not a
    /// terminal, so a redirected run shows no bars either way.
    pub(super) fn display(&self, display: Display) {
        let target = match display {
            Display::Shown => ProgressDrawTarget::stderr(),
            Display::Hidden => ProgressDrawTarget::hidden(),
        };

        self.multi.set_draw_target(target);
    }

    /// Run `write` with the bars cleared, then redraw them.
    pub(super) fn suspend<R>(&self, write: impl FnOnce() -> R) -> R {
        self.multi.suspend(write)
    }
}

fn style(unit: Unit, extent: Extent) -> ProgressStyle {
    let template = match (unit, extent) {
        (Unit::Items, Extent::Known) => ITEMS_BAR,
        (Unit::Bytes, Extent::Known) => BYTES_BAR,
        (Unit::Items, Extent::Unknown) => ITEMS_ACTIVITY,
        (Unit::Bytes, Extent::Unknown) => BYTES_ACTIVITY,
    };

    ProgressStyle::with_template(template)
        .expect("templates are constant and tested")
        .progress_chars(BAR_CHARS)
}

impl ProgressSink for Bars {
    fn open(
        &self,
        parent: Option<NodeId>,
        label: String,
        unit: Unit,
        total: Option<u64>,
    ) -> NodeId {
        let id = NodeId(self.next.fetch_add(1, Ordering::Relaxed));

        let extent = match total {
            Some(_) => Extent::Known,
            None => Extent::Unknown,
        };

        // Hidden until it joins the display: a bar left to itself draws
        // straight to standard error, whatever the display says.
        let bar = ProgressBar::with_draw_target(total, ProgressDrawTarget::hidden())
            .with_style(style(unit, extent));

        let mut nodes = self.nodes.lock().expect("not poisoned");

        // A child sits directly under its parent; a node whose parent has
        // already closed is drawn as a root rather than lost.
        let above = parent.and_then(|parent| nodes.get(&parent));
        let depth = above.map_or(0, |above| above.depth + 1);

        // Labelled before it joins the display, so no frame draws it bare.
        bar.set_prefix(INDENT.repeat(depth));
        bar.set_message(label);

        let bar = match above {
            Some(above) => self.multi.insert_after(&above.bar, bar),
            None => self.multi.add(bar),
        };

        nodes.insert(id, Entry { bar, depth, unit });

        id
    }

    fn advance(&self, id: NodeId, amount: u64) {
        let nodes = self.nodes.lock().expect("not poisoned");

        if let Some(entry) = nodes.get(&id) {
            entry.bar.inc(amount);
        }
    }

    fn grow_total(&self, id: NodeId, additional: u64) {
        let nodes = self.nodes.lock().expect("not poisoned");

        let Some(entry) = nodes.get(&id) else {
            return;
        };

        // `inc_length` ignores a bar with no length, so the first growth
        // sets one and turns the activity line into a bar.
        let Some(length) = entry.bar.length() else {
            entry.bar.set_length(additional);
            entry.bar.set_style(style(entry.unit, Extent::Known));
            return;
        };

        entry.bar.set_length(length.saturating_add(additional));
    }

    fn close(&self, id: NodeId) {
        let removed = self.nodes.lock().expect("not poisoned").remove(&id);

        let Some(entry) = removed else {
            return;
        };

        entry.bar.finish_and_clear();
        self.multi.remove(&entry.bar);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::core::progress;

    #[test]
    fn templates_parse() {
        for unit in [Unit::Items, Unit::Bytes] {
            for extent in [Extent::Known, Extent::Unknown] {
                let _ = style(unit, extent);
            }
        }
    }

    #[test]
    fn node_child_indents_under_parent() {
        let bars = Arc::new(Bars::hidden());
        let root = progress::root(bars.clone(), "copy", Unit::Items, Some(3));
        let child = root.child("resolve x", Unit::Items, None);

        let nodes = bars.nodes.lock().unwrap();
        let depths: Vec<usize> = {
            let mut depths: Vec<usize> = nodes.values().map(|entry| entry.depth).collect();
            depths.sort();
            depths
        };

        assert_eq!(depths, [0, 1]);

        drop(nodes);
        drop(child);
        drop(root);
    }

    #[test]
    fn node_unknown_total_grows_length() {
        let bars = Arc::new(Bars::hidden());
        let root = progress::root(bars.clone(), "scan", Unit::Items, None);

        root.grow_total(10);
        root.grow_total(5);

        let nodes = bars.nodes.lock().unwrap();
        let entry = nodes.values().next().expect("open");

        assert_eq!(entry.bar.length(), Some(15));
    }

    #[test]
    fn node_closed_forgotten() {
        let bars = Arc::new(Bars::hidden());
        let root = progress::root(bars.clone(), "copy", Unit::Items, Some(1));

        root.advance(1);
        drop(root);

        assert!(bars.nodes.lock().unwrap().is_empty());
    }

    #[test]
    fn suspend_returns_result() {
        let bars = Bars::hidden();

        assert_eq!(bars.suspend(|| 7), 7);
    }
}
