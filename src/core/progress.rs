//! Stacked progress reporting.
//!
//! Progress is a *tree*, not a bar: the end user needs to see overall
//! completion and per-artifact completion at the same time.
//!
//! ```text
//!   overall   [######--------]  412/1030 artifacts    1.2/8.4 GB
//!     download commons-lang3-3.14.0.jar  [########--]  412/580 KB
//!     download slf4j-api-2.0.9.jar       [##--------]   31/142 KB
//! ```
//!
//! Totals are usually unknown when a node starts and grow as inspection
//! results stream in, so [`Node::grow_total`] exists and a `None` total
//! renders as indeterminate rather than as zero.

use std::sync::Arc;

/// A handle to one node in the progress tree.
///
/// Dropping it finishes the node.  Cloning shares it, so a node can be
/// advanced from several tasks.
#[derive(Debug, Clone)]
pub struct Node {
    handle: Arc<Handle>,
}

/// The state every clone of a [`Node`] shares.
#[derive(Debug)]
struct Handle {
    sink: Arc<dyn ProgressSink>,
    id: NodeId,
}

impl Handle {
    fn node(sink: Arc<dyn ProgressSink>, id: NodeId) -> Node {
        Node {
            handle: Arc::new(Handle { sink, id }),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Dropped with the last clone of its node, so a clone going out of
        // scope does not end the work early.
        self.sink.close(self.id);
    }
}

/// Opaque identity of a node within its sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

/// What a node counts, which decides how its numbers are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Rendered with a byte suffix: `1.2/8.4 GB`.
    Bytes,

    /// Rendered as a plain count: `412/1030 artifacts`.
    Items,
}

impl Node {
    /// Open a child node beneath this one.
    pub fn child(&self, label: impl Into<String>, unit: Unit, total: Option<u64>) -> Node {
        let sink = &self.handle.sink;
        let id = sink.open(Some(self.handle.id), label.into(), unit, total);

        Handle::node(Arc::clone(sink), id)
    }

    /// Advance by `amount`.
    pub fn advance(&self, amount: u64) {
        self.handle.sink.advance(self.handle.id, amount);
    }

    /// Raise the total, for work found after the node opened.
    pub fn grow_total(&self, additional: u64) {
        self.handle.sink.grow_total(self.handle.id, additional);
    }

    /// Mark this node complete.  Idempotent.
    pub fn finish(&self) {
        self.handle.sink.close(self.handle.id);
    }
}

/// Renders progress.  Implementations exist per `output-format`, and an
/// embedder can supply its own to receive the events without any terminal
/// rendering.
pub trait ProgressSink: std::fmt::Debug + Send + Sync {
    /// Open a node, optionally beneath a parent.  A `None` total renders as
    /// indeterminate.
    fn open(&self, parent: Option<NodeId>, label: String, unit: Unit, total: Option<u64>)
    -> NodeId;

    fn advance(&self, id: NodeId, amount: u64);

    fn grow_total(&self, id: NodeId, additional: u64);

    fn close(&self, id: NodeId);
}

/// A sink that renders nothing.
///
/// Used by `--quiet`, by tests, and as the default when no sink is supplied.
#[derive(Debug, Default)]
pub struct NullSink;

impl ProgressSink for NullSink {
    fn open(
        &self,
        _parent: Option<NodeId>,
        _label: String,
        _unit: Unit,
        _total: Option<u64>,
    ) -> NodeId {
        NodeId(0)
    }

    fn advance(&self, _id: NodeId, _amount: u64) {}

    fn grow_total(&self, _id: NodeId, _additional: u64) {}

    fn close(&self, _id: NodeId) {}
}

/// Open a root node on a sink.
pub fn root(
    sink: Arc<dyn ProgressSink>,
    label: impl Into<String>,
    unit: Unit,
    total: Option<u64>,
) -> Node {
    let id = sink.open(None, label.into(), unit, total);

    Handle::node(sink, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every event so tests can assert on the tree shape.
    #[derive(Debug, Default)]
    struct Recorder {
        events: Mutex<Vec<String>>,
        next: Mutex<u64>,
    }

    impl ProgressSink for Recorder {
        fn open(
            &self,
            parent: Option<NodeId>,
            label: String,
            _unit: Unit,
            total: Option<u64>,
        ) -> NodeId {
            let mut next = self.next.lock().unwrap();
            *next += 1;

            self.events.lock().unwrap().push(format!(
                "open {label} parent={:?} total={total:?}",
                parent.map(|p| p.0)
            ));

            NodeId(*next)
        }

        fn advance(&self, id: NodeId, amount: u64) {
            self.events
                .lock()
                .unwrap()
                .push(format!("advance {} {amount}", id.0));
        }

        fn grow_total(&self, id: NodeId, additional: u64) {
            self.events
                .lock()
                .unwrap()
                .push(format!("grow {} {additional}", id.0));
        }

        fn close(&self, id: NodeId) {
            self.events.lock().unwrap().push(format!("close {}", id.0));
        }
    }

    #[test]
    fn children_nest_under_parent() {
        let sink = Arc::new(Recorder::default());
        let overall = root(sink.clone(), "overall", Unit::Items, Some(10));

        let child = overall.child("download x", Unit::Bytes, None);
        child.advance(512);
        child.finish();

        let events = sink.events.lock().unwrap().clone();

        assert_eq!(events[0], "open overall parent=None total=Some(10)");
        assert_eq!(events[1], "open download x parent=Some(1) total=None");
        assert_eq!(events[2], "advance 2 512");
        assert_eq!(events[3], "close 2");
    }

    /// Inspection results stream in, so a total that was unknown must be
    /// raisable.
    #[test]
    fn totals_can_grow_after_opening() {
        let sink = Arc::new(Recorder::default());
        let node = root(sink.clone(), "scan", Unit::Items, None);

        node.grow_total(1000);
        node.advance(1);

        let events = sink.events.lock().unwrap().clone();

        assert_eq!(events[1], "grow 1 1000");
    }

    /// A clone shares the node, so only the last one dropped closes it.
    #[test]
    fn clone_closes_on_last_drop() {
        let sink = Arc::new(Recorder::default());
        let node = root(sink.clone(), "scan", Unit::Items, None);

        let clone = node.clone();
        drop(clone);
        assert!(!sink.events.lock().unwrap().contains(&"close 1".to_string()));

        drop(node);
        let events = sink.events.lock().unwrap().clone();
        assert_eq!(events, ["open scan parent=None total=None", "close 1"]);
    }

    #[test]
    fn null_sink_swallows_everything() {
        let node = root(Arc::new(NullSink), "x", Unit::Bytes, Some(1));

        node.advance(1);
        node.grow_total(1);
        node.finish();
    }
}
