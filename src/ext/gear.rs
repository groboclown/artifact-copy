//! The gearing: where an extension point meets an out-of-process
//! extension.
//!
//! ```text
//!   registry --kind is built in----------> built-in (holds an ExtHost)
//!          \--kind names an `extensions`--> launch --> Gear --> point adapter
//! ```
//!
//! A built-in holds an [`ExtHost`](super::ExtHost) and does its own I/O
//! through it. An extension does none: the gearing launches it, gives it a
//! scratch directory of its own (usually a temporary directory, possibly one
//! per thread), stages what it needs there, performs every request it asks
//! for through the host, and translates between the extension point's trait
//! and the stateless, file-based protocol below. Each point's adapter lives
//! beside its trait (`repo`, `enumerate`, `lock`) and wraps a [`Gear`], so this
//! module never names them.
//!
//! The Target gearing is where ask, answer, and prepare belong: an
//! extension cannot hold a lock or read before it writes, so it states
//! what it needs to know, the gearing answers, and the extension returns
//! the operations to perform.
//!
//! An ecosystem is extensible without a gearing: an extension's metadata
//! may declare one by supplying the constants the typed
//! [`Ecosystem`](crate::ecosystem::Ecosystem) methods return.
//!
//! Built-ins answer through typed trait methods and never build the
//! protocol types here; only a gearing reads them.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::config::Extension;
use crate::core::ctx::Ctx;
use crate::core::error::{Error, Result};
use crate::ext::ExtHost;

mod envelope;
mod host;
mod protocol;
#[cfg(test)]
pub(crate) mod testing;
mod wasm;

pub(crate) use envelope::check;
pub use protocol::{Description, EcosystemDesc, PointKind};
pub(crate) use protocol::{PROTOCOL_SCHEMA, PROTOCOL_VERSION};

/// The correlation id of the next message, unique within the process.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A running extension, for a point adapter to wrap.
///
/// Cheap to clone: the compiled module is shared, and every invocation
/// gets an instance of its own.
#[derive(Clone)]
pub struct Gear {
    runtime: Arc<wasm::Runtime>,
    description: Description,
}

impl fmt::Debug for Gear {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gear")
            .field("name", &self.runtime.name())
            .field("description", &self.description)
            .finish()
    }
}

/// Launch the extension a configured `kind` names.
///
/// Compiles the module and asks it what it is, so an incompatible or
/// broken extension is refused while the configuration is read rather than
/// part way through a run. Only a WASM module runs; an executable is
/// refused as unimplemented.
pub fn launch(name: &str, extension: &Extension) -> Result<Gear> {
    let module = match extension {
        Extension::Wasm { module, .. } => module,
        Extension::Executable { .. } => {
            return Err(Error::Unimplemented("running an executable extension"));
        }
    };

    start(wasm::Runtime::load(name, module)?)
}

/// Describe a compiled module, and hold it ready for invocation.
fn start(runtime: wasm::Runtime) -> Result<Gear> {
    // Blocking is safe: a description needs no host call, so nothing
    // inside it waits on the async runtime.
    let description = futures::executor::block_on(describe(&runtime))?;

    Ok(Gear {
        runtime: Arc::new(runtime),
        description,
    })
}

/// Ask a module what it is, refusing one this build cannot talk to.
async fn describe(runtime: &wasm::Runtime) -> Result<Description> {
    let answer = runtime
        .handle(&envelope::Envelope::describe(&next_id()), None)
        .await?;

    let output = match answer.dir {
        envelope::Dir::Describe => answer.output.unwrap_or_default(),
        _ => return Err(runtime.broken(format!("describe answered {}", answer.explain()))),
    };

    check("Description", &output).map_err(|detail| runtime.broken(detail))?;

    let description: Description =
        serde_json::from_value(output).map_err(|err| runtime.broken(err.to_string()))?;

    if !description.is_compatible() {
        return Err(Error::Config(format!(
            "extension {:?} speaks protocol {}; this build speaks {PROTOCOL_VERSION}",
            runtime.name(),
            description.protocol,
        )));
    }

    Ok(description)
}

impl Gear {
    /// The configured extension name.
    pub(crate) fn name(&self) -> &str {
        self.runtime.name()
    }

    /// What the extension said about itself at launch.
    pub(crate) fn description(&self) -> &Description {
        &self.description
    }

    /// Perform `op` on `point`, serving host calls through `host`.
    ///
    /// Returns the `output` of a `result`. A `failed` answer becomes an
    /// [`Error::Extension`] carrying the extension's code, so a proxy still
    /// reads `artifact-not-found` as "ask the next upstream".
    pub(crate) async fn invoke(
        &self,
        point: PointKind,
        op: &str,
        input: Value,
        host: Arc<dyn ExtHost>,
        ctx: &Ctx,
    ) -> Result<Value> {
        let request = envelope::Envelope::invoke(&next_id(), point, op, input);
        let calling = host::Calling {
            host,
            ctx: ctx.clone(),
        };

        let answer = self.runtime.handle(&request, Some(calling)).await?;

        if answer.id != request.id {
            return Err(self.runtime.broken(format!(
                "answered message {:?} to {:?}",
                answer.id, request.id
            )));
        }

        match answer.dir {
            envelope::Dir::Result => Ok(answer.output.unwrap_or_default()),

            envelope::Dir::Failed | envelope::Dir::Problem => Err(Error::Extension {
                extension: self.runtime.name().to_owned(),
                code: answer.problem_code(),
                detail: answer.explain(),
            }),

            other => Err(self
                .runtime
                .broken(format!("answered {op:?} with {other:?}"))),
        }
    }
}

fn next_id() -> String {
    NEXT_ID.fetch_add(1, Ordering::Relaxed).to_string()
}
