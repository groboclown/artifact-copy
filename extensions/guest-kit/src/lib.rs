//! The guest side of the artifact-copy extension protocol, shared by every
//! bundled WASM extension.
//!
//! An extension supplies a [`Source`] and exports it with [`export!`]:
//!
//! ```text
//!   host --ac_handle--> export! --> protocol::handle --> Source::answer
//!                                                          | Host::fetch
//!   host <--host_call------------- abi::WasmHost <---------+
//! ```

pub mod protocol;
pub mod wildcard;

#[cfg(target_family = "wasm")]
pub mod abi;

pub use protocol::{Failure, Host, Source};

/// Export the guest ABI (`ac_alloc`, `ac_free`, `ac_handle`) for `$source`,
/// a value implementing [`Source`], named by a `crate::` path such as
/// `crate::protocol::NodeJs`.
///
/// A macro so the symbols belong to the extension's own `cdylib`; a
/// `no_mangle` function in a dependency is not reliably exported.
#[macro_export]
macro_rules! export {
    ($source:expr) => {
        #[cfg(target_family = "wasm")]
        mod guest_exports {
            #[unsafe(no_mangle)]
            pub extern "C" fn ac_alloc(len: i32) -> i32 {
                $crate::abi::alloc(len)
            }

            /// # Safety
            ///
            /// `ptr` and `len` must come from one `ac_alloc` call, freed once.
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn ac_free(ptr: i32, len: i32) {
                // SAFETY: the caller's contract.
                unsafe { $crate::abi::free(ptr, len) }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn ac_handle(ptr: i32, len: i32) -> i64 {
                $crate::abi::handle(ptr, len, &$source)
            }
        }
    };
}
