#[cfg(feature = "no_std")]
use wasm_builder_runner::{build_current_project, WasmBuilderSource};

/// It does nothing if "no_std" feature is not defined.
fn main() {
    #[cfg(feature ="no_std")]
    build_current_project(
        "wasm_binary.rs",
        WasmBuilderSource::Crates("1.0.8"),
    );
}
