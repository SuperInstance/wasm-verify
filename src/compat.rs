//! Compatibility / target detection.

use crate::error::Result;
use crate::parser::WasmModule;

/// Detected wasm target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum WasmTarget {
    /// Pure wasm — no WASI imports, designed for browsers or bare execution.
    Wasm32UnknownUnknown,
    /// WASI-enabled — imports from wasi_snapshot_preview1 or wasi_unstable.
    Wasm32Wasi,
    /// Hybrid — has both WASI and non-WASI imports (unusual).
    Hybrid,
    /// Cannot determine (empty module or ambiguous).
    Unknown,
}

impl std::fmt::Display for WasmTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmTarget::Wasm32UnknownUnknown => write!(f, "wasm32-unknown-unknown"),
            WasmTarget::Wasm32Wasi => write!(f, "wasm32-wasi"),
            WasmTarget::Hybrid => write!(f, "hybrid"),
            WasmTarget::Unknown => write!(f, "unknown"),
        }
    }
}

/// Compatibility check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CompatibilityResult {
    pub detected_target: WasmTarget,
    pub wasi_imports: Vec<String>,
    pub non_wasi_imports: Vec<String>,
    pub can_run_in_browser: bool,
    pub can_run_in_wasi_runtime: bool,
    pub notes: Vec<String>,
}

pub struct CompatibilityChecker;

impl CompatibilityChecker {
    /// Detect the wasm target from imports and structure.
    pub fn check(module: &WasmModule) -> Result<CompatibilityResult> {
        let wasi_prefixes = ["wasi_snapshot_preview1", "wasi_unstable"];

        let mut wasi_imports: Vec<String> = Vec::new();
        let mut non_wasi_imports: Vec<String> = Vec::new();

        for imp in &module.imports {
            let label = format!("{}::{}", imp.module, imp.field);
            if wasi_prefixes.iter().any(|p| imp.module.starts_with(p)) {
                wasi_imports.push(label);
            } else {
                non_wasi_imports.push(label);
            }
        }

        let detected_target = if !wasi_imports.is_empty() && !non_wasi_imports.is_empty() {
            WasmTarget::Hybrid
        } else if !wasi_imports.is_empty() {
            WasmTarget::Wasm32Wasi
        } else if !non_wasi_imports.is_empty() {
            WasmTarget::Wasm32UnknownUnknown
        } else if !module.exports.is_empty() || !module.functions.is_empty() {
            // No imports but has defined functions — pure wasm
            WasmTarget::Wasm32UnknownUnknown
        } else {
            WasmTarget::Unknown
        };

        let can_run_in_browser = wasi_imports.is_empty();
        let can_run_in_wasi_runtime = !wasi_imports.is_empty() || module.imports.is_empty();

        let mut notes = Vec::new();

        match detected_target {
            WasmTarget::Wasm32UnknownUnknown => {
                notes.push("Pure wasm module — suitable for browser and bare runtimes.".into());
            }
            WasmTarget::Wasm32Wasi => {
                notes.push("WASI module — requires a WASI-compatible runtime (Wasmtime, WasmEdge, etc.).".into());
                notes.push("Cannot run directly in browsers without WASI polyfill.".into());
            }
            WasmTarget::Hybrid => {
                notes.push("Unusual: mixes WASI and non-WASI imports.".into());
            }
            WasmTarget::Unknown => {
                notes.push("No imports detected — module is fully self-contained.".into());
                notes.push("Compatible with any wasm runtime.".into());
            }
        }

        if module.exports.is_empty() {
            notes.push("Warning: module has no exports.".into());
        }

        // Check for memory export (needed for JS interop)
        let has_memory_export = module.exports.iter().any(|e| e.kind == crate::parser::EXT_MEMORY);
        if !has_memory_export && detected_target == WasmTarget::Wasm32UnknownUnknown {
            notes.push("No exported memory — JS host cannot access linear memory directly.".into());
        }

        Ok(CompatibilityResult {
            detected_target,
            wasi_imports,
            non_wasi_imports,
            can_run_in_browser,
            can_run_in_wasi_runtime,
            notes,
        })
    }
}
