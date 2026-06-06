//! # wasm-verify
//!
//! A WebAssembly binary analysis, verification, and health reporting library.
//!
//! Provides tools to parse `.wasm` binaries, measure sizes, verify exports,
//! audit imports for risky dependencies, check compatibility targets, and
//! generate comprehensive JSON health reports.

mod parser;
mod size;
mod exports;
mod imports;
mod compat;
mod report;
mod error;

pub use error::{WasmVerifyError, Result};
pub use parser::{WasmParser, WasmModule, FuncType, FunctionSig, ImportEntry, ExportEntry, ValType};
pub use size::{SizeAnalyzer, SizeReport, FunctionSize};
pub use exports::{ExportChecker, ExportCheckResult};
pub use imports::{ImportAuditor, ImportAuditResult, RiskLevel};
pub use compat::{CompatibilityChecker, CompatibilityResult, WasmTarget};
pub use report::{WasmReport, HealthStatus};

/// Convenience function: generate a full health report for a wasm binary.
pub fn analyze_wasm(bytes: &[u8]) -> Result<WasmReport> {
    WasmReport::generate(bytes)
}
