//! Full health report generation.

use crate::compat::{CompatibilityChecker, CompatibilityResult, WasmTarget};
use crate::error::Result;
use crate::imports::{ImportAuditor, ImportAuditResult};
use crate::parser::{WasmModule, WasmParser};
use crate::size::{SizeAnalyzer, SizeReport};

/// Overall health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Warning => write!(f, "warning"),
            HealthStatus::Critical => write!(f, "critical"),
        }
    }
}

/// Complete health report for a wasm binary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WasmReport {
    pub health: HealthStatus,
    pub target: WasmTarget,
    pub total_bytes: usize,
    pub size: SizeReport,
    pub imports: ImportAuditResult,
    pub exports_summary: Vec<String>,
    pub compatibility: CompatibilityResult,
    pub function_count: usize,
    pub issues: Vec<String>,
}

impl WasmReport {
    /// Generate a full report from raw wasm bytes.
    pub fn generate(bytes: &[u8]) -> Result<WasmReport> {
        let module = WasmParser::parse(bytes)?;
        Self::from_module(&module)
    }

    /// Generate a full report from a parsed module.
    pub fn from_module(module: &WasmModule) -> Result<WasmReport> {
        let size = SizeAnalyzer::analyze(module)?;
        let imports = ImportAuditor::audit(module)?;
        let compatibility = CompatibilityChecker::check(module)?;

        let exports_summary: Vec<String> = module.exports.iter().map(|e| e.name.clone()).collect();

        let function_count = module.num_imported_funcs as usize + module.functions.len();

        // Collect issues
        let mut issues = Vec::new();

        if imports.has_risky_imports {
            issues.push("Module contains risky imports (filesystem, network, or system access)".into());
        }
        for w in &size.bloat_warnings {
            issues.push(w.clone());
        }
        if module.exports.is_empty() {
            issues.push("Module has no exports".into());
        }
        if compatibility.detected_target == WasmTarget::Hybrid {
            issues.push("Module mixes WASI and non-WASI imports (unusual)".into());
        }

        // Determine health
        let health = if issues.iter().any(|i| i.contains("risky imports")) {
            HealthStatus::Critical
        } else if !issues.is_empty() {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        Ok(WasmReport {
            health,
            target: compatibility.detected_target,
            total_bytes: module.total_size,
            size,
            imports,
            exports_summary,
            compatibility,
            function_count,
            issues,
        })
    }

    /// Render the report as pretty-printed JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
