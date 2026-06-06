//! Import auditing and risk flagging.

use crate::error::Result;
use crate::parser::{ImportEntry, WasmModule, EXT_FUNC, EXT_MEMORY, EXT_GLOBAL, EXT_TABLE};

/// Risk level for an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RiskLevel {
    Safe,
    Caution,
    Risky,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Safe => write!(f, "safe"),
            RiskLevel::Caution => write!(f, "caution"),
            RiskLevel::Risky => write!(f, "risky"),
        }
    }
}

/// Risk assessment for one import.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportRisk {
    pub module: String,
    pub field: String,
    pub kind: String,
    pub risk: RiskLevel,
    pub reason: String,
}

/// Overall audit result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportAuditResult {
    pub total_imports: usize,
    pub risks: Vec<ImportRisk>,
    pub has_risky_imports: bool,
    pub has_caution_imports: bool,
    pub summary: String,
}

fn kind_str(kind: u32) -> &'static str {
    match kind {
        EXT_FUNC => "function",
        EXT_TABLE => "table",
        EXT_MEMORY => "memory",
        EXT_GLOBAL => "global",
        _ => "unknown",
    }
}

// Modules/prefixes considered risky
const RISKY_PREFIXES: &[&str] = &[
    "wasi_snapshot_preview1", // WASI — filesystem, network, etc.
    "wasi_unstable",
];

// Specific fields that are risky
const RISKY_FIELDS: &[&str] = &[
    // Network
    "sock_accept", "sock_recv", "sock_send", "sock_connect", "sock_shutdown",
    "sock_bind", "sock_listen",
    // Filesystem
    "path_open", "path_rename", "path_remove_directory", "path_unlink_file",
    "path_create_directory", "path_symlink", "path_link",
    "fd_read", "fd_write", "fd_readdir", "fd_seek", "fd_close", "fd_sync",
    "fd_allocate", "fd_filestat_get", "fd_filestat_set_size",
    // Random / entropy
    "random_get",
    // Process / env
    "proc_exit", "proc_raise", "environ_get", "environ_sizes_get",
    // Clocks (timing side-channels)
    "clock_time_get", "clock_res_get",
];

// Fields that are caution-worthy but not outright risky
const CAUTION_FIELDS: &[&str] = &[
    "args_get", "args_sizes_get",
];

pub struct ImportAuditor;

impl ImportAuditor {
    /// Audit all imports for risk.
    pub fn audit(module: &WasmModule) -> Result<ImportAuditResult> {
        let mut risks = Vec::new();

        for imp in &module.imports {
            let (risk, reason) = classify_import(imp);
            risks.push(ImportRisk {
                module: imp.module.clone(),
                field: imp.field.clone(),
                kind: kind_str(imp.kind).to_owned(),
                risk,
                reason,
            });
        }

        let has_risky = risks.iter().any(|r| r.risk == RiskLevel::Risky);
        let has_caution = risks.iter().any(|r| r.risk == RiskLevel::Caution);

        let summary = if has_risky {
            format!("{} risky import(s) detected", risks.iter().filter(|r| r.risk == RiskLevel::Risky).count())
        } else if has_caution {
            "No risky imports, some caution items".into()
        } else if risks.is_empty() {
            "No imports — fully self-contained module".into()
        } else {
            "All imports are safe".into()
        };

        Ok(ImportAuditResult {
            total_imports: module.imports.len(),
            risks,
            has_risky_imports: has_risky,
            has_caution_imports: has_caution,
            summary,
        })
    }
}

fn classify_import(imp: &ImportEntry) -> (RiskLevel, String) {
    // WASI modules are inherently caution+
    let is_wasi = RISKY_PREFIXES.iter().any(|p| imp.module.starts_with(p));

    if is_wasi {
        if RISKY_FIELDS.iter().any(|f| &imp.field == f) {
            let category = categorize_field(&imp.field);
            return (RiskLevel::Risky, format!("WASI import with {} access", category));
        }
        if CAUTION_FIELDS.iter().any(|f| &imp.field == f) {
            return (RiskLevel::Caution, "WASI import with process info access".into());
        }
        return (RiskLevel::Caution, "WASI import".into());
    }

    // Non-WASI imports are generally safe for wasm32-unknown-unknown
    // but flag anything with "env" + suspicious field names
    if imp.module == "env" {
        if ["memory", "memory.size", "memory.grow"].iter().any(|f| &imp.field == f) {
            return (RiskLevel::Safe, "Standard memory import".into());
        }
        return (RiskLevel::Safe, "Environment import".into());
    }

    (RiskLevel::Safe, "Non-WASI import".into())
}

fn categorize_field(field: &str) -> &'static str {
    if field.starts_with("sock_") { "network" }
    else if field.starts_with("fd_") || field.starts_with("path_") { "filesystem" }
    else if field == "random_get" { "random/entropy" }
    else if field.starts_with("proc_") || field.starts_with("environ") { "process/environment" }
    else if field.starts_with("clock_") { "clock/timing" }
    else { "system" }
}
