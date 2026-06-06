//! Export verification.

use crate::error::Result;
use crate::parser::{ExportEntry, FuncType, ValType, WasmModule, EXT_FUNC};

/// Result of checking a single expected export.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportCheck {
    pub name: String,
    pub found: bool,
    pub signature_match: bool,
    pub expected_sig: Option<String>,
    pub actual_sig: Option<String>,
}

/// Overall export check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportCheckResult {
    pub all_present: bool,
    pub all_signatures_match: bool,
    pub checks: Vec<ExportCheck>,
    pub extra_exports: Vec<ExportEntry>,
}

pub struct ExportChecker;

impl ExportChecker {
    /// Verify that all `expected` exports exist and have matching function signatures.
    ///
    /// Each tuple is (export_name, expected_params, expected_results).
    pub fn check(
        module: &WasmModule,
        expected: &[(&str, &[ValType], &[ValType])],
    ) -> Result<ExportCheckResult> {
        let func_exports: Vec<&ExportEntry> = module.exports.iter().filter(|e| e.kind == EXT_FUNC).collect();

        let mut checks = Vec::new();

        for &(name, params, results) in expected {
            let expected_type = FuncType {
                params: params.to_vec(),
                results: results.to_vec(),
            };

            if let Some(export) = func_exports.iter().find(|e| e.name == name) {
                let actual_type = resolve_func_type(module, export.index);
                let sig_match = actual_type == expected_type;
                checks.push(ExportCheck {
                    name: name.to_owned(),
                    found: true,
                    signature_match: sig_match,
                    expected_sig: Some(expected_type.to_string()),
                    actual_sig: Some(actual_type.to_string()),
                });
            } else {
                checks.push(ExportCheck {
                    name: name.to_owned(),
                    found: false,
                    signature_match: false,
                    expected_sig: Some(expected_type.to_string()),
                    actual_sig: None,
                });
            }
        }

        let expected_names: std::collections::HashSet<&str> = expected.iter().map(|(n, _, _)| *n).collect();
        let extra_exports: Vec<ExportEntry> = module
            .exports
            .iter()
            .filter(|e| !expected_names.contains(e.name.as_str()))
            .cloned()
            .collect();

        let all_present = checks.iter().all(|c| c.found);
        let all_signatures_match = checks.iter().all(|c| c.signature_match);

        Ok(ExportCheckResult {
            all_present,
            all_signatures_match,
            checks,
            extra_exports,
        })
    }

    /// Convenience: check only that the given export names exist (ignoring signatures).
    pub fn check_names_exist<'a>(module: &'a WasmModule, names: &[&'a str]) -> Vec<(&'a str, bool)> {
        let export_names: std::collections::HashSet<&str> = module.exports.iter().map(|e| e.name.as_str()).collect();
        names.iter().map(|&n| (n, export_names.contains(n))).collect()
    }
}

fn resolve_func_type(module: &WasmModule, func_index: u32) -> FuncType {
    if func_index < module.num_imported_funcs {
        // Imported function — look up type via import
        let import_funcs: Vec<_> = module.imports.iter().filter(|i| i.kind == EXT_FUNC).collect();
        if let Some(imp) = import_funcs.get(func_index as usize) {
            if let Some(tidx) = imp.type_index {
                return module.types.get(tidx as usize).cloned().unwrap_or(FuncType { params: vec![], results: vec![] });
            }
        }
        FuncType { params: vec![], results: vec![] }
    } else {
        let local_idx = (func_index - module.num_imported_funcs) as usize;
        if let Some(&tidx) = module.functions.get(local_idx) {
            module.types.get(tidx as usize).cloned().unwrap_or(FuncType { params: vec![], results: vec![] })
        } else {
            FuncType { params: vec![], results: vec![] }
        }
    }
}
