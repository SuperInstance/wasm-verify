//! Size analysis for wasm binaries.

use crate::error::Result;
use crate::parser::{WasmModule, SECTION_TYPE, SECTION_IMPORT, SECTION_FUNCTION, SECTION_EXPORT, SECTION_CODE};

/// Per-function size breakdown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionSize {
    pub index: u32,
    pub name: Option<String>,
    pub body_bytes: usize,
    pub percentage_of_code: f64,
}

/// Overall size report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SizeReport {
    pub total_bytes: usize,
    pub section_sizes: Vec<SectionSize>,
    pub function_sizes: Vec<FunctionSize>,
    pub code_section_bytes: usize,
    pub largest_function: Option<FunctionSize>,
    pub bloat_warnings: Vec<String>,
}

/// Size of one section.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SectionSize {
    pub id: u8,
    pub name: String,
    pub bytes: usize,
    pub percentage: f64,
}

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        SECTION_TYPE => "type",
        SECTION_IMPORT => "import",
        SECTION_FUNCTION => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        SECTION_EXPORT => "export",
        8 => "start",
        9 => "element",
        SECTION_CODE => "code",
        11 => "data",
        12 => "datacount",
        _ => "unknown",
    }
}

pub struct SizeAnalyzer;

impl SizeAnalyzer {
    /// Analyze sizes for a parsed module.
    pub fn analyze(module: &WasmModule) -> Result<SizeReport> {
        let total = module.total_size;

        let section_sizes: Vec<SectionSize> = module
            .sections
            .iter()
            .map(|&(id, _off, sz)| SectionSize {
                id,
                name: section_name(id).to_owned(),
                bytes: sz,
                percentage: if total > 0 { sz as f64 / total as f64 * 100.0 } else { 0.0 },
            })
            .collect();

        let code_section_bytes: usize = module
            .sections
            .iter()
            .filter(|(id, _, _)| *id == SECTION_CODE)
            .map(|(_, _, sz)| sz)
            .sum();

        // Build export name map for function indices
        let export_names: std::collections::HashMap<u32, String> = module
            .exports
            .iter()
            .filter(|e| e.kind == crate::parser::EXT_FUNC)
            .map(|e| (e.index, e.name.clone()))
            .collect();

        let function_sizes: Vec<FunctionSize> = module
            .codes
            .iter()
            .map(|code| {
                let pct = if code_section_bytes > 0 {
                    code.body_size as f64 / code_section_bytes as f64 * 100.0
                } else {
                    0.0
                };
                FunctionSize {
                    index: code.func_index,
                    name: export_names.get(&code.func_index).cloned(),
                    body_bytes: code.body_size,
                    percentage_of_code: pct,
                }
            })
            .collect();

        let largest_function = function_sizes.iter().max_by_key(|f| f.body_bytes).cloned();

        // Bloat heuristics
        let mut bloat_warnings = Vec::new();
        if total > 5_000_000 {
            bloat_warnings.push(format!("Very large wasm binary ({:.1} MB); consider splitting or tree-shaking.", total as f64 / 1_048_576.0));
        } else if total > 1_000_000 {
            bloat_warnings.push(format!("Large wasm binary ({:.1} MB); review for unnecessary code.", total as f64 / 1_048_576.0));
        }
        if let Some(ref f) = largest_function {
            if f.body_bytes > code_section_bytes / 2 && code_section_bytes > 10_000 {
                bloat_warnings.push(format!(
                    "Function '{}' accounts for {:.1}% of the code section ({} bytes); consider refactoring.",
                    f.name.as_deref().unwrap_or("(unnamed)"),
                    f.percentage_of_code,
                    f.body_bytes
                ));
            }
        }
        let import_size: usize = module.sections.iter().filter(|(id, _, _)| *id == SECTION_IMPORT).map(|(_, _, sz)| sz).sum();
        if import_size as f64 / total as f64 > 0.3 && total > 50_000 {
            bloat_warnings.push("Import section is >30% of binary; verify all imports are needed.".into());
        }

        Ok(SizeReport {
            total_bytes: total,
            section_sizes,
            function_sizes,
            code_section_bytes,
            largest_function,
            bloat_warnings,
        })
    }
}
