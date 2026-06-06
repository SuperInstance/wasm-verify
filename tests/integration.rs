//! Integration and unit tests for wasm-verify.

use wasm_verify::*;

// ── Helper: build a minimal valid wasm binary ────────────────────────────────

/// Build a minimal wasm binary with a single exported function `add` (i32,i32)->(i32).
fn minimal_wasm() -> Vec<u8> {
    vec![
        // Magic
        0x00, 0x61, 0x73, 0x6d,
        // Version
        0x01, 0x00, 0x00, 0x00,
        // Type section: one func type (i32, i32) -> (i32)
        0x01, 0x07, // section id=1, size=7
        0x01,       // 1 type
        0x60,       // functype
        0x02, 0x7f, 0x7f, // 2 params: i32, i32
        0x01, 0x7f, // 1 result: i32
        // Function section: one function, type index 0
        0x03, 0x02, // section id=3, size=2
        0x01,       // 1 function
        0x00,       // type index 0
        // Export section: export "add" as function index 0
        0x07, 0x07, // section id=7, size=7
        0x01,       // 1 export
        0x03, 0x61, 0x64, 0x64, // name: "add"
        0x00,       // kind: function
        0x00,       // index: 0
        // Code section: one function body
        0x0a, 0x09, // section id=10, size=9
        0x01,       // 1 function body
        0x07,       // body size=7
        0x00,       // 0 local declarations
        0x20, 0x00, // local.get 0
        0x20, 0x01, // local.get 1
        0x6a,       // i32.add
        0x0b,       // end
    ]
}

/// Build a wasm binary with imports from "env" and "wasi_snapshot_preview1".
fn wasm_with_mixed_imports() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02, 0x2f,
        0x02, 0x03, 0x65, 0x6e, 0x76, 0x03, 0x6c, 0x6f, 0x67, 0x00, 0x00, 0x16, 0x77, 0x61, 0x73, 0x69,
        0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65,
        0x77, 0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x00, 0x03,
        0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, 0x0a, 0x01, 0x00,
    ]
}

/// Empty module (just header, no sections).
fn empty_wasm() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

/// Invalid magic bytes.
fn invalid_magic() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
}

/// Invalid version.
fn invalid_version() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00]
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_parse_minimal_wasm() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    assert_eq!(module.version, 1);
    assert_eq!(module.types.len(), 1);
    assert_eq!(module.functions.len(), 1);
    assert_eq!(module.exports.len(), 1);
    assert_eq!(module.codes.len(), 1);
    assert_eq!(module.num_imported_funcs, 0);
}

#[test]
fn test_parse_rejects_invalid_magic() {
    let result = WasmParser::parse(&invalid_magic());
    assert!(result.is_err());
    match result.unwrap_err() {
        WasmVerifyError::InvalidMagic(m) => assert_eq!(m, [0x00, 0x00, 0x00, 0x00]),
        e => panic!("expected InvalidMagic, got {:?}", e),
    }
}

#[test]
fn test_parse_rejects_invalid_version() {
    let result = WasmParser::parse(&invalid_version());
    assert!(result.is_err());
    match result.unwrap_err() {
        WasmVerifyError::UnsupportedVersion(v) => assert_eq!(v, 2),
        e => panic!("expected UnsupportedVersion, got {:?}", e),
    }
}

#[test]
fn test_parse_rejects_truncated() {
    let result = WasmParser::parse(&[0x00, 0x61, 0x73]);
    assert!(result.is_err());
    match result.unwrap_err() {
        WasmVerifyError::UnexpectedEof(3) => {}
        e => panic!("expected UnexpectedEof(3), got {:?}", e),
    }
}

#[test]
fn test_function_signatures() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let sigs = WasmParser::resolve_function_sigs(&module);
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].name.as_deref(), Some("add"));
    assert_eq!(sigs[0].func_type.params.len(), 2);
    assert_eq!(sigs[0].func_type.results.len(), 1);
    assert_eq!(sigs[0].func_type.params[0], ValType::I32);
    assert_eq!(sigs[0].func_type.results[0], ValType::I32);
}

#[test]
fn test_size_analyzer() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let report = SizeAnalyzer::analyze(&module).unwrap();
    assert_eq!(report.total_bytes, bytes.len());
    assert!(!report.section_sizes.is_empty());
    assert_eq!(report.function_sizes.len(), 1);
    assert!(report.largest_function.is_some());
    assert!(report.bloat_warnings.is_empty());
}

#[test]
fn test_export_checker_found() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = ExportChecker::check(
        &module,
        &[("add", &[ValType::I32, ValType::I32], &[ValType::I32])],
    ).unwrap();
    assert!(result.all_present);
    assert!(result.all_signatures_match);
    assert_eq!(result.checks.len(), 1);
}

#[test]
fn test_export_checker_missing() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = ExportChecker::check(
        &module,
        &[("nonexistent", &[], &[])],
    ).unwrap();
    assert!(!result.all_present);
    assert!(!result.checks[0].found);
}

#[test]
fn test_export_checker_wrong_signature() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = ExportChecker::check(
        &module,
        &[("add", &[ValType::I32], &[ValType::I32])],
    ).unwrap();
    assert!(result.all_present);
    assert!(!result.all_signatures_match);
}

#[test]
fn test_export_check_names_exist() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = ExportChecker::check_names_exist(&module, &["add", "missing"]);
    assert_eq!(result, vec![("add", true), ("missing", false)]);
}

#[test]
fn test_import_auditor_safe() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = ImportAuditor::audit(&module).unwrap();
    assert_eq!(result.total_imports, 0);
    assert!(!result.has_risky_imports);
    assert!(!result.has_caution_imports);
}

#[test]
fn test_import_auditor_flags_risky() {
    let bytes = wasm_with_mixed_imports();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = ImportAuditor::audit(&module).unwrap();
    assert_eq!(result.total_imports, 2);
    assert!(result.has_risky_imports);
    let risky: Vec<_> = result.risks.iter().filter(|r| r.risk == RiskLevel::Risky).collect();
    assert_eq!(risky.len(), 1);
    assert!(risky[0].field.contains("random_get"));
}

#[test]
fn test_compatibility_pure_wasm() {
    let bytes = minimal_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = CompatibilityChecker::check(&module).unwrap();
    assert_eq!(result.detected_target, WasmTarget::Wasm32UnknownUnknown);
    assert!(result.can_run_in_browser);
    assert!(result.wasi_imports.is_empty());
}

#[test]
fn test_compatibility_empty_module() {
    let bytes = empty_wasm();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = CompatibilityChecker::check(&module).unwrap();
    assert_eq!(result.detected_target, WasmTarget::Unknown);
    assert!(result.can_run_in_browser);
    assert!(result.can_run_in_wasi_runtime);
}

#[test]
fn test_compatibility_hybrid() {
    let bytes = wasm_with_mixed_imports();
    let module = WasmParser::parse(&bytes).unwrap();
    let result = CompatibilityChecker::check(&module).unwrap();
    assert_eq!(result.detected_target, WasmTarget::Hybrid);
    assert!(!result.can_run_in_browser);
}

#[test]
fn test_full_report_minimal() {
    let bytes = minimal_wasm();
    let report = WasmReport::generate(&bytes).unwrap();
    assert_eq!(report.health, HealthStatus::Healthy);
    assert_eq!(report.target, WasmTarget::Wasm32UnknownUnknown);
    assert_eq!(report.total_bytes, bytes.len());
    assert!(report.issues.is_empty());
    let json = report.to_json().unwrap();
    assert!(json.contains("\"Healthy\""));
}

#[test]
fn test_full_report_risky() {
    let bytes = wasm_with_mixed_imports();
    let report = WasmReport::generate(&bytes).unwrap();
    assert_eq!(report.health, HealthStatus::Critical);
    assert!(!report.issues.is_empty());
}
