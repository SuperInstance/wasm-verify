# wasm-verify

A WebAssembly binary analysis, verification, and health reporting library written in Rust.

Parses `.wasm` binaries at the byte level — no external dependencies, no WASM runtimes needed. Extracts function signatures, measures sizes, verifies exports, audits imports for security risks, detects the compilation target, and generates comprehensive JSON health reports.

## Features

| Component | Description |
|---|---|
| **WasmParser** | Parses `.wasm` binaries, extracts function signatures, imports, exports |
| **SizeAnalyzer** | Measures file/section/function sizes, identifies bloat |
| **ExportChecker** | Verifies expected exports exist with correct signatures |
| **ImportAuditor** | Lists all imports, flags risky ones (network, filesystem, random) |
| **CompatibilityChecker** | Detects wasm32-unknown-unknown vs wasm32-wasi targets |
| **WasmReport** | Generates a JSON health report for a `.wasm` binary |

## Quick Start

```rust
use wasm_verify::*;

let bytes = std::fs::read("my_module.wasm")?;
let report = WasmReport::generate(&bytes)?;

println!("Health: {}", report.health);        // Healthy | Warning | Critical
println!("Target: {}", report.target);         // wasm32-unknown-unknown | wasm32-wasi
println!("Size: {} bytes", report.total_bytes);
println!("Functions: {}", report.function_count);

// Get JSON output
let json = report.to_json()?;
```

### Individual Components

```rust
let bytes = std::fs::read("my_module.wasm")?;
let module = WasmParser::parse(&bytes)?;

// Check exports
let result = ExportChecker::check(&module, &[
    ("add", &[ValType::I32, ValType::I32], &[ValType::I32]),
])?;
assert!(result.all_present);

// Audit imports for risky dependencies
let audit = ImportAuditor::audit(&module)?;
if audit.has_risky_imports {
    for risk in audit.risks.iter().filter(|r| r.risk == RiskLevel::Risky) {
        eprintln!("RISKY: {}::{} — {}", risk.module, risk.field, risk.reason);
    }
}

// Check compatibility
let compat = CompatibilityChecker::check(&module)?;
println!("Browser-ready: {}", compat.can_run_in_browser);

// Size analysis
let sizes = SizeAnalyzer::analyze(&module)?;
for f in &sizes.function_sizes {
    println!("  {}: {} bytes ({:.1}%)", f.name.as_deref().unwrap_or("(unnamed)"), f.body_bytes, f.percentage_of_code);
}
```

## Real Analysis Results

Analyzed `sample_wasm.wasm` — a Rust library compiled with `wasm32-unknown-unknown` (release, 17,895 bytes):

```json
{
  "health": "Healthy",
  "target": "Wasm32UnknownUnknown",
  "total_bytes": 17895,
  "imports": {
    "total_imports": 0,
    "summary": "No imports — fully self-contained module"
  },
  "exports_summary": [
    "memory", "add", "factorial", "fibonacci", "greet", "is_prime", "MEMORY",
    "__data_end", "__heap_base"
  ],
  "compatibility": {
    "detected_target": "Wasm32UnknownUnknown",
    "can_run_in_browser": true,
    "can_run_in_wasi_runtime": true,
    "notes": ["Pure wasm module — suitable for browser and bare runtimes."]
  },
  "function_count": 58,
  "size": {
    "code_section_bytes": 12399,
    "section_sizes": [
      { "name": "type",     "bytes": 66,    "percentage": 0.37  },
      { "name": "function", "bytes": 59,    "percentage": 0.33  },
      { "name": "table",    "bytes": 5,     "percentage": 0.03  },
      { "name": "memory",   "bytes": 3,     "percentage": 0.02  },
      { "name": "global",   "bytes": 33,    "percentage": 0.18  },
      { "name": "export",   "bytes": 95,    "percentage": 0.53  },
      { "name": "element",  "bytes": 22,    "percentage": 0.12  },
      { "name": "code",     "bytes": 12399, "percentage": 69.29 },
      { "name": "data",     "bytes": 543,   "percentage": 3.03  },
      { "name": "custom",   "bytes": 4634,  "percentage": 25.90 }
    ],
    "largest_function": {
      "index": 24,
      "body_bytes": 5099,
      "percentage_of_code": 41.1
    }
  },
  "issues": []
}
```

### Key Findings

- **58 functions** total (5 user-defined + 53 compiler-generated for panics, formatting, etc.)
- **No imports** — fully self-contained, zero external dependencies
- **Code section dominates** at 69.3% of the binary (12,399 bytes)
- **Custom sections** (debug info, names) take 25.9% — can be stripped for production
- **One large function** at index 24 accounts for 41.1% of the code section — likely panic/unwind machinery
- **Browser-compatible** — pure `wasm32-unknown-unknown`, no WASI dependencies

## Import Risk Detection

The `ImportAuditor` classifies WASI imports into risk levels:

| Risk Level | Examples |
|---|---|
| **Risky** | `sock_accept`, `path_open`, `fd_read`, `random_get`, `proc_exit` |
| **Caution** | `args_get`, other WASI imports |
| **Safe** | `env::memory`, non-WASI imports |

## Architecture

```
src/
├── lib.rs        # Public API re-exports
├── error.rs      # Error types
├── parser.rs     # Wasm binary format parser (LEB128, sections, types)
├── size.rs       # Size analysis and bloat detection
├── exports.rs    # Export verification
├── imports.rs    # Import auditing and risk classification
├── compat.rs     # Target compatibility detection
└── report.rs     # JSON health report generation
```

The parser reads the [WebAssembly binary format](https://webassembly.github.io/spec/core/binary/index.html) directly — no `wasmtime`, `wasmer`, or other runtime dependencies.

## Running the Example

```bash
# Build the sample wasm binary
cd sample && cargo build --target wasm32-unknown-unknown --release

# Analyze it
cd .. && cargo run --example analyze -- sample/target/wasm32-unknown-unknown/release/sample_wasm.wasm
```

## Tests

```bash
cargo test
```

17 integration tests covering:
- Parsing valid/invalid wasm binaries
- Function signature resolution
- Size analysis and bloat detection
- Export verification (found, missing, wrong signature)
- Import risk classification (safe, risky)
- Compatibility detection (pure wasm, WASI, hybrid, empty)
- Full health report generation

## License

MIT
