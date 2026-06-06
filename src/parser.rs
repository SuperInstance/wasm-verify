//! Low-level wasm binary parser.
//!
//! Reads the [WebAssembly binary format](https://webassembly.github.io/spec/core/binary/index.html)
//! and extracts sections, function types, imports, exports, and code bodies.

use crate::error::{Result, WasmVerifyError};
use std::fmt;

// ── Section IDs ──────────────────────────────────────────────────────────────
pub(crate) const SECTION_TYPE: u8 = 1;
pub(crate) const SECTION_IMPORT: u8 = 2;
pub(crate) const SECTION_FUNCTION: u8 = 3;
pub(crate) const SECTION_EXPORT: u8 = 7;
pub(crate) const SECTION_CODE: u8 = 10;

// ── External kinds ───────────────────────────────────────────────────────────
pub const EXT_FUNC: u32 = 0;
pub const EXT_TABLE: u32 = 1;
pub const EXT_MEMORY: u32 = 2;
pub const EXT_GLOBAL: u32 = 3;

// ── Value types ──────────────────────────────────────────────────────────────
pub const VAL_I32: u32 = 0x7F;
pub const VAL_I64: u32 = 0x7E;
pub const VAL_F32: u32 = 0x7D;
pub const VAL_F64: u32 = 0x7C;
pub const VAL_FUNCREF: u32 = 0x70;
pub const VAL_EXTERNREF: u32 = 0x6F;

/// A parsed wasm value type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    Funcref,
    Externref,
    Other(u32),
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValType::I32 => write!(f, "i32"),
            ValType::I64 => write!(f, "i64"),
            ValType::F32 => write!(f, "f32"),
            ValType::F64 => write!(f, "f64"),
            ValType::Funcref => write!(f, "funcref"),
            ValType::Externref => write!(f, "externref"),
            ValType::Other(v) => write!(f, "valtype({:#x})", v),
        }
    }
}

fn decode_valtype(v: u32) -> ValType {
    match v {
        VAL_I32 => ValType::I32,
        VAL_I64 => ValType::I64,
        VAL_F32 => ValType::F32,
        VAL_F64 => ValType::F64,
        VAL_FUNCREF => ValType::Funcref,
        VAL_EXTERNREF => ValType::Externref,
        other => ValType::Other(other),
    }
}

/// A function type signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

impl fmt::Display for FuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ps: Vec<String> = self.params.iter().map(|v| v.to_string()).collect();
        let rs: Vec<String> = self.results.iter().map(|v| v.to_string()).collect();
        write!(f, "({}) -> ({})", ps.join(", "), rs.join(", "))
    }
}

/// A function signature (name optional, type resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSig {
    pub index: u32,
    pub name: Option<String>,
    pub func_type: FuncType,
}

/// An import entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub module: String,
    pub field: String,
    pub kind: u32,
    /// For function imports, the type index.
    pub type_index: Option<u32>,
}

/// An export entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExportEntry {
    pub name: String,
    pub kind: u32,
    pub index: u32,
}

/// A code body (from the Code section).
#[derive(Debug, Clone)]
pub struct CodeEntry {
    pub func_index: u32,
    pub body_size: usize,
    pub body_offset: usize,
}

/// The fully-parsed wasm module.
#[derive(Debug, Clone)]
pub struct WasmModule {
    pub version: u32,
    pub types: Vec<FuncType>,
    pub imports: Vec<ImportEntry>,
    pub functions: Vec<u32>,       // type indices from the Function section
    pub exports: Vec<ExportEntry>,
    pub codes: Vec<CodeEntry>,
    /// Total number of imported functions (needed to map code bodies).
    pub num_imported_funcs: u32,
    /// Raw section offsets and sizes for every section encountered.
    pub sections: Vec<(u8, usize, usize)>, // (id, offset, size)
    /// Total byte length.
    pub total_size: usize,
}

// ── Cursor helper ────────────────────────────────────────────────────────────

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(WasmVerifyError::UnexpectedEof(self.pos));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u32_leb128(&mut self) -> Result<u32> {
        let mut result: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            let b = self.byte()?;
            if shift >= 35 {
                return Err(WasmVerifyError::InvalidLeb128(self.pos));
            }
            result |= ((b & 0x7F) as u32) << shift;
            if (b & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(WasmVerifyError::UnexpectedEof(self.pos));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_name(&mut self) -> Result<String> {
        let len = self.read_u32_leb128()? as usize;
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes)
            .map(|s| s.to_owned())
            .map_err(|e| WasmVerifyError::InvalidUtf8(self.pos, e))
    }

    fn pos(&self) -> usize {
        self.pos
    }
}

/// Reads a wasm binary and produces a [`WasmModule`].
pub struct WasmParser;

impl WasmParser {
    /// Parse a complete wasm binary.
    pub fn parse(bytes: &[u8]) -> Result<WasmModule> {
        if bytes.len() < 8 {
            return Err(WasmVerifyError::UnexpectedEof(bytes.len()));
        }

        // Magic
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != [0x00, 0x61, 0x73, 0x6d] {
            return Err(WasmVerifyError::InvalidMagic(magic));
        }

        // Version
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != 1 {
            return Err(WasmVerifyError::UnsupportedVersion(version));
        }

        let mut cur = Cursor::new(bytes);
        cur.pos = 8; // skip header

        let mut types: Vec<FuncType> = Vec::new();
        let mut imports: Vec<ImportEntry> = Vec::new();
        let mut functions: Vec<u32> = Vec::new();
        let mut exports: Vec<ExportEntry> = Vec::new();
        let mut codes: Vec<CodeEntry> = Vec::new();
        let mut sections: Vec<(u8, usize, usize)> = Vec::new();
        let mut num_imported_funcs: u32 = 0;

        while cur.pos < bytes.len() {
            let section_id = cur.byte()?;
            let section_size = cur.read_u32_leb128()? as usize;
            let section_start = cur.pos;
            sections.push((section_id, section_start, section_size));

            let mut sc = Cursor::new(&bytes[section_start..section_start + section_size]);

            match section_id {
                SECTION_TYPE => {
                    let count = sc.read_u32_leb128()?;
                    for _ in 0..count {
                        let form = sc.byte()?;
                        if form != 0x60 {
                            continue;
                        }
                        let pc = sc.read_u32_leb128()? as usize;
                        let mut params = Vec::with_capacity(pc);
                        for _ in 0..pc {
                            params.push(decode_valtype(sc.byte()? as u32));
                        }
                        let rc = sc.read_u32_leb128()? as usize;
                        let mut results = Vec::with_capacity(rc);
                        for _ in 0..rc {
                            results.push(decode_valtype(sc.byte()? as u32));
                        }
                        types.push(FuncType { params, results });
                    }
                }
                SECTION_IMPORT => {
                    let count = sc.read_u32_leb128()?;
                    for _ in 0..count {
                        let module = sc.read_name()?;
                        let field = sc.read_name()?;
                        let kind = sc.byte()? as u32;
                        let mut type_index: Option<u32> = None;
                        match kind {
                            EXT_FUNC => {
                                type_index = Some(sc.read_u32_leb128()?);
                                num_imported_funcs += 1;
                            }
                            EXT_TABLE => { skip_table_type(&mut sc)?; }
                            EXT_MEMORY => { skip_mem_type(&mut sc)?; }
                            EXT_GLOBAL => { sc.byte()?; sc.byte()?; }
                            _ => {
                                return Err(WasmVerifyError::InvalidSectionId(kind as u8, sc.pos));
                            }
                        }
                        imports.push(ImportEntry { module, field, kind, type_index });
                    }
                }
                SECTION_FUNCTION => {
                    let count = sc.read_u32_leb128()?;
                    for _ in 0..count {
                        functions.push(sc.read_u32_leb128()?);
                    }
                }
                SECTION_EXPORT => {
                    let count = sc.read_u32_leb128()?;
                    for _ in 0..count {
                        let name = sc.read_name()?;
                        let kind = sc.byte()? as u32;
                        let index = sc.read_u32_leb128()?;
                        exports.push(ExportEntry { name, kind, index });
                    }
                }
                SECTION_CODE => {
                    let _count = sc.read_u32_leb128()?;
                    for i in 0..functions.len() {
                        let body_size = sc.read_u32_leb128()? as usize;
                        let body_start = sc.pos;
                        codes.push(CodeEntry {
                            func_index: num_imported_funcs + i as u32,
                            body_size,
                            body_offset: section_start + body_start,
                        });
                        sc.pos += body_size;
                    }
                }
                _ => {
                    // Unknown/custom section — skip
                }
            }

            cur.pos = section_start + section_size;
        }

        Ok(WasmModule {
            version,
            types,
            imports,
            functions,
            exports,
            codes,
            num_imported_funcs,
            sections,
            total_size: bytes.len(),
        })
    }

    /// Resolve full function signatures for all defined functions.
    pub fn resolve_function_sigs(module: &WasmModule) -> Vec<FunctionSig> {
        let mut sigs = Vec::new();

        // Import functions
        let mut func_idx = 0u32;
        for imp in &module.imports {
            if imp.kind == EXT_FUNC {
                let tidx = imp.type_index.unwrap_or(0);
                let ft = module.types.get(tidx as usize).cloned().unwrap_or(FuncType {
                    params: vec![],
                    results: vec![],
                });
                sigs.push(FunctionSig {
                    index: func_idx,
                    name: Some(format!("{}::{}", imp.module, imp.field)),
                    func_type: ft,
                });
                func_idx += 1;
            }
        }

        // Defined functions
        for (i, &tidx) in module.functions.iter().enumerate() {
            let fidx = module.num_imported_funcs + i as u32;
            let ft = module.types.get(tidx as usize).cloned().unwrap_or(FuncType {
                params: vec![],
                results: vec![],
            });
            let name = module.exports.iter()
                .find(|e| e.kind == EXT_FUNC && e.index == fidx)
                .map(|e| e.name.clone());
            sigs.push(FunctionSig {
                index: fidx,
                name,
                func_type: ft,
            });
        }

        sigs
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn skip_table_type(cur: &mut Cursor) -> Result<()> {
    cur.byte()?; // elem type
    let flags = cur.byte()?;
    cur.read_u32_leb128()?; // min
    if flags & 1 != 0 {
        cur.read_u32_leb128()?; // max
    }
    Ok(())
}

fn skip_mem_type(cur: &mut Cursor) -> Result<()> {
    let flags = cur.byte()?;
    cur.read_u32_leb128()?; // min
    if flags & 1 != 0 {
        cur.read_u32_leb128()?; // max
    }
    Ok(())
}
