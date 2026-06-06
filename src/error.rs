/// All errors produced by wasm-verify.
#[derive(Debug, thiserror::Error)]
pub enum WasmVerifyError {
    #[error("invalid wasm magic number: expected 0x00 0x61 0x73 0x6d, got {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("unsupported wasm version: expected 1, got {0}")]
    UnsupportedVersion(u32),

    #[error("unexpected end of wasm binary at offset {0}")]
    UnexpectedEof(usize),

    #[error("invalid section id {0} at offset {1}")]
    InvalidSectionId(u8, usize),

    #[error("invalid LEB128 encoding at offset {0}")]
    InvalidLeb128(usize),

    #[error("UTF-8 decode error at offset {0}: {1}")]
    InvalidUtf8(usize, #[source] std::str::Utf8Error),

    #[error("malformed wasm binary: {0}")]
    Malformed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Alias result type used across the crate.
pub type Result<T> = std::result::Result<T, WasmVerifyError>;
