use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: analyze <file.wasm>");
        std::process::exit(1);
    }
    let bytes = fs::read(&args[1]).expect("failed to read wasm file");
    let report = wasm_verify::WasmReport::generate(&bytes).expect("failed to analyze");
    println!("{}", report.to_json().unwrap());
}
