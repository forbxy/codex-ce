use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../codex-rs/linux-sandbox/src/linux_run_main.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let text = fs::read_to_string(source).unwrap();
    let start = text
        .find("fn is_proc_mount_failure(stderr: &str) -> bool {")
        .unwrap();
    let end = start + text[start..].find("\n}").unwrap() + 2;
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("proc_failure.rs");
    fs::write(output, &text[start..end]).unwrap();
}
