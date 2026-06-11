//! Compile the BPF datapath to an arch-independent object embedded via include_bytes.
//! Runs on the host toolchain (clang) regardless of the Rust target, since BPF
//! bytecode is portable across x86_64/aarch64.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/pbridge.bpf.c");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out.join("pbridge.bpf.o");

    // asm/types.h lives under the host multiarch include dir.
    let asm_inc = ["/usr/include/x86_64-linux-gnu", "/usr/include/aarch64-linux-gnu"]
        .iter()
        .find(|p| std::path::Path::new(&format!("{p}/asm/types.h")).exists())
        .copied()
        .unwrap_or("/usr/include");

    let status = Command::new("clang")
        .args([
            "-target", "bpf", "-O2", "-g", "-Wall", "-Werror",
            "-I", asm_inc,
            "-c", "bpf/pbridge.bpf.c",
            "-o", obj.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run clang for BPF (is clang installed?)");
    assert!(status.success(), "BPF compilation failed");
}
