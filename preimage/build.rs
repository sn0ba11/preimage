use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(preimage_cuda)");
    println!("cargo:rerun-if-changed=src/cloudap_cuda.cu");
    println!("cargo:rerun-if-env-changed=NVCC");

    let Some(nvcc) = find_nvcc() else {
        return;
    };
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let library = out_dir.join("libpreimage_cloudap_cuda.a");
    let status = Command::new(&nvcc)
        .args(["--lib", "-O3", "--use_fast_math", "-lineinfo"])
        .arg(if cfg!(windows) {
            "-Xcompiler=/O2"
        } else {
            "-Xcompiler=-fPIC"
        })
        .arg("src/cloudap_cuda.cu")
        .arg("-o")
        .arg(&library)
        .status()
        .unwrap_or_else(|error| panic!("failed to run {}: {error}", nvcc.display()));
    if !status.success() {
        panic!("nvcc failed while building the CloudAP CUDA backend");
    }

    println!("cargo:rustc-cfg=preimage_cuda");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=preimage_cloudap_cuda");
    println!("cargo:rustc-link-lib=dylib=cudart");
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        if let Some(root) = nvcc.parent().and_then(Path::parent) {
            let lib64 = root.join("lib64");
            if lib64.is_dir() {
                println!("cargo:rustc-link-search=native={}", lib64.display());
            }
        }
    }
}

fn find_nvcc() -> Option<PathBuf> {
    if let Some(path) = env::var_os("NVCC") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        panic!("NVCC points to a missing file: {}", path.display());
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|dir| dir.join(if cfg!(windows) { "nvcc.exe" } else { "nvcc" }))
            .find(|candidate| candidate.is_file())
    })
}
