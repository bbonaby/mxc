// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// build.rs — generates the **client-side** MIDL stub. Separate crate
// from the server side so cargo cannot link both `RpcCall` definitions
// into one binary (feature unification would silently break dispatch).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let idl = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("idl")
        .join("mxc_service.idl");
    println!("cargo:rerun-if-changed={}", idl.display());
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let (midl, sdk_inc_root) = find_midl_and_includes();
    let sdk_shared = sdk_inc_root.join("shared");
    let sdk_um = sdk_inc_root.join("um");
    let sdk_winrt = sdk_inc_root.join("winrt");
    let sdk_ucrt = sdk_inc_root.join("ucrt");

    let header = out_dir.join("mxc_service.h");
    let client_stub = out_dir.join("mxc_service_c.c");

    let status = Command::new(&midl)
        .arg("/nologo")
        .arg("/env").arg("x64")
        .arg("/target").arg("NT100")
        .arg("/Oicf")
        .arg("/robust")
        .arg("/h").arg(&header)
        .arg("/I").arg(&sdk_shared)
        .arg("/I").arg(&sdk_um)
        .arg("/I").arg(&sdk_winrt)
        .arg("/cstub").arg(&client_stub)
        .arg("/server").arg("none")
        .arg(&idl)
        .current_dir(&out_dir)
        .status()
        .expect("invoke midl.exe");
    if !status.success() {
        panic!("midl.exe failed: {status:?}");
    }

    cc::Build::new()
        .file(&client_stub)
        .include(&sdk_shared)
        .include(&sdk_um)
        .include(&sdk_ucrt)
        .flag_if_supported("/wd4100")
        .flag_if_supported("/wd4101")
        .flag_if_supported("/wd4127")
        .flag_if_supported("/wd4131")
        .flag_if_supported("/wd4152")
        .flag_if_supported("/wd4324")
        .flag_if_supported("/wd4505")
        .flag_if_supported("/wd5045")
        .define("WIN32", None)
        .define("_WINDOWS", None)
        .compile("mxc_service_rpc_client_stubs");

    println!("cargo:rustc-link-lib=dylib=rpcrt4");
}

fn find_midl_and_includes() -> (PathBuf, PathBuf) {
    if let Ok(p) = env::var("MIDL_EXE") {
        let p = PathBuf::from(p);
        if p.exists() {
            return (p.clone(), guess_include(&p));
        }
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    for base in [
        PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin"),
        PathBuf::from(r"C:\Program Files\Windows Kits\10\bin"),
    ] {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for entry in rd.flatten() {
                let s = entry.file_name().to_string_lossy().to_string();
                if !s.starts_with("10.") { continue; }
                let c = entry.path().join("x64").join("midl.exe");
                if c.exists() { candidates.push(c); }
            }
        }
    }
    candidates.sort();
    if let Some(latest) = candidates.last() {
        return (latest.clone(), guess_include(latest));
    }
    panic!("midl.exe not found; set MIDL_EXE or install Win10/11 SDK");
}

fn guess_include(midl: &Path) -> PathBuf {
    let ver = midl.ancestors().nth(2)
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("10.0.26100.0").to_string();
    let kits_10 = midl.ancestors().nth(4)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10"));
    kits_10.join("Include").join(&ver)
}
