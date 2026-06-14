// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// build.rs — invokes midl.exe to generate RPC stubs from mxc_service.idl,
// then compiles the generated C stubs via the `cc` crate and links them.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=idl/mxc_service.idl");
    println!("cargo:rerun-if-changed=build.rs");

    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        // No-op on non-Windows hosts. Server/client wrappers in
        // src/lib.rs gate on cfg(windows) too.
        return;
    }
    let _ = host;

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let idl_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("idl")
        .join("mxc_service.idl");

    let (midl, sdk_inc_root) = find_midl_and_includes();
    eprintln!("mxc_service_rpc: midl = {}", midl.display());
    eprintln!(
        "mxc_service_rpc: sdk include root = {}",
        sdk_inc_root.display()
    );
    let sdk_shared = sdk_inc_root.join("shared");
    let sdk_um = sdk_inc_root.join("um");
    let sdk_winrt = sdk_inc_root.join("winrt");
    let sdk_ucrt = sdk_inc_root.join("ucrt");

    // MIDL invocation. /env x64 + /target NT100 hit the modern runtime;
    // /Oicf yields inline+fully-interpreted stubs (smaller code, no
    // per-arg type fmt blob lookups); /no_format_opt disables auto
    // formatting (we keep generated files unchanged); /robust enables
    // the modern arg validation in NDR.
    //
    // Output files go straight into OUT_DIR so cargo cleans them.
    let header = out_dir.join("mxc_service.h");
    let client_stub = out_dir.join("mxc_service_c.c");
    let server_stub = out_dir.join("mxc_service_s.c");

    let want_client = env::var_os("CARGO_FEATURE_CLIENT").is_some();
    let want_server = env::var_os("CARGO_FEATURE_SERVER").is_some();
    if !want_client && !want_server {
        // No-op: nothing depends on the stubs. Just generate the
        // header so dependents can introspect, and exit.
        return;
    }

    let mut midl = Command::new(&midl);
    midl.arg("/nologo")
        .arg("/env").arg("x64")
        .arg("/target").arg("NT100")
        .arg("/Oicf")
        .arg("/robust")
        .arg("/h").arg(&header)
        .arg("/I").arg(&sdk_shared)
        .arg("/I").arg(&sdk_um)
        .arg("/I").arg(&sdk_winrt);
    if want_client {
        midl.arg("/cstub").arg(&client_stub);
    } else {
        midl.arg("/client").arg("none");
    }
    if want_server {
        midl.arg("/sstub").arg(&server_stub);
    } else {
        midl.arg("/server").arg("none");
    }
    midl.arg(&idl_path);
    let status = midl
        .current_dir(&out_dir)
        .status()
        .expect("failed to invoke midl.exe");
    if !status.success() {
        panic!("midl.exe failed with status {status:?}");
    }

    // Compile only the side requested. Both sides export the same
    // `RpcCall` symbol (client = proxy, server = expected user impl),
    // so they cannot coexist in one linkage closure.
    let mut build = cc::Build::new();
    if want_client {
        build.file(&client_stub);
    }
    if want_server {
        build.file(&server_stub);
    }
    build
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
        .define("_WINDOWS", None);
    build.compile("mxc_service_rpc_stubs");

    // The RPC runtime + NDR helpers come from rpcrt4.lib.
    println!("cargo:rustc-link-lib=dylib=rpcrt4");

    // Expose the OUT_DIR to lib.rs via env so we can include the
    // generated header via bindgen-style FFI (we don't actually need
    // it because we re-declare the externs by hand, but it's handy
    // for debugging — see src/sys.rs).
    println!("cargo:rustc-env=MXC_RPC_OUT_DIR={}", out_dir.display());
}

fn find_midl_and_includes() -> (PathBuf, PathBuf) {
    // 1) MIDL env var override.
    if let Ok(p) = env::var("MIDL_EXE") {
        let p = PathBuf::from(p);
        if p.exists() {
            return (p.clone(), guess_include(&p));
        }
    }

    // 2) Walk the standard SDK install location for the newest x64 midl.
    let mut candidates: Vec<PathBuf> = Vec::new();
    for base in [
        PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin"),
        PathBuf::from(r"C:\Program Files\Windows Kits\10\bin"),
    ] {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if !s.starts_with("10.") {
                    continue;
                }
                let candidate = entry.path().join("x64").join("midl.exe");
                if candidate.exists() {
                    candidates.push(candidate);
                }
            }
        }
    }
    candidates.sort();
    if let Some(latest) = candidates.last() {
        return (latest.clone(), guess_include(latest));
    }

    panic!(
        "Could not locate midl.exe. Set MIDL_EXE env var or install \
         the Windows 10/11 SDK."
    );
}

fn guess_include(midl: &Path) -> PathBuf {
    // .../Windows Kits/10/bin/<ver>/x64/midl.exe
    // ancestors: 0=midl.exe 1=x64 2=<ver> 3=bin 4=10 5=Windows Kits
    let ver = midl
        .ancestors()
        .nth(2)
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("10.0.26100.0")
        .to_string();
    // Walk up to "10": four steps above midl.exe (x64/<ver>/bin/10).
    let kits_10 = midl
        .ancestors()
        .nth(4)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10"));
    kits_10.join("Include").join(&ver)
}
