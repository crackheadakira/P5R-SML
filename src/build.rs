use std::{env, path::PathBuf};

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os == "windows" {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut def_path = PathBuf::from(manifest_dir);
        def_path.push("src/defs");

        if target_env == "msvc" {
            def_path.push("dinput8_msvc.def");
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
        } else {
            def_path.push("dinput8_gnu.def");
            println!("cargo:rustc-cdylib-link-arg={}", def_path.display());
        }

        println!("cargo:rerun-if-changed={}", def_path.display());
    }
}
