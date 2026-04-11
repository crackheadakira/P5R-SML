fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        println!("cargo:rustc-cdylib-link-arg=/DEF:src/dinput8.def");
    }
}
