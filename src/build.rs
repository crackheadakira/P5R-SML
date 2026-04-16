fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut path = std::env::current_dir().unwrap();
        path.push("src");
        path.push("dinput8.def");

        println!("cargo:rustc-cdylib-link-arg={}", path.display());
    }
}
