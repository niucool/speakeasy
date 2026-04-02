// build.rs - Build script for Speakeasy

#[cfg(target_os = "windows")]
fn configure_windows_link_paths() {
    use std::env;
    use std::path::Path;

    println!("cargo:rerun-if-env-changed=UNICORN_LIB_DIR");
    println!("cargo:rustc-link-search=native=C:/Program Files/LLVM/lib");

    if let Ok(path) = env::var("UNICORN_LIB_DIR") {
        if Path::new(&path).exists() {
            println!("cargo:rustc-link-search=native={path}");
        }
    } else {
        let default_unicorn_path = "C:/Program Files/Python314/Lib/site-packages/unicorn/lib";
        if Path::new(default_unicorn_path).exists() {
            println!("cargo:rustc-link-search=native={default_unicorn_path}");
        }
    }
}

fn main() {
    #[cfg(target_os = "windows")]
    configure_windows_link_paths();

    // Enable optimization features
    println!("cargo:rustc-env=CARGO_CFG_TARGET_FEATURE=default");

    // Version information
    let version = env!("CARGO_PKG_VERSION");
    println!("cargo:rustc-env=SPEAKEASY_VERSION={}", version);
}
