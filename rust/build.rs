// build.rs - Build script for Speakeasy

fn main() {
    // Windows-specific build configuration
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=native=C:/Program Files/LLVM/lib");
    }

    // Enable optimization features
    println!("cargo:rustc-env=CARGO_CFG_TARGET_FEATURE=default");

    // Version information
    let version = env!("CARGO_PKG_VERSION");
    println!("cargo:rustc-env=SPEAKEASY_VERSION={}", version);
}
