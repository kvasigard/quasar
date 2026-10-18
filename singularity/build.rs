fn main() -> Result<(), wdk_build::ConfigError> {
    println!("cargo:rustc-link-arg=/INTEGRITYCHECK");
    wdk_build::configure_wdk_binary_build()
}
