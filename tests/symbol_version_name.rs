use std::process::Command;

// Relative to CARGO_MANIFEST_DIR
const TEST_SCRIPT: &str = "boringssl/test_symbol_version_name.sh";

#[test]
fn test_symbol_version_name() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let test_script = format!("{}/{}", manifest_dir, TEST_SCRIPT);
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    let status = Command::new("bash")
        .arg(test_script)
        .arg(major)
        .arg(minor)
        .arg(patch)
        .status()
        .expect("failed to execute script");

    assert!(status.success());
}
