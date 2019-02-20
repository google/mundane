// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use std::process::Command;

// Relative to CARGO_MANIFEST_DIR
const TEST_SYMBOL_VERSION_NAME_SCRIPT: &str = "boringssl/test_symbol_version_name.sh";
#[cfg(feature = "run-symbol-conflict-test")]
const TEST_SYMBOL_CONFLICT_SCRIPT: &str = "boringssl/test_symbol_conflict.sh";

struct EnvVars {
    manifest_dir: &'static str,
    major: &'static str,
    minor: &'static str,
    patch: &'static str,
}

const VARS: EnvVars = EnvVars {
    manifest_dir: env!("CARGO_MANIFEST_DIR"),
    major: env!("CARGO_PKG_VERSION_MAJOR"),
    minor: env!("CARGO_PKG_VERSION_MINOR"),
    patch: env!("CARGO_PKG_VERSION_PATCH"),
};

#[test]
fn test_symbol_version_name() {
    let test_script = format!("{}/{}", VARS.manifest_dir, TEST_SYMBOL_VERSION_NAME_SCRIPT);
    let status = Command::new("bash")
        .arg(test_script)
        .arg(VARS.major)
        .arg(VARS.minor)
        .arg(VARS.patch)
        .status()
        .expect("failed to execute script");
    assert!(status.success());
}

#[test]
#[cfg(feature = "run-symbol-conflict-test")]
fn test_symbol_conflict() {
    let test_script = format!("{}/{}", VARS.manifest_dir, TEST_SYMBOL_CONFLICT_SCRIPT);
    let status = Command::new("bash").arg(test_script).status().expect("failed to execute script");
    assert!(status.success());
}
