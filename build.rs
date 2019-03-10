// Copyright 2018 Google LLC
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// This build script is responsible for building BoringSSL with the appropriate
// symbol prefix. See boringssl/README.md for details.

use std::env;
use std::fs;
use std::process::{Command, Stdio};

// Relative to CARGO_MANIFEST_DIR
const BORINGSSL_SRC: &str = "boringssl/boringssl";

// Relative to OUT_DIR
const BUILD_DIR_1: &str = "boringssl/build_1";
const BUILD_DIR_2: &str = "boringssl/build_2";
const SYMBOL_FILE: &str = "boringssl/symbols.txt";

fn env(name: &str) -> String {
    let var = env::var(name).expect(&format!("missing required environment variable {}", name));
    println!("cargo:rerun-if-env-changed={}", var);
    var
}

fn main() {
    validate_dependencies();

    let manifest_dir = env("CARGO_MANIFEST_DIR");
    let abs_boringssl_src = format!("{}/{}", manifest_dir, BORINGSSL_SRC);

    let out_dir = env("OUT_DIR");
    let abs_build_dir_1 = format!("{}/{}", out_dir, BUILD_DIR_1);
    let abs_build_dir_2 = format!("{}/{}", out_dir, BUILD_DIR_2);
    let abs_symbol_file = format!("{}/{}", out_dir, SYMBOL_FILE);

    fs::create_dir_all(&abs_build_dir_1).expect("failed to create first build directory");
    fs::create_dir_all(&abs_build_dir_2).expect("failed to create second build directory");

    let major = env("CARGO_PKG_VERSION_MAJOR");
    let minor = env("CARGO_PKG_VERSION_MINOR");
    let patch = env("CARGO_PKG_VERSION_PATCH");
    let version_string = format!("{}_{}_{}", major, minor, patch);
    let prefix = format!("__RUST_MUNDANE_{}", version_string);
    let cmake_version_flag = format!("-DBORINGSSL_PREFIX={}", prefix);

    let built_with = built_with(&abs_build_dir_1);
    let have_ninja = have_ninja();
    let build = |build_dir, flags: &[&str]| {
        // Add CMAKE_POSITION_INDEPENDENT_CODE=1 to the list of CMake variables.
        // This causes compilation with -fPIC, which is required on some
        // platforms. This was added to address
        // https://github.com/google/mundane/issues/3
        let mut flags = flags.to_vec();
        flags.push("-DCMAKE_POSITION_INDEPENDENT_CODE=1");
        fn with_ninja<'a, 'b>(flags: &'a [&'b str]) -> Vec<&'b str> {
            let mut flags = flags.to_vec();
            flags.push("-GNinja");
            flags
        }

        env::set_current_dir(build_dir).expect("failed to cd to build directory");
        // If we've already run a build, then we need to build with the same
        // tool the second time around, or cmake will complain. There's
        // technically a chance that, after having built, the user uninstalled
        // the build tool, but that's unlikely enough that it's not worth
        // introducing the complexity necessary to support that use case.
        match built_with {
            Some(BuildSystem::Ninja) => {
                run("cmake", &with_ninja(&flags));
                run("ninja", &["crypto"]);
            }
            Some(BuildSystem::Make) => {
                run("cmake", &flags);
                run("make", &["crypto"]);
            }
            None => {
                if have_ninja {
                    run("cmake", &with_ninja(&flags));
                    run("ninja", &["crypto"]);
                } else {
                    run("cmake", &flags);
                    run("make", &["crypto"]);
                }
            }
        }
    };

    build(&abs_build_dir_1, &[&abs_boringssl_src]);

    // 'go run' requires that we're cd'd into a subdirectory of the Go module
    // root in order for Go modules to work
    let orig = env::current_dir().expect("could not get current directory");
    env::set_current_dir(&format!("{}", &abs_boringssl_src))
        .expect("could not set current directory");
    // GOPATH should not be respected; we want the borringssl go.mod.
    env::remove_var("GOPATH");
    run(
        "go",
        &[
            "run",
            "util/read_symbols.go",
            "-out",
            &abs_symbol_file,
            &format!("{}/crypto/libcrypto.a", &abs_build_dir_1),
        ],
    );
    env::set_current_dir(orig).expect("could not set current directory");

    build(
        &abs_build_dir_2,
        &[&abs_boringssl_src, &cmake_version_flag, "-DBORINGSSL_PREFIX_SYMBOLS=../symbols.txt"],
    );

    // NOTE(joshlf): We symlink rather than renaming so that the BoringSSL build
    // system won't notice that libcrypto.a is gone and spuriously attempt to
    // rebuild.
    #[cfg(unix)]
    let res = std::os::unix::fs::symlink(
        format!("{}/crypto/libcrypto.a", abs_build_dir_2),
        format!("{}/crypto/libcrypto_{}.a", abs_build_dir_2, version_string),
    );
    #[cfg(windows)]
    let res = std::os::windows::fs::symlink_file(
        format!("{}/crypto/libcrypto.a", abs_build_dir_2),
        format!("{}/crypto/libcrypto_{}.a", abs_build_dir_2, version_string),
    );
    // If symlinking isn't available, we fall back to renaming.
    #[cfg(not(any(unix, windows)))]
    let res = fs::rename(
        format!("{}/crypto/libcrypto.a", abs_build_dir_2),
        format!("{}/crypto/libcrypto_{}.a", abs_build_dir_2, version_string),
    );

    if let Err(err) = res {
        // If the error is an AlreadyExists error, that just means we've already
        // compiled before. Renaming to an existing file works without error, so
        // it's OK that our panic message only mentions symlinking.
        if err.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("could not symlink to libcrypto.a: {}", err)
        }
    }

    println!("cargo:rustc-link-search=native={}/crypto", abs_build_dir_2);
}

// Validates that dependencies which we invoke directly are present, or panics
// with an error message. Does not check for dependencies of BoringSSL's build
// system.
fn validate_dependencies() {
    let go = have_go();
    let cmake = have_cmake();
    let ninja = have_ninja();
    let make = have_make();

    if !go {
        panic!(
            "

Missing build dependency Go (1.11 or higher).

"
        );
    }
    if !cmake {
        panic!(
            "

Missing build dependency CMake.

"
        );
    }
    if cfg!(windows) && !ninja {
        panic!(
            "

Building on Windows requires the Ninja tool. See https://ninja-build.org/.

"
        );
    }
    if !make && !ninja {
        panic!(
            "

Building requires either Make or Ninja (https://ninja-build.org/).

"
        );
    }
}

// Runs a command and panic if it fails.
fn run(cmd: &str, args: &[&str]) {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect(&format!("failed to invoke {}", cmd));
    if !output.status.success() {
        panic!("{} failed with status {}", cmd, output.status);
    }
}

// Is Go installed?
fn have_go() -> bool {
    have("go", &["version"])
}

// Is CMake installed?
fn have_cmake() -> bool {
    have("cmake", &["--version"])
}

// Is Ninja installed?
fn have_ninja() -> bool {
    have("ninja", &["--version"])
}

// Is Make installed?
fn have_make() -> bool {
    have("make", &["--version"])
}

// Checks whether a program is installed by running it.
//
// `have` checks whether `name` is installed by running it with the provided
// `args`. It must exist successfully.
fn have(name: &str, args: &[&str]) -> bool {
    Command::new(name).args(args).output().map(|output| output.status.success()).unwrap_or(false)
}

enum BuildSystem {
    Ninja,
    Make,
}

// Checks which build tool was used for the previous build.
fn built_with(abs_dir: &str) -> Option<BuildSystem> {
    let is_file = |file| {
        fs::metadata(format!("{}/{}", abs_dir, file)).map(|meta| meta.is_file()).unwrap_or(false)
    };
    if is_file("build.ninja") {
        Some(BuildSystem::Ninja)
    } else if is_file("Makefile") {
        Some(BuildSystem::Make)
    } else {
        None
    }
}
