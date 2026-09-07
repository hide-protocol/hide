//! Compiles and runs a real C program against the built library, so the header
//! cannot drift from the implementation without the build breaking.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// The C round-trip needs a compiler and is skipped where none exists, so the
/// constants are also checked here: this runs everywhere, and a header that
/// disagrees with Rust would otherwise mislead every binding that reads it.
#[test]
fn the_header_constants_match_the_rust_ones() {
    let header = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("include")
            .join("hide.h"),
    )
    .expect("the header ships with the crate");

    let defined = |name: &str| -> i64 {
        header
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("#define ")?;
                let (found, value) = rest.split_once(char::is_whitespace)?;
                (found == name).then(|| value.trim().parse::<i64>().ok())?
            })
            .unwrap_or_else(|| panic!("{name} is not defined in hide.h"))
    };

    for (name, rust) in [
        ("HIDE_OK", hide_ffi::HIDE_OK as i64),
        (
            "HIDE_ERR_INVALID_ARGUMENT",
            hide_ffi::HIDE_ERR_INVALID_ARGUMENT as i64,
        ),
        (
            "HIDE_ERR_WRONG_PASSPHRASE",
            hide_ffi::HIDE_ERR_WRONG_PASSPHRASE as i64,
        ),
        ("HIDE_ERR_NOT_A_KEY", hide_ffi::HIDE_ERR_NOT_A_KEY as i64),
        (
            "HIDE_ERR_AUTHENTICATION",
            hide_ffi::HIDE_ERR_AUTHENTICATION as i64,
        ),
        (
            "HIDE_ERR_NO_MATCHING_RECIPIENT",
            hide_ffi::HIDE_ERR_NO_MATCHING_RECIPIENT as i64,
        ),
        ("HIDE_ERR_MALFORMED", hide_ffi::HIDE_ERR_MALFORMED as i64),
        ("HIDE_ERR_TOO_LARGE", hide_ffi::HIDE_ERR_TOO_LARGE as i64),
        (
            "HIDE_ERR_CHALLENGE_EXPIRED",
            hide_ffi::HIDE_ERR_CHALLENGE_EXPIRED as i64,
        ),
        (
            "HIDE_ERR_CHALLENGE_REPLAYED",
            hide_ffi::HIDE_ERR_CHALLENGE_REPLAYED as i64,
        ),
        ("HIDE_ERR_PANIC", hide_ffi::HIDE_ERR_PANIC as i64),
        ("HIDE_ERR_INTERNAL", hide_ffi::HIDE_ERR_INTERNAL as i64),
        ("HIDE_KEY_RAW", hide_ffi::HIDE_KEY_RAW as i64),
        ("HIDE_KEY_PROTECTED", hide_ffi::HIDE_KEY_PROTECTED as i64),
        ("HIDE_PUBLIC_KEY_LEN", hide_ffi::HIDE_PUBLIC_KEY_LEN as i64),
        (
            "HIDE_MIN_PASSPHRASE_LEN",
            hide_ffi::HIDE_MIN_PASSPHRASE_LEN as i64,
        ),
        ("HIDE_SIGNATURE_LEN", hide_ffi::HIDE_SIGNATURE_LEN as i64),
        (
            "HIDE_VERIFYING_KEY_LEN",
            hide_ffi::HIDE_VERIFYING_KEY_LEN as i64,
        ),
        ("HIDE_NONCE_LEN", hide_ffi::HIDE_NONCE_LEN as i64),
    ] {
        assert_eq!(defined(name), rust, "hide.h disagrees with Rust on {name}");
    }
}

/// Picks a compiler that can actually link the library we build.
///
/// On an MSVC toolchain the staticlib is MSVC-ABI, and MinGW `gcc` cannot link
/// it — it fails on `__chkstk` and the MSVC type_info vtable. Only `cl` will
/// do there, so a MinGW gcc that happens to be on PATH must not be chosen.
fn cc() -> Option<&'static str> {
    let candidates: &[&str] = if cfg!(target_env = "msvc") {
        &["cl"]
    } else {
        &["cc", "gcc", "clang"]
    };
    candidates.iter().copied().find(|candidate| {
        // `cl` has no --version and exits non-zero with no arguments, so
        // only check that it can be spawned at all.
        let probe = if *candidate == "cl" {
            Command::new(candidate).output()
        } else {
            Command::new(candidate).arg("--version").output()
        };
        probe.is_ok()
    })
}

fn find_library(target_dir: &Path) -> Option<PathBuf> {
    ["debug", "release", ""]
        .into_iter()
        .flat_map(|profile| {
            ["libhide_ffi.a", "hide_ffi.lib"]
                .into_iter()
                .map(move |name| target_dir.join(profile).join(name))
        })
        .find(|candidate| candidate.exists())
}

#[test]
fn a_c_program_links_against_the_header_and_round_trips() {
    let Some(cc) = cc() else {
        // Skipping here is only safe because CI asserts this line is absent on
        // Linux, where a compiler is always present. On Windows `cl` is only
        // on PATH inside a Visual Studio shell, and MinGW gcc cannot link an
        // MSVC staticlib, so there is nothing to run.
        eprintln!("skipping: no C compiler found");
        return;
    };

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let source = out.join("abi_check.c");
    fs::write(&source, PROGRAM).expect("write the C program");

    // CARGO_TARGET_TMPDIR is <target>/tmp, so the staticlib sits under a
    // profile directory beside it. `cargo test` does not build a staticlib, so
    // build it here rather than skipping: a skipped ABI test is
    // indistinguishable from a passing one.
    let target_dir = out.parent().expect("target dir").to_path_buf();
    let library = find_library(&target_dir).unwrap_or_else(|| {
        let built = Command::new(env!("CARGO"))
            .args(["build", "-p", "hide-ffi"])
            .current_dir(manifest.join("../.."))
            .status()
            .expect("cargo runs");
        assert!(built.success(), "could not build the static library");
        find_library(&target_dir)
            .unwrap_or_else(|| panic!("no static library under {}", target_dir.display()))
    });

    let binary = out.join(if cfg!(windows) { "abi.exe" } else { "abi" });
    let mut build = Command::new(cc);
    if cc == "cl" {
        // MSVC takes its own flags, and wants the system libraries by name.
        build
            .arg("/nologo")
            .arg(&source)
            .arg(format!("/I{}", manifest.join("include").display()))
            .arg(format!("/Fe:{}", binary.display()))
            .arg(format!("/Fo:{}\\", out.display()))
            .arg("/link")
            .arg(&library)
            .args([
                "bcrypt.lib",
                "advapi32.lib",
                "userenv.lib",
                "ntdll.lib",
                "ws2_32.lib",
                "msvcrt.lib",
            ]);
    } else {
        build
            .arg(&source)
            .arg(&library)
            .arg("-I")
            .arg(manifest.join("include"))
            .arg("-o")
            .arg(&binary);
        if cfg!(target_os = "linux") {
            build.args(["-lpthread", "-ldl", "-lm"]);
        }
    }

    let compiled = build.output().expect("the C compiler runs");
    assert!(
        compiled.status.success(),
        "the C program did not build against hide.h:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let run = Command::new(&binary).output().expect("the C program runs");
    assert!(
        run.status.success(),
        "C round-trip failed:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

const PROGRAM: &str = r#"
#include "hide.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "FAILED: %s\n", message);                                \
      return 1;                                                                \
    }                                                                          \
  } while (0)

/* True when `needle` does not appear anywhere in the buffer. */
static int absent(const uint8_t *haystack, size_t len, const char *needle) {
    size_t n = strlen(needle);
    if (n > len) {
        return 1;
    }
    for (size_t i = 0; i + n <= len; i++) {
        if (memcmp(haystack + i, needle, n) == 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
  HideSecretKey *secret = NULL;
  HideBuffer public_key = hide_buffer_empty();
  CHECK(hide_keypair_generate(&secret, &public_key) == HIDE_OK, "keygen");
  CHECK(public_key.len == HIDE_PUBLIC_KEY_LEN, "public key length");

  const char *message = "salariu 9000 RON";
  HideBuffer container = hide_buffer_empty();
  CHECK(hide_encrypt((const uint8_t *)message, strlen(message),
                     public_key.data, 1, "note.txt", "text/plain",
                     &container) == HIDE_OK,
        "encrypt");
    CHECK(absent(container.data, container.len, message), "plaintext leaked");

  HideBuffer plaintext = hide_buffer_empty();
  HideBuffer filename = hide_buffer_empty();
  CHECK(hide_decrypt(container.data, container.len, secret, &plaintext,
                     &filename, NULL) == HIDE_OK,
        "decrypt");
  CHECK(plaintext.len == strlen(message), "plaintext length");
  CHECK(memcmp(plaintext.data, message, plaintext.len) == 0, "plaintext bytes");
  CHECK(filename.len == strlen("note.txt") &&
            memcmp(filename.data, "note.txt", filename.len) == 0,
        "filename");

  /* A single flipped byte must be refused, with no plaintext produced. */
  container.data[container.len - 1] ^= 1;
  HideBuffer nothing = hide_buffer_empty();
  CHECK(hide_decrypt(container.data, container.len, secret, &nothing, NULL,
                     NULL) != HIDE_OK,
        "tampering accepted");
  CHECK(nothing.data == NULL, "published unverified plaintext");

  /* Protected keys. */
  HideBuffer sealed = hide_buffer_empty();
  CHECK(hide_secret_key_protect(secret, "correct horse", &sealed) == HIDE_OK,
        "protect");
  int32_t kind = -1;
  CHECK(hide_inspect_key(sealed.data, sealed.len, &kind) == HIDE_OK, "inspect");
  CHECK(kind == HIDE_KEY_PROTECTED, "kind");
  HideSecretKey *reopened = NULL;
  CHECK(hide_secret_key_open(sealed.data, sealed.len, "wrong", &reopened) ==
            HIDE_ERR_WRONG_PASSPHRASE,
        "wrong passphrase accepted");
  CHECK(hide_secret_key_open(sealed.data, sealed.len, "correct horse",
                             &reopened) == HIDE_OK,
        "reopen");

  hide_buffer_free(&filename);
  hide_buffer_free(&plaintext);
  hide_buffer_free(&container);
  hide_buffer_free(&sealed);
  hide_buffer_free(&public_key);
  hide_secret_key_free(reopened);
  hide_secret_key_free(secret);
  printf("C round-trip OK, hide %s\n", hide_version());
  return 0;
}
"#;
