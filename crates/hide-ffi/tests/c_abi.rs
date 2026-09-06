//! Compiles and runs a real C program against the built library, so the header
//! cannot drift from the implementation without the build breaking.

use std::{env, fs, path::PathBuf, process::Command};

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|candidate| Command::new(candidate).arg("--version").output().is_ok())
}

#[test]
fn a_c_program_links_against_the_header_and_round_trips() {
    let Some(cc) = cc() else {
        // Deliberately loud: CI asserts this line is absent.
        eprintln!("skipping: no C compiler found");
        return;
    };

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let source = out.join("abi_check.c");
    fs::write(&source, PROGRAM).expect("write the C program");

    // CARGO_TARGET_TMPDIR is <target>/tmp, so the staticlib is under a profile
    // directory beside it. Missing means fail loudly, never skip: a skipped
    // ABI test is indistinguishable from a passing one.
    let target_dir = out.parent().expect("target dir").to_path_buf();
    let mut library = None;
    for profile in ["debug", "release", ""] {
        for name in ["libhide_ffi.a", "hide_ffi.lib"] {
            let candidate = target_dir.join(profile).join(name);
            if candidate.exists() {
                library = Some(candidate);
            }
        }
    }
    let library = library.unwrap_or_else(|| {
        panic!(
            "no static library under {}. Run `cargo build -p hide-ffi` first.",
            target_dir.display()
        )
    });

    let binary = out.join(if cfg!(windows) { "abi.exe" } else { "abi" });
    let mut build = Command::new(cc);
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
    if cfg!(windows) {
        build.args(["-lbcrypt", "-ladvapi32", "-luserenv", "-lntdll", "-lws2_32"]);
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
