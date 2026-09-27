//! Rust side of the differential fuzzer (`conformance/differential/run.mjs`).
//!
//! Opens every container named on the command line (a directory argument means
//! every `.hide` inside it) with `conformance/vectors/recipient.test-secret`
//! and prints one JSON line per file. One process for the whole batch, because
//! the fuzzer produces thousands of mutants and a process per file would
//! dominate the run time.
//!
//! Run with: cargo run -p hide-object --features test-vectors --example differential_oracle -- <dir|files...>

use std::{
    error::Error,
    fmt::Write as _,
    fs,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use hide_crypto::RecipientSecret;

fn main() -> Result<(), Box<dyn Error>> {
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let secret = RecipientSecret::from_bytes(&fs::read(vectors.join("recipient.test-secret"))?)?;

    let mut files = Vec::new();
    for argument in std::env::args_os().skip(1) {
        let path = PathBuf::from(argument);
        if path.is_dir() {
            let mut inside: Vec<PathBuf> = fs::read_dir(&path)?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|ext| ext == "hide"))
                .collect();
            inside.sort();
            files.extend(inside);
        } else {
            files.push(path);
        }
    }

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for path in &files {
        writeln!(out, "{}", report(path, &secret))?;
    }
    out.flush()?;
    Ok(())
}

fn report(path: &Path, secret: &RecipientSecret) -> String {
    let mut line = format!("{{\"path\":{}", json_string(&path.to_string_lossy()));
    let container = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = write!(
                line,
                ",\"ok\":false,\"error\":{}}}",
                json_string(&format!("ReadFailed({error:?})"))
            );
            return line;
        }
    };
    let mut plaintext = Vec::new();
    match hide_object::decrypt_to_staging(&mut container.as_slice(), &mut plaintext, secret) {
        Ok(verified) => {
            let optional =
                |value: &Option<String>| value.as_deref().map_or("null".into(), json_string);
            let signer = verified.signer.as_ref().map_or("null".into(), |s| {
                json_string(&hex(&hide_crypto::hash(&[&s.to_bytes()])))
            });
            let _ = write!(
                line,
                ",\"ok\":true,\"error\":null,\"plaintext_sha256\":{},\"plaintext_len\":{},\"filename\":{},\"media_type\":{},\"extensions\":{},\"signer_sha256\":{}}}",
                json_string(&hex(&hide_crypto::hash(&[&plaintext]))),
                verified.plaintext_len,
                optional(&verified.metadata.filename),
                optional(&verified.metadata.media_type),
                verified.metadata.extensions.len(),
                signer,
            );
        }
        Err(error) => {
            let _ = write!(
                line,
                ",\"ok\":false,\"error\":{}}}",
                json_string(&format!("{error:?}"))
            );
        }
    }
    line
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Escapes every non-ASCII-printable character as `\uXXXX` (UTF-16), so a
/// filename carrying control characters or U+0085 survives the pipe intact.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}
