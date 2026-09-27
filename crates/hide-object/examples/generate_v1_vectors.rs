//! HIDE/1.0 conformance vectors: what 0.9.0 added to the wire, positive and
//! negative, plus `manifest.json` over every vector in the tree.
//!
//! It never rewrites a file that already exists with different bytes: the
//! HIDE/0.1–0.8 vectors are frozen, and so are these once committed. A change
//! that would alter one is refused, because it is a protocol change.
//!
//! Run with: cargo run -p hide-object --features test-vectors --example generate_v1_vectors
//! Add `-- --check` to only verify (CI); nothing is written then.

use std::{error::Error, fs, path::Path, path::PathBuf};

use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_object::{
    Extension, Metadata, ProtectedHeader, SignaturePlacement, Stanza, UnknownStanza, VectorShape,
    encrypt_shaped_for_vector, rewrite_for_test,
};
use hide_sign::SigningIdentity;

type Outcome = Result<(), Box<dyn Error>>;

struct Writer {
    root: PathBuf,
    check: bool,
    drift: Vec<String>,
}

impl Writer {
    /// An index may grow but never lose or change a row: every existing line
    /// must survive. Anything else is drift like any frozen vector.
    fn put_index(&mut self, relative: &str, text: &str) -> Outcome {
        let path = self.root.join(relative);
        if let Ok(existing) = fs::read_to_string(&path) {
            if existing == text {
                return Ok(());
            }
            let kept = existing
                .lines()
                .filter(|l| !l.starts_with('#'))
                .all(|l| text.lines().any(|n| n == l));
            if !kept || self.check {
                self.drift.push(relative.to_owned());
                return Ok(());
            }
        }
        fs::write(&path, text)?;
        println!("wrote {relative}");
        Ok(())
    }

    fn put(&mut self, relative: &str, bytes: &[u8]) -> Outcome {
        let path = self.root.join(relative);
        match fs::read(&path) {
            Ok(existing) if existing == bytes => Ok(()),
            Ok(_) => {
                self.drift.push(relative.to_owned());
                Ok(())
            }
            Err(_) if self.check => {
                self.drift.push(format!("{relative} (missing)"));
                Ok(())
            }
            Err(_) => {
                fs::write(&path, bytes)?;
                println!("wrote {relative}: {} bytes", bytes.len());
                Ok(())
            }
        }
    }
}

const GREASE_HEADER_KEY: u16 = 0xFAFA;
const GREASE_METADATA_KEY: u16 = 0x4A4A;
const GREASE_STANZA_TAG: u16 = 0x7A7A;

fn grease_shape(minor: u8) -> VectorShape {
    VectorShape {
        minor,
        header_extensions: vec![Extension {
            key: GREASE_HEADER_KEY,
            value: b"HIDE GREASE header extension".to_vec(),
        }],
        leading_stanzas: vec![Stanza::Unknown(UnknownStanza {
            tag: GREASE_STANZA_TAG,
            fields: vec![vec![0x7A; 32], b"future recipient type".to_vec()],
        })],
    }
}

fn metadata(name: &str, grease: bool) -> Metadata {
    Metadata {
        filename: Some(format!("{name}.txt")),
        media_type: Some("text/plain".into()),
        signature: None,
        extensions: if grease {
            vec![Extension {
                key: GREASE_METADATA_KEY,
                value: b"HIDE GREASE metadata extension".to_vec(),
            }]
        } else {
            Vec::new()
        },
    }
}

fn seal(
    public: &RecipientPublic,
    plaintext: &[u8],
    metadata: &Metadata,
    signer: Option<(&SigningIdentity, SignaturePlacement)>,
    shape: &VectorShape,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = Vec::new();
    encrypt_shaped_for_vector(&mut &*plaintext, &mut out, public, metadata, signer, shape)?;
    Ok(out)
}

/// A metadata map with raw CBOR entries appended, re-headed with the new count.
/// Used for keys the encoder rightly refuses to write.
fn metadata_with_raw(base: &[u8], extra_entries: usize, raw: &[u8]) -> Vec<u8> {
    let count = usize::from(base[0] & 0x1f) + extra_entries;
    assert!(count < 24, "short map head only");
    let mut out = vec![0xa0 | count as u8];
    out.extend_from_slice(&base[1..]);
    out.extend_from_slice(raw);
    out
}

fn main() -> Outcome {
    let check = std::env::args().any(|a| a == "--check");
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let mut w = Writer {
        root: vectors.clone(),
        check,
        drift: Vec::new(),
    };
    let secret = RecipientSecret::from_bytes(&fs::read(vectors.join("recipient.test-secret"))?)?;
    let public = secret.public_key()?;
    let signer = SigningIdentity::from_bytes(&[0x55; 32])?;

    // ---- positive -------------------------------------------------------
    let plain = VectorShape::default();
    let text = b"Hello HIDE 1.0\n".as_slice();
    let v1_signed = seal(
        &public,
        text,
        &metadata("v1-signed", false),
        Some((&signer, SignaturePlacement::Public)),
        &plain,
    )?;
    w.put("v1-signed.hide", &v1_signed)?;
    w.put("v1-signed.txt", text)?;
    let v1_conf = seal(
        &public,
        text,
        &metadata("v1-signed-confidential", false),
        Some((&signer, SignaturePlacement::Confidential)),
        &plain,
    )?;
    w.put("v1-signed-confidential.hide", &v1_conf)?;
    w.put("v1-signed-confidential.txt", text)?;

    let grease_text = b"Readers skip what they do not know.\n".as_slice();
    let grease = seal(
        &public,
        grease_text,
        &metadata("grease", true),
        None,
        &grease_shape(1),
    )?;
    w.put("grease.hide", &grease)?;
    w.put("grease.txt", grease_text)?;
    let grease_signed = seal(
        &public,
        grease_text,
        &metadata("grease-signed", true),
        Some((&signer, SignaturePlacement::Public)),
        &grease_shape(1),
    )?;
    w.put("grease-signed.hide", &grease_signed)?;
    w.put("grease-signed.txt", grease_text)?;
    let minor_text = b"A newer minor is a non-breaking revision.\n".as_slice();
    let grease_minor = seal(
        &public,
        minor_text,
        &metadata("grease-minor", false),
        None,
        &VectorShape {
            minor: 7,
            ..VectorShape::default()
        },
    )?;
    w.put("grease-minor.hide", &grease_minor)?;
    w.put("grease-minor.txt", minor_text)?;

    // ---- negative -------------------------------------------------------
    // Each is produced with everything a recipient controls (header MAC,
    // metadata seal, payload) recomputed, so the refusal is for the stated
    // reason and not an incidental MAC failure.
    let unsigned = seal(&public, text, &metadata("r", false), None, &plain)?;
    let mut index = String::from(
        "# name\treason\n# Every file here MUST fail to decrypt with recipient.test-secret.\n",
    );
    let mut reject = |w: &mut Writer, name: &str, bytes: &[u8], reason: &str| -> Outcome {
        w.put(&format!("rejections/{name}.hide"), bytes)?;
        index.push_str(&format!("{name}\t{reason}\n"));
        Ok(())
    };
    let raw_header = |header: &ProtectedHeader, key: u64, value: &[u8]| -> Vec<u8> {
        // The encoder refuses critical/out-of-range keys, so append raw CBOR.
        let mut bytes = header.encode().expect("encodable");
        bytes[0] += 1;
        bytes.extend(cbor_uint(key));
        bytes.extend(cbor_bstr(value));
        bytes
    };

    let r = |minor, flags, edit: &dyn Fn(&mut ProtectedHeader), meta: &dyn Fn(&mut Vec<u8>)| {
        rewrite_for_test(&unsigned, &secret, minor, flags, edit, meta)
    };
    reject(
        &mut w,
        "unknown-flag",
        &r(None, Some(0x02), &|_| {}, &|_| {})?,
        "preamble flag 0x02 is not defined; every flag is critical",
    )?;
    reject(
        &mut w,
        "minor-zero",
        &r(Some(0), None, &|_| {}, &|_| {})?,
        "preamble minor 0 is not a HIDE version",
    )?;
    reject(
        &mut w,
        "legacy-minor-with-flag",
        &rewrite_for_test(&v1_signed, &secret, Some(2), None, |_| {}, |_| {})?,
        "minor 2 (legacy signed) with a flag set is not a valid preamble",
    )?;
    reject(
        &mut w,
        "stripped-signature",
        &rewrite_for_test(
            &v1_signed,
            &secret,
            None,
            None,
            |h| h.signatures.clear(),
            |_| {},
        )?,
        "SIGNED flag set but no signature is present",
    )?;
    reject(
        &mut w,
        "unexpected-signature",
        &rewrite_for_test(&v1_signed, &secret, None, Some(0), |_| {}, |_| {})?,
        "a signature is present but the SIGNED flag is clear",
    )?;
    reject(
        &mut w,
        "signature-extension-rewritten",
        &rewrite_for_test(
            &grease_signed,
            &secret,
            None,
            None,
            |h| h.extensions[0].value[0] ^= 1,
            |_| {},
        )?,
        "a recipient re-MACed a changed header extension; the 1.0 transcript binds it",
    )?;
    reject(
        &mut w,
        "signature-unknown-stanza-removed",
        &rewrite_for_test(
            &grease_signed,
            &secret,
            None,
            None,
            |h| {
                h.recipients.remove(0);
            },
            |_| {},
        )?,
        "a recipient re-MACed with an unknown stanza removed; the 1.0 transcript binds every stanza",
    )?;
    reject(
        &mut w,
        "legacy-minor2-with-extension",
        &rewrite_for_test(
            &fs::read(vectors.join("signed-public.hide"))?,
            &secret,
            None,
            None,
            |h| {
                h.extensions.push(Extension {
                    key: GREASE_HEADER_KEY,
                    value: Vec::new(),
                })
            },
            |_| {},
        )?,
        "minor 2 (legacy signed) carries a header extension its transcript cannot bind",
    )?;
    reject(
        &mut w,
        "only-unknown-stanzas",
        &rewrite_for_test(
            &grease,
            &secret,
            None,
            None,
            |h| h.recipients.retain(|s| s.as_xwing().is_none()),
            |_| {},
        )?,
        "no recipient stanza of a known type; skipping unknown ones leaves nothing to open",
    )?;

    // Raw-CBOR cases the encoder refuses. The MAC is recomputed over them.
    for (name, key, value, reason) in [
        (
            "critical-header-key",
            6_u64,
            vec![0],
            "header key 6 is in the critical range 6..=63 and not defined",
        ),
        (
            "header-key-over-u16",
            65_536,
            vec![0],
            "header key above 65535 is outside every range",
        ),
    ] {
        let bytes = rewrite_raw_header(&unsigned, &secret, |h| raw_header(h, key, &value))?;
        reject(&mut w, name, &bytes, reason)?;
    }
    let oversize = rewrite_raw_header(&unsigned, &secret, |h| {
        raw_header(h, 0xFAFA, &vec![0; 65_537])
    })?;
    reject(
        &mut w,
        "ignorable-ext-oversize",
        &oversize,
        "ignorable header extension value exceeds 65536 bytes",
    )?;
    let not_bstr = rewrite_raw_header(&unsigned, &secret, |h| {
        let mut bytes = h.encode().expect("encodable");
        bytes[0] += 1;
        bytes.extend(cbor_uint(0xFAFA));
        bytes.extend(cbor_uint(1));
        bytes
    })?;
    reject(
        &mut w,
        "ignorable-ext-not-bstr",
        &not_bstr,
        "ignorable header extension value is not a byte string",
    )?;
    let too_many = rewrite_raw_header(&unsigned, &secret, |h| {
        let mut bytes = h.encode().expect("encodable");
        bytes[0] = 0xb6; // map(22) = 5 core + 17 extensions
        for key in 0..17_u64 {
            bytes.extend(cbor_uint(1000 + key));
            bytes.extend(cbor_bstr(&[]));
        }
        bytes
    })?;
    reject(
        &mut w,
        "too-many-extensions",
        &too_many,
        "17 ignorable header extensions; at most 16 are admitted",
    )?;
    let two_signatures = rewrite_raw_header(&v1_signed, &secret, |h| {
        // Rewrite key 5's array(1) head to array(2) and duplicate the stanza.
        let bytes = h.encode().expect("encodable");
        let stanza_len = 1 + 1 + 3 + 1984 + 3 + 3373;
        let at = bytes.len() - stanza_len;
        assert_eq!(bytes[at - 1], 0x81);
        let mut out = bytes.clone();
        out[at - 1] = 0x82;
        out.extend_from_slice(&bytes[at..]);
        out
    })?;
    reject(
        &mut w,
        "two-signatures",
        &two_signatures,
        "two public signature stanzas; exactly one is verified, so a second is refused",
    )?;
    let unknown_signature_tag = rewrite_raw_header(&v1_signed, &secret, |h| {
        let mut bytes = h.encode().expect("encodable");
        let stanza_len = 1 + 1 + 3 + 1984 + 3 + 3373;
        let at = bytes.len() - stanza_len;
        assert_eq!(bytes[at + 1], 0x01);
        bytes[at + 1] = 0x02;
        bytes
    })?;
    reject(
        &mut w,
        "unknown-signature-tag",
        &unknown_signature_tag,
        "signature stanza tag 2 is unknown; unlike recipient stanzas it is refused, not skipped",
    )?;

    // Metadata cases: sealed with the real metadata key.
    let base = metadata("r", false).encode()?;
    for (name, raw, reason) in [
        (
            "critical-metadata-key",
            [cbor_uint(7), cbor_bstr(&[0])].concat(),
            "metadata key 7 is in the critical range and not defined",
        ),
        (
            "reserved-metadata-key",
            [cbor_uint(4), cbor_bstr(&[0])].concat(),
            "metadata key 4 is reserved core and not defined",
        ),
    ] {
        let bytes = r(None, None, &|_| {}, &|m| {
            *m = metadata_with_raw(&base, 1, &raw)
        })?;
        reject(&mut w, name, &bytes, reason)?;
    }
    let dotdot = r(None, None, &|_| {}, &|m| {
        *m = [&[0xa1, 0x01, 0x62][..], b".."].concat();
    })?;
    reject(
        &mut w,
        "filename-dotdot",
        &dotdot,
        "filename '..' is a path component, not a name",
    )?;
    let noncanonical = r(None, None, &|_| {}, &|m| {
        // filename key 1 as a two-byte integer: 18 01.
        *m = [&[0xa1, 0x18, 0x01, 0x61][..], b"a"].concat();
    })?;
    reject(
        &mut w,
        "non-canonical-metadata",
        &noncanonical,
        "metadata integer key not in shortest form",
    )?;

    // §9.5 / §15.7: non-canonical X25519 encodings of points, which the
    // seven-string small-order list does not match by bytes.
    let genuine = public.to_bytes();
    for (name, x25519, reason) in [
        (
            "x25519-high-bit.test-public",
            {
                let mut zero_high = [0_u8; 32];
                zero_high[31] = 0x80;
                zero_high
            },
            "X25519 component has bit 255 set (the zero point, non-canonically); refuse as a recipient",
        ),
        (
            "x25519-not-reduced.test-public",
            {
                let mut p_plus_one = [0xff_u8; 32];
                p_plus_one[0] = 0xee;
                p_plus_one[31] = 0x7f;
                p_plus_one
            },
            "X25519 component is p + 1, a non-canonical encoding of u = 1; refuse as a recipient",
        ),
    ] {
        let mut bytes = genuine.clone();
        bytes[1184..].copy_from_slice(&x25519);
        assert!(
            RecipientPublic::from_bytes(&bytes).is_err(),
            "{name} parses"
        );
        w.put(&format!("rejections/{name}"), &bytes)?;
        index.push_str(&format!("{name}\t{reason}\n"));
    }

    // Keep the pre-0.9 rows, which the old generator still owns, first.
    let old = fs::read_to_string(vectors.join("rejections/rejections.txt"))?;
    let mut rows: Vec<&str> = old
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    let new_rows: Vec<String> = index
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(str::to_owned)
        .collect();
    for row in &new_rows {
        let name = row.split('\t').next().unwrap_or_default();
        if !rows.iter().any(|r| r.split('\t').next() == Some(name)) {
            rows.push(row);
        }
    }
    let mut merged = String::from(
        "# name\treason\n# Every file here MUST be refused: containers with recipient.test-secret, keys by their parser.\n",
    );
    for row in rows {
        merged.push_str(row);
        merged.push('\n');
    }
    w.put_index("rejections/rejections.txt", &merged)?;

    // The manifest hashes every file, so it is regenerated from what is on
    // disk; each vector it names is itself checked for drift above.
    let manifest = manifest(&vectors)?;
    w.put_index("manifest.json", &manifest)?;

    if !w.drift.is_empty() {
        for d in &w.drift {
            eprintln!("DRIFT {d}");
        }
        return Err(format!("{} frozen vector(s) would change", w.drift.len()).into());
    }
    println!("vectors consistent");
    Ok(())
}

/// Opens the container as a recipient, lets `build` produce new protected
/// bytes (which may be ones `encode()` refuses), then recomputes the MAC.
fn rewrite_raw_header(
    container: &[u8],
    secret: &RecipientSecret,
    build: impl FnOnce(&ProtectedHeader) -> Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut protected = None;
    // rewrite_for_test hands us the decoded header; capture its bytes and
    // produce the container with a placeholder, then splice.
    let rebuilt = rewrite_for_test(
        container,
        secret,
        None,
        None,
        |h| protected = Some(build(h)),
        |_| {},
    )?;
    let protected = protected.expect("edit ran");
    Ok(hide_object::replace_protected_for_test(
        &rebuilt, secret, &protected,
    )?)
}

fn cbor_uint(value: u64) -> Vec<u8> {
    match value {
        0..=23 => vec![value as u8],
        24..=0xff => vec![0x18, value as u8],
        0x100..=0xffff => [&[0x19][..], &(value as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[0x1a][..], &(value as u32).to_be_bytes()].concat(),
        _ => [&[0x1b][..], &value.to_be_bytes()].concat(),
    }
}

fn cbor_bstr(value: &[u8]) -> Vec<u8> {
    let mut head = cbor_uint(value.len() as u64);
    head[0] |= 0x40;
    [head, value.to_vec()].concat()
}

/// Every vector in the tree with its expected outcome and SHA-256, so an
/// implementation in another language can run the whole suite from one file.
fn manifest(vectors: &Path) -> Result<String, Box<dyn Error>> {
    let rejections: Vec<(String, String)> =
        fs::read_to_string(vectors.join("rejections/rejections.txt"))?
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .filter_map(|l| l.split_once('\t'))
            .map(|(n, r)| (n.to_owned(), r.to_owned()))
            .collect();
    let mut entries = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    collect(vectors, &mut files)?;
    files.sort();
    for path in files {
        let relative = path
            .strip_prefix(vectors)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "manifest.json" || relative.ends_with(".txt") || relative.ends_with(".md") {
            continue;
        }
        let bytes = fs::read(&path)?;
        let sha = hex(&hide_crypto::hash(&[&bytes]));
        let (kind, expect, reason) = classify(&relative, &rejections);
        entries.push(format!(
            "    {{\"path\": {}, \"kind\": \"{kind}\", \"expect\": \"{expect}\", \"reason\": {}, \"sha256\": \"{sha}\"}}",
            json(&relative),
            json(&reason)
        ));
    }
    Ok(format!(
        "{{\n  \"format\": \"hide-vectors/1\",\n  \"secret\": \"recipient.test-secret\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
        entries.join(",\n")
    ))
}

fn classify(
    relative: &str,
    rejections: &[(String, String)],
) -> (&'static str, &'static str, String) {
    let kind = if relative.starts_with("subsystems/") {
        "subsystem"
    } else if relative.ends_with(".hide") {
        "container"
    } else if relative.ends_with(".test-public") {
        "public-key"
    } else if relative.ends_with(".sig") {
        "detached-signature"
    } else {
        "key"
    };
    if let Some(name) = relative.strip_prefix("rejections/") {
        let stem = name.strip_suffix(".hide").unwrap_or(name);
        let reason = rejections
            .iter()
            .find(|(n, _)| n == stem || n == name)
            .map(|(_, r)| r.clone())
            .unwrap_or_default();
        return (kind, "reject", reason);
    }
    let reason = match relative {
        "subsystems/identity-tampered.bin" | "subsystems/identity-tampered-legacy.bin" => {
            ("reject", "entry 3 signature byte flipped; link check fails")
        }
        "subsystems/epoch-broken.bin" => ("reject", "epoch 1 key altered; chain hash breaks"),
        "subsystems/other-leaf.bin" | "subsystems/rewritten-root.bin" => {
            ("reject", "does not verify against the recorded proof")
        }
        "subsystems/binding-recovery-forged.bin" => (
            "reject",
            "recovery binding signed by the attacker, not the founder; refuse under the pinned root",
        ),
        "subsystems/binding-hijacked-log.bin" => (
            "reject",
            "log with an attacker Recover appended; replays bare, refused under the recovery binding",
        ),
        "subsystems/binding-epoch-stranger.bin" => (
            "reject",
            "epoch binding signed by a device the identity never enrolled",
        ),
        "subsystems/checkpoint-tampered.note" => (
            "reject",
            "checkpoint size changed after signing; the log signature fails",
        ),
        _ => ("open", ""),
    };
    (kind, reason.0, reason.1.to_owned())
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Outcome {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
