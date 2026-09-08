//! Negative vectors: containers and keys that every implementation MUST refuse.
//!
//! The positive vectors prove an implementation can open what this one wrote.
//! These prove it refuses what it must, which is the half of a format that
//! independent implementers get wrong. Each file is derived deterministically
//! from `hello.hide`, so regenerating is stable; `rejections.txt` records the
//! reason for each, keyed by filename, so a verifier can assert the reason.
//!
//! Run with: cargo run -p hide-object --features test-vectors --example generate_rejections

use std::{error::Error, fs, path::PathBuf};

use hide_format::PREAMBLE_LEN;

fn main() -> Result<(), Box<dyn Error>> {
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let directory = vectors.join("rejections");
    fs::create_dir_all(&directory)?;
    let hello = fs::read(vectors.join("hello.hide"))?;
    let mut index = String::from(
        "# name\treason\n# Every file here MUST fail to decrypt with recipient.test-secret.\n",
    );
    let mut emit = |name: &str, bytes: &[u8], reason: &str| -> Result<(), Box<dyn Error>> {
        fs::write(directory.join(format!("{name}.hide")), bytes)?;
        index.push_str(&format!("{name}\t{reason}\n"));
        println!("generated {name}: {} bytes", bytes.len());
        Ok(())
    };

    // §1: the preamble is exact bytes.
    let mut bad_magic = hello.clone();
    bad_magic[0] ^= 0x01;
    emit("bad-magic", &bad_magic, "preamble magic does not match")?;

    let mut wrong_major = hello.clone();
    wrong_major[8] = 1;
    emit("unsupported-major", &wrong_major, "major version is not 0")?;

    // §2: header_len is authenticated and bounded.
    let mut huge_header = hello.clone();
    huge_header[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    emit(
        "header-len-overflow",
        &huge_header,
        "header_len exceeds MAX_HEADER_LEN; refuse before allocating",
    )?;

    // §4: the header MAC covers preamble || protected. One bit anywhere in the
    // header fails the MAC before any recipient is tried.
    let mut header_bit = hello.clone();
    header_bit[PREAMBLE_LEN + 8] ^= 0x80;
    emit(
        "header-bit-flipped",
        &header_bit,
        "header MAC does not verify",
    )?;

    // §5: every record is AEAD-bound to its counter and kind.
    let mut last_bit = hello.clone();
    let last = last_bit.len() - 1;
    last_bit[last] ^= 0x01;
    emit(
        "final-record-bit-flipped",
        &last_bit,
        "FINAL record tag does not verify",
    )?;

    // §5: a container that ends before FINAL authenticates nothing.
    emit(
        "truncated-before-final",
        &hello[..hello.len() - 1],
        "stream ends before the FINAL record authenticates; no plaintext may be released",
    )?;

    // §5: trailing bytes after FINAL are not slack, they are a second message.
    let mut trailing = hello.clone();
    trailing.extend_from_slice(b"\x00");
    emit("trailing-bytes-after-final", &trailing, "bytes after FINAL")?;

    // §5: a payload_salt is outside the authenticators but changes the key, so
    // every record then fails. This is the documented DoS-only case.
    let preamble = hide_format::Preamble::decode(&hello[..PREAMBLE_LEN])?;
    let salt_at = PREAMBLE_LEN + preamble.header_len();
    let mut salt = hello.clone();
    salt[salt_at] ^= 0xFF;
    emit(
        "payload-salt-altered",
        &salt,
        "payload key derives from the altered salt; first record fails",
    )?;

    // §3: a small-order X25519 component in a recipient key MUST be rejected at
    // parse time. The all-zero point is the simplest.
    let mut small_order = fs::read(vectors.join("recipient.test-public"))?;
    small_order[1184..1216].fill(0);
    fs::write(directory.join("small-order.test-public"), &small_order)?;
    index.push_str(
        "small-order.test-public\tX25519 component is a small-order point; refuse as a recipient\n",
    );
    println!("generated small-order.test-public");

    fs::write(directory.join("rejections.txt"), index)?;
    Ok(())
}
