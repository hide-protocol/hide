//! Checks, and on request rewrites, `conformance/vectors/subsystems/`.
//!
//! Run with: `cargo run -p hide-identity --example generate_subsystem_vectors`
//! (check mode, exits non-zero on any mismatch — this is what CI runs), or add
//! `-- --write` to rewrite the files this program derives.
//!
//! What is derived and what is only checked:
//!
//! - `identity-log.bin` and `identity-tampered.bin` are DERIVED, byte for
//!   byte, from `identity-log-legacy.bin`: the same entries re-encoded in the
//!   current framing (array of 7 per entry), and that log with its last byte
//!   flipped. The framing is not signed, so the recovery key, device keys and
//!   head stay those of the legacy log.
//! - Every other file is CHECK-ONLY. The identity keys and the epoch secrets
//!   behind them were random and never recorded, and the transparency leaf
//!   contents were not recorded either, so none of them can be reproduced.
//!   Instead each file is checked against what the SDK tests claim about it.
//!
//! Only public material is involved; nothing here holds a secret key.

use hide_identity::{IdentityLog, decode, device_id, encode};
use hide_sign::VerifyingIdentity;
use hide_transparency::{ConsistencyProof, Hash, InclusionProof};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const LEGACY_LOG: &str = "identity-log-legacy.bin";
const LEGACY_TAMPERED: &str = "identity-tampered-legacy.bin";
const LOG: &str = "identity-log.bin";
const TAMPERED: &str = "identity-tampered.bin";

/// Byte the published epoch-broken vector flips: inside epoch 1's public key,
/// so the chain still decodes and only the link check can catch it.
const EPOCH_BROKEN_OFFSET: usize = 1261;

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/subsystems")
}

struct Run {
    dir: PathBuf,
    write: bool,
    failures: Vec<String>,
}

impl Run {
    fn read(&mut self, name: &str) -> Option<Vec<u8>> {
        match std::fs::read(self.dir.join(name)) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                self.failures.push(format!("{name}: {error}"));
                None
            }
        }
    }

    fn check(&mut self, ok: bool, what: &str) {
        if ok {
            println!("ok       {what}");
        } else {
            self.failures.push(what.to_owned());
        }
    }

    /// Writes `expected` when asked to, otherwise compares it with the disk.
    fn derived(&mut self, name: &str, expected: &[u8]) {
        if self.write {
            match std::fs::write(self.dir.join(name), expected) {
                Ok(()) => println!("wrote    {name} ({} bytes)", expected.len()),
                Err(error) => self.failures.push(format!("{name}: {error}")),
            }
            return;
        }
        let on_disk = self.read(name);
        self.check(
            on_disk.as_deref() == Some(expected),
            &format!("{name} is reproduced byte for byte"),
        );
    }
}

fn hash32(bytes: &[u8]) -> Option<Hash> {
    bytes.try_into().ok()
}

fn path_of(bytes: &[u8]) -> Vec<Hash> {
    bytes.chunks_exact(32).filter_map(hash32).collect()
}

fn identity(run: &mut Run) {
    let (
        Some(legacy),
        Some(legacy_tampered),
        Some(recovery),
        Some(phone),
        Some(laptop),
        Some(head),
    ) = (
        run.read(LEGACY_LOG),
        run.read(LEGACY_TAMPERED),
        run.read("identity-recovery.bin"),
        run.read("identity-device-phone.bin"),
        run.read("identity-device-laptop.bin"),
        run.read("identity-head.bin"),
    )
    else {
        return;
    };
    let (Ok(recovery), Ok(phone), Ok(laptop)) = (
        VerifyingIdentity::from_bytes(&recovery),
        VerifyingIdentity::from_bytes(&phone),
        VerifyingIdentity::from_bytes(&laptop),
    ) else {
        run.failures
            .push("an identity key file does not parse".into());
        return;
    };

    run.check(
        legacy.starts_with(&[0x84, 0x86]),
        "identity-log-legacy.bin uses the 0.6-0.8 framing",
    );
    let Ok(entries) = decode(&legacy) else {
        run.failures.push(format!("{LEGACY_LOG} does not decode"));
        return;
    };
    let Ok(log) = IdentityLog::from_entries(entries.clone(), recovery.clone()) else {
        run.failures.push(format!("{LEGACY_LOG} does not verify"));
        return;
    };
    let membership = log.membership();
    run.check(membership.len() == 2, "the legacy log trusts two devices");
    run.check(
        membership.contains(&device_id(&phone)),
        "the legacy log trusts the phone",
    );
    run.check(
        !membership.contains(&device_id(&laptop))
            && membership.revoked_at(&device_id(&laptop)).is_some(),
        "the legacy log revoked the laptop",
    );
    run.check(
        log.head().as_slice() == head,
        "identity-head.bin is the log head",
    );

    let mut expected_tampered = legacy.clone();
    if let Some(last) = expected_tampered.last_mut() {
        *last ^= 1;
    }
    run.check(
        legacy_tampered == expected_tampered,
        "identity-tampered-legacy.bin is the legacy log with its last byte flipped",
    );

    let Ok(current) = encode(&entries) else {
        run.failures
            .push("the legacy entries do not re-encode".into());
        return;
    };
    let mut tampered = current.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    run.check(
        current.starts_with(&[0x84, 0x87, 0x00, 0x01]),
        "the derived log uses the array(7) framing",
    );
    run.check(
        decode(&tampered).is_ok_and(|bad| IdentityLog::verify(&bad, &recovery).is_err()),
        "the derived tampered log decodes and does not verify",
    );
    run.derived(LOG, &current);
    run.derived(TAMPERED, &tampered);
}

fn epoch(run: &mut Run) {
    let (Some(chain), Some(broken), Some(key1)) = (
        run.read("epoch-chain.bin"),
        run.read("epoch-broken.bin"),
        run.read("epoch-public-key-1.bin"),
    ) else {
        return;
    };
    let records = hide_epoch::decode_records(&chain);
    run.check(
        records.as_ref().is_ok_and(|records| {
            records.len() == 3 && hide_epoch::EpochChain::verify(records).is_ok()
        }),
        "epoch-chain.bin is a valid chain of three epochs",
    );
    run.check(
        records
            .as_ref()
            .is_ok_and(|records| records.get(1).is_some_and(|r| r.public_key == key1)),
        "epoch-public-key-1.bin is epoch 1's key",
    );
    let mut expected_broken = chain.clone();
    if let Some(byte) = expected_broken.get_mut(EPOCH_BROKEN_OFFSET) {
        *byte ^= 1;
    }
    run.check(
        broken == expected_broken,
        "epoch-broken.bin is the chain with one byte of epoch 1's key flipped",
    );
    run.check(
        hide_epoch::decode_records(&broken)
            .is_ok_and(|records| hide_epoch::EpochChain::verify(&records).is_err()),
        "epoch-broken.bin decodes and does not verify",
    );
}

fn transparency(run: &mut Run) {
    let names = [
        "leaf.bin",
        "other-leaf.bin",
        "inclusion-path.bin",
        "tree-root.bin",
        "consistency-path.bin",
        "root-at-5.bin",
        "rewritten-root.bin",
    ];
    let files: Vec<Option<Vec<u8>>> = names.iter().map(|name| run.read(name)).collect();
    let [
        Some(leaf),
        Some(other),
        Some(inclusion),
        Some(root),
        Some(consistency),
        Some(root5),
        Some(rewritten),
    ] = <[Option<Vec<u8>>; 7]>::try_from(files).unwrap_or_default()
    else {
        return;
    };
    let (Some(leaf), Some(other), Some(root), Some(root5), Some(rewritten)) = (
        hash32(&leaf),
        hash32(&other),
        hash32(&root),
        hash32(&root5),
        hash32(&rewritten),
    ) else {
        run.failures
            .push("a transparency hash file is not 32 bytes".into());
        return;
    };
    let inclusion = InclusionProof {
        index: 3,
        size: 8,
        path: path_of(&inclusion),
    };
    run.check(
        hide_transparency::verify_inclusion(&inclusion, &leaf, &root).is_ok(),
        "leaf.bin is entry 3 of 8 under tree-root.bin",
    );
    run.check(
        hide_transparency::verify_inclusion(&inclusion, &other, &root).is_err(),
        "other-leaf.bin is not included at 3",
    );
    let consistency = ConsistencyProof {
        old_size: 5,
        new_size: 8,
        path: path_of(&consistency),
    };
    run.check(
        hide_transparency::verify_consistency(&consistency, &root5, &root).is_ok(),
        "root-at-5.bin is a prefix of tree-root.bin",
    );
    run.check(
        hide_transparency::verify_consistency(&consistency, &root5, &rewritten).is_err(),
        "rewritten-root.bin is not consistent with root-at-5.bin",
    );
}

fn main() -> ExitCode {
    let write = std::env::args().skip(1).any(|arg| arg == "--write");
    let mut run = Run {
        dir: directory(),
        write,
        failures: Vec::new(),
    };
    identity(&mut run);
    epoch(&mut run);
    transparency(&mut run);

    if run.failures.is_empty() {
        println!("subsystem vectors: all checks passed");
        ExitCode::SUCCESS
    } else {
        for failure in &run.failures {
            eprintln!("FAILED   {failure}");
        }
        if !write {
            eprintln!("rerun with `-- --write` only if the change is a deliberate protocol change");
        }
        ExitCode::FAILURE
    }
}
