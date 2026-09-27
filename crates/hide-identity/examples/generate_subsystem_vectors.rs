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
//!
//! The §16 vectors (`binding-*`, `checkpoint-*`) are DERIVED from fixed seeds
//! (HIDE-Sign is deterministic), so they reproduce byte for byte. Their seeds
//! are test-only constants, the one place this program touches signing keys.

use hide_identity::{EpochBinding, IdentityLog, RecoveryBinding, decode, device_id, encode};
use hide_sign::{SigningIdentity, VerifyingIdentity};
use hide_transparency::{
    Checkpoint, ConsistencyProof, Hash, InclusionProof, TransparencyLog, epoch_leaf, identity_leaf,
    leaf_hash,
};
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
    bindings(&mut run);

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

/// Seeds of the §16 fixture identity. Public test constants, never real keys.
const FOUNDER_SEED: u8 = 0x61;
const PHONE_SEED: u8 = 0x62;
const RECOVERY_SEED: u8 = 0x63;
const ATTACKER_SEED: u8 = 0x66;
const LOG_SEED: u8 = 0x70;
const WITNESS_SEED: u8 = 0x71;
pub const CHECKPOINT_ORIGIN: &str = "log.example/hide";
pub const WITNESS_NAME: &str = "witness.example/w1";

fn seeded(byte: u8) -> SigningIdentity {
    SigningIdentity::from_bytes(&[byte; 32]).expect("32-byte seed")
}

fn bindings(run: &mut Run) {
    let founder = seeded(FOUNDER_SEED);
    let phone = seeded(PHONE_SEED);
    let recovery = seeded(RECOVERY_SEED);
    let attacker = seeded(ATTACKER_SEED);
    let (Ok(mut log), Some(chain)) = (
        IdentityLog::create(&founder, "founder", &recovery.verifying_key()),
        run.read("epoch-chain.bin"),
    ) else {
        run.failures.push("fixture identity cannot be built".into());
        return;
    };
    let Ok(records) = hide_epoch::decode_records(&chain) else {
        run.failures.push("epoch-chain.bin does not decode".into());
        return;
    };
    let binding = RecoveryBinding::create(&log, &founder).expect("founder binds");
    let first_link = log.head();
    log.enrol(&founder, &phone.verifying_key(), "phone")
        .expect("enrol");
    let entries = log.entries().to_vec();
    let root = log.root();

    // §15.1 attack: the genuine log plus a Recover signed by the attacker.
    let mut hijacked =
        IdentityLog::from_entries(entries.clone(), attacker.verifying_key()).expect("replays");
    hijacked
        .recover(&attacker, &attacker.verifying_key(), "attacker")
        .expect("attacker appends");
    let forged = RecoveryBinding {
        root,
        recovery_key: attacker.verifying_key(),
        signature: attacker
            .sign(
                hide_identity::RECOVERY_BINDING_CONTEXT,
                &[&root[..], &attacker.verifying_key().to_bytes()[..]].concat(),
            )
            .to_vec(),
    };
    let epoch_binding = EpochBinding::create(&log, &phone, &records).expect("phone binds");
    let mut stranger_binding = epoch_binding.clone();
    stranger_binding.signer = device_id(&attacker.verifying_key());
    stranger_binding.signature = attacker
        .sign(
            hide_identity::EPOCH_BINDING_CONTEXT,
            &stranger_binding.encode()[..136],
        )
        .to_vec();

    let pinned_ok = binding.verify_pinned(entries.clone(), &root).is_ok();
    run.check(
        pinned_ok,
        "binding-recovery.bin binds binding-identity-log.bin",
    );
    run.check(
        binding
            .verify_pinned(hijacked.entries().to_vec(), &root)
            .is_err()
            && forged
                .verify_pinned(hijacked.entries().to_vec(), &root)
                .is_err()
            && IdentityLog::verify(hijacked.entries(), &attacker.verifying_key()).is_ok(),
        "binding-hijacked-log.bin replays bare and is refused under either binding",
    );
    run.check(
        epoch_binding.verify(&log, &records).is_ok()
            && stranger_binding.verify(&log, &records).is_err(),
        "binding-epoch.bin verifies; binding-epoch-stranger.bin does not",
    );
    run.derived(
        "binding-identity-log.bin",
        &encode(&entries).expect("encodes"),
    );
    run.derived("binding-root.bin", &root);
    run.derived(
        "binding-recovery-key.bin",
        &recovery.verifying_key().to_bytes(),
    );
    run.derived("binding-recovery.bin", &binding.encode());
    run.derived("binding-recovery-forged.bin", &forged.encode());
    run.derived(
        "binding-hijacked-log.bin",
        &encode(hijacked.entries()).expect("encodes"),
    );
    run.derived("binding-epoch.bin", &epoch_binding.encode());
    run.derived("binding-epoch-stranger.bin", &stranger_binding.encode());

    // §16.3 leaves for this identity, logged in order, and §16.2 notes.
    let recovery_id = device_id(&recovery.verifying_key());
    let chain_head = records.last().map_or([0; 32], |r| r.link);
    let leaves = [
        identity_leaf(&root, &recovery_id, &first_link, 1),
        identity_leaf(&root, &recovery_id, &log.head(), 2),
        epoch_leaf(&root, &chain_head, records.len() as u64),
    ];
    let mut tree = TransparencyLog::new();
    for leaf in &leaves {
        tree.append(leaf);
    }
    let log_key = seeded(LOG_SEED);
    let witness = seeded(WITNESS_SEED);
    let note_at = |size: u64| -> Vec<u8> {
        let checkpoint = Checkpoint {
            origin: CHECKPOINT_ORIGIN.into(),
            size,
            root: tree.root_at(size).expect("in range"),
        };
        let mut note = checkpoint.sign(&log_key).expect("signs");
        Checkpoint::cosign(&mut note, WITNESS_NAME, &witness).expect("cosigns");
        note.encode().into_bytes()
    };
    let note2 = note_at(2);
    let note3 = note_at(3);
    let tampered = String::from_utf8(note3.clone())
        .expect("utf-8")
        .replacen("\n3\n", "\n4\n", 1)
        .into_bytes();
    let inclusion = tree
        .prove_inclusion(1, 3)
        .expect("proof")
        .encode()
        .expect("encodes");
    let consistency = tree
        .prove_consistency(2, 3)
        .expect("proof")
        .encode()
        .expect("encodes");

    let log_public = log_key.verifying_key();
    let witness_public = witness.verifying_key();
    let witnesses = [(WITNESS_NAME, &witness_public)];
    let verified = |note: &[u8]| {
        Checkpoint::verify_witnessed(note, CHECKPOINT_ORIGIN, &log_public, &witnesses, 1)
    };
    let proofs_ok = match (verified(&note2), verified(&note3)) {
        (Ok(old), Ok(new)) => {
            InclusionProof::decode(&inclusion).is_ok_and(|p| {
                hide_transparency::verify_inclusion(&p, &leaf_hash(&leaves[1]), &new.root).is_ok()
            }) && ConsistencyProof::decode(&consistency).is_ok_and(|p| {
                hide_transparency::verify_consistency(&p, &old.root, &new.root).is_ok()
            })
        }
        _ => false,
    };
    run.check(
        proofs_ok && verified(&tampered).is_err(),
        "checkpoint notes verify with the witness; the proofs fold to their roots; the tampered note is refused",
    );
    run.derived("checkpoint-log-key.bin", &log_public.to_bytes());
    run.derived("checkpoint-witness-key.bin", &witness_public.to_bytes());
    run.derived("checkpoint-2.note", &note2);
    run.derived("checkpoint-3.note", &note3);
    run.derived("checkpoint-tampered.note", &tampered);
    run.derived("checkpoint-inclusion.bin", &inclusion);
    run.derived("checkpoint-consistency.bin", &consistency);
}
