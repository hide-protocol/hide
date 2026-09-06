use hide_crypto::RecipientSecret;
use hide_object::{Metadata, decrypt_to_staging, encrypt};
use proptest::prelude::*;
use std::sync::LazyLock;

/// X-Wing key generation is slow, so every case reuses one deterministic pair.
static SECRET: LazyLock<RecipientSecret> =
    LazyLock::new(|| RecipientSecret::from_bytes(&[0x77; 32]).expect("valid seed"));

fn seal(plaintext: &[u8]) -> Vec<u8> {
    let mut container = Vec::new();
    encrypt(
        &mut &*plaintext,
        &mut container,
        &[SECRET.public_key().expect("public key")],
        &Metadata::default(),
    )
    .expect("encrypt");
    container
}

fn open(container: &[u8]) -> Result<Vec<u8>, hide_object::ObjectError> {
    let mut plaintext = Vec::new();
    decrypt_to_staging(&mut &*container, &mut plaintext, &SECRET)?;
    Ok(plaintext)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn roundtrip_preserves_arbitrary_payloads(plaintext in prop::collection::vec(any::<u8>(), 0..200_000)) {
        prop_assert_eq!(open(&seal(&plaintext))?, plaintext);
    }

    #[test]
    fn every_single_byte_mutation_fails(plaintext in prop::collection::vec(any::<u8>(), 0..70_000), index in any::<prop::sample::Index>(), delta in 1u8..=255) {
        let container = seal(&plaintext);
        let mut damaged = container.clone();
        let position = index.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        prop_assert!(open(&damaged).is_err(), "accepted mutation at {}", position);
    }

    #[test]
    fn truncation_and_extension_always_fail(plaintext in prop::collection::vec(any::<u8>(), 1..70_000), index in any::<prop::sample::Index>(), suffix in prop::collection::vec(any::<u8>(), 1..8)) {
        let container = seal(&plaintext);
        let cut = index.index(container.len());
        prop_assert!(open(&container[..cut]).is_err());
        let mut extended = container.clone();
        extended.extend_from_slice(&suffix);
        prop_assert!(open(&extended).is_err());
    }

    #[test]
    fn arbitrary_containers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = open(&bytes);
    }

    #[test]
    fn wrong_recipient_never_decrypts(plaintext in prop::collection::vec(any::<u8>(), 0..4096), seed in any::<[u8; 32]>()) {
        prop_assume!(seed != [0x77; 32]);
        let container = seal(&plaintext);
        let stranger = RecipientSecret::from_bytes(&seed)?;
        let mut output = Vec::new();
        prop_assert!(decrypt_to_staging(&mut &*container, &mut output, &stranger).is_err());
        prop_assert!(output.is_empty());
    }
}
