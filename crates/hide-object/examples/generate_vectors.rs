use std::{error::Error, fs, path::PathBuf};

use hide_crypto::RecipientSecret;
use hide_object::{Metadata, SignaturePlacement, encrypt_for_vector, encrypt_signed_for_vector};
use hide_sign::SigningIdentity;

fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    fs::create_dir_all(&directory)?;
    let secret = RecipientSecret::from_bytes(&[0x55; 32])?;
    let public = secret.public_key()?;
    fs::write(directory.join("recipient.test-secret"), [0x55; 32])?;
    fs::write(directory.join("recipient.test-public"), public.to_bytes())?;
    for (name, plaintext) in [
        ("hello", b"Hello HIDE\n".as_slice()),
        ("empty", b"".as_slice()),
    ] {
        let metadata = Metadata {
            filename: Some(format!("{name}.txt")),
            media_type: Some("text/plain".into()),
            signature: None,
        };
        let mut ciphertext = Vec::new();
        encrypt_for_vector(&mut &*plaintext, &mut ciphertext, &public, &metadata)?;
        fs::write(directory.join(format!("{name}.hide")), &ciphertext)?;
        fs::write(directory.join(format!("{name}.txt")), plaintext)?;
        println!("generated {name}: {} bytes", ciphertext.len());
    }

    // Signed containers, one per placement, so an independent implementation can
    // check both against the same signer.
    let identity = SigningIdentity::from_bytes(&[0x55; 32])?;
    fs::write(
        directory.join("signed.test-public"),
        identity.verifying_key().to_bytes(),
    )?;
    for (name, placement) in [
        ("signed-public", SignaturePlacement::Public),
        ("signed-confidential", SignaturePlacement::Confidential),
    ] {
        let plaintext = b"Hello signed HIDE\n".as_slice();
        let metadata = Metadata {
            filename: Some("signed.txt".into()),
            media_type: Some("text/plain".into()),
            signature: None,
        };
        let mut ciphertext = Vec::new();
        encrypt_signed_for_vector(
            &mut &*plaintext,
            &mut ciphertext,
            &public,
            &metadata,
            &identity,
            placement,
        )?;
        fs::write(directory.join(format!("{name}.hide")), &ciphertext)?;
        fs::write(directory.join(format!("{name}.txt")), plaintext)?;
        println!("generated {name}: {} bytes", ciphertext.len());
    }
    Ok(())
}
