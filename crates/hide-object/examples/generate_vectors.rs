use std::{error::Error, fs, path::PathBuf};

use hide_crypto::RecipientSecret;
use hide_object::{Metadata, encrypt_for_vector};

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
        };
        let mut ciphertext = Vec::new();
        encrypt_for_vector(&mut &*plaintext, &mut ciphertext, &public, &metadata)?;
        fs::write(directory.join(format!("{name}.hide")), &ciphertext)?;
        fs::write(directory.join(format!("{name}.txt")), plaintext)?;
        println!("generated {name}: {} bytes", ciphertext.len());
    }
    Ok(())
}
