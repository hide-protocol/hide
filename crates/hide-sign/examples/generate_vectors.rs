use std::{error::Error, fs, path::PathBuf};

use hide_sign::{SEED_LENGTH, SigningIdentity};

fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    fs::create_dir_all(&directory)?;

    let seed = [0x55_u8; SEED_LENGTH];
    let signing = SigningIdentity::from_bytes(&seed)?;
    fs::write(directory.join("signer.test-seed"), seed)?;
    fs::write(
        directory.join("signer.test-public"),
        signing.verifying_key().to_bytes(),
    )?;

    for (name, context, message) in [
        (
            "hello",
            b"HIDE/0.5 vector".as_slice(),
            b"Hello HIDE\n".as_slice(),
        ),
        ("empty", b"HIDE/0.5 vector".as_slice(), b"".as_slice()),
    ] {
        let signature = signing.sign(context, message);
        fs::write(directory.join(format!("{name}.sig")), signature)?;
        println!("generated {name}.sig: {} bytes", signature.len());
    }
    Ok(())
}
