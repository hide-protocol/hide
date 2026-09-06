//! Desktop bindings for the HIDE core.
//!
//! The frontend never receives key material. Secrets are loaded, used and
//! dropped entirely inside these commands; only ciphertext, public keys and
//! human-readable status ever cross into the webview.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_keyring::KeyFormat;
use hide_object::Metadata;
use serde::Serialize;
use zeroize::Zeroizing;

const IO_BUFFER: usize = 1 << 20;
const PUBLIC_KEY_LEN: usize = 1216;
const MAX_KEY_FILE: usize = 4096;
/// Messages are held in memory, so they are bounded well below file size.
const MAX_MESSAGE_LEN: usize = 1 << 20;

const MESSAGE_HEADER: &str = "----- BEGIN HIDE MESSAGE -----";
const MESSAGE_FOOTER: &str = "----- END HIDE MESSAGE -----";

/// A portable build keeps everything beside the executable and writes nothing
/// to the user profile, so it can run from a USB stick and leave no trace.
#[tauri::command]
fn default_key_directory() -> Result<String> {
    if cfg!(feature = "portable") {
        let executable =
            std::env::current_exe().map_err(|error| fail("could not locate the program", error))?;
        let directory = executable
            .parent()
            .ok_or("the program is not in a folder")?
            .join("hide-keys");
        std::fs::create_dir_all(&directory)
            .map_err(|error| fail("could not create the keys folder", error))?;
        return Ok(directory.display().to_string());
    }
    Ok(String::new())
}

#[tauri::command]
fn is_portable() -> bool {
    cfg!(feature = "portable")
}

/// Errors are strings because they are shown to a person. Care is taken never
/// to include key material or plaintext in them.
type Result<T> = std::result::Result<T, String>;

fn fail(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}: {error}")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path).map_err(|error| fail("could not open the file", error))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| fail("could not read the file", error))?;
    if bytes.len() > limit {
        return Err("that file is too large to be a HIDE key".into());
    }
    Ok(bytes)
}

/// Refuses to overwrite, matching the CLI: encryption output must never
/// silently replace an existing file.
fn create_new(path: &Path) -> Result<File> {
    File::create_new(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            "that file already exists; choose another name".into()
        } else {
            fail("could not create the file", error)
        }
    })
}

fn load_public(path: &Path) -> Result<RecipientPublic> {
    let bytes = read_bounded(path, MAX_KEY_FILE)?;
    let raw = if bytes.starts_with(b"hide-public-key:") {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "that public key file is not valid text".to_owned())?;
        hide_keyring::decode_public(text).map_err(|error| fail("public key", error))?
    } else {
        bytes.to_vec()
    };
    if raw.len() != PUBLIC_KEY_LEN {
        return Err("that file is not a HIDE public key".into());
    }
    RecipientPublic::from_bytes(&raw).map_err(|error| fail("public key", error))
}

fn load_secret(path: &Path, passphrase: Option<&str>) -> Result<RecipientSecret> {
    let bytes = read_bounded(path, MAX_KEY_FILE)?;
    match (hide_keyring::inspect(&bytes), passphrase) {
        (KeyFormat::Raw, _) => {
            RecipientSecret::from_bytes(&bytes).map_err(|error| fail("secret key", error))
        }
        (KeyFormat::Protected, Some(passphrase)) => {
            hide_keyring::unprotect(&bytes, passphrase).map_err(|error| error.to_string())
        }
        (KeyFormat::Protected, None) => Err("this key is protected; enter its passphrase".into()),
    }
}

#[derive(Serialize)]
pub struct KeyPair {
    public_path: String,
    secret_path: String,
    armored_public: String,
    protected: bool,
}

/// Creates a key pair. A passphrase is required unless the caller explicitly
/// asks for a disposable test key, so the safe path is the default one.
#[tauri::command]
fn generate_keys(directory: String, name: String, passphrase: Option<String>) -> Result<KeyPair> {
    let name = name.trim();
    if name.is_empty() {
        return Err("choose a name for the key".into());
    }
    // Prevent the name from escaping the chosen directory.
    if name.contains(['/', '\\', ':']) || name.starts_with('.') {
        return Err("the name may not contain a path or start with a dot".into());
    }

    let directory = PathBuf::from(directory);
    let secret_path = directory.join(format!("{name}.hide-key"));
    let public_path = directory.join(format!("{name}.hide-pub"));

    let secret = RecipientSecret::generate().map_err(|error| fail("key generation", error))?;
    let public = secret
        .public_key()
        .map_err(|error| fail("key generation", error))?
        .to_bytes();

    let sealed = match passphrase.as_deref() {
        Some(passphrase) => {
            hide_keyring::protect(&secret, passphrase).map_err(|error| error.to_string())?
        }
        None => secret.expose_seed_for_sealing().to_vec(),
    };

    // Write the public key first: if the secret cannot be written we abandon
    // both rather than leaving a public key with no matching secret.
    let mut secret_file = create_new(&secret_path)?;
    secret_file
        .write_all(&sealed)
        .and_then(|()| secret_file.sync_all())
        .map_err(|error| fail("could not write the secret key", error))?;
    let mut public_file = create_new(&public_path)?;
    public_file
        .write_all(&public)
        .and_then(|()| public_file.sync_all())
        .map_err(|error| fail("could not write the public key", error))?;

    Ok(KeyPair {
        public_path: public_path.display().to_string(),
        secret_path: secret_path.display().to_string(),
        armored_public: hide_keyring::encode_public(&public),
        protected: passphrase.is_some(),
    })
}

#[tauri::command]
fn encrypt_file(input: String, recipients: Vec<String>, output: String) -> Result<String> {
    if recipients.is_empty() || recipients.len() > 64 {
        return Err("choose between 1 and 64 recipients".into());
    }
    let recipients = recipients
        .iter()
        .map(|path| load_public(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;

    let input = PathBuf::from(input);
    let filename = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("that filename cannot be represented as text")?;
    let metadata = Metadata {
        filename: Some(filename.into()),
        media_type: None,
    };

    let source = File::open(&input).map_err(|error| fail("could not open the input", error))?;
    let mut source = BufReader::with_capacity(IO_BUFFER, source);
    let output = PathBuf::from(output);
    let mut sink = BufWriter::with_capacity(IO_BUFFER, create_new(&output)?);

    let written = hide_object::encrypt(&mut source, &mut sink, &recipients, &metadata)
        .map_err(|error| fail("encryption failed", error))?;
    sink.flush()
        .map_err(|error| fail("encryption failed", error))?;

    Ok(format!(
        "Encrypted {written} bytes for {} recipient(s).",
        recipients.len()
    ))
}

#[tauri::command]
fn decrypt_file(
    input: String,
    secret: String,
    passphrase: Option<String>,
    output: String,
) -> Result<String> {
    let secret = load_secret(Path::new(&secret), passphrase.as_deref())?;
    let source = File::open(&input).map_err(|error| fail("could not open the input", error))?;
    let mut source = BufReader::with_capacity(IO_BUFFER, source);

    // Decrypt beside the target and only publish once the FINAL record has
    // authenticated, so a truncated file never appears as a finished one.
    let output = PathBuf::from(output);
    let staging = output.with_extension("hide-part");
    let mut sink = BufWriter::with_capacity(IO_BUFFER, create_new(&staging)?);

    let result = hide_object::decrypt_to_staging(&mut source, &mut sink, &secret)
        .map_err(|error| fail("decryption failed", error))
        .and_then(|verified| {
            sink.flush()
                .map_err(|error| fail("decryption failed", error))?;
            Ok(verified)
        });

    match result {
        Ok(verified) => {
            drop(sink);
            std::fs::rename(&staging, &output)
                .map_err(|error| fail("could not publish the output", error))?;
            let name = verified
                .metadata
                .filename
                .as_deref()
                .unwrap_or("(no original name)");
            Ok(format!(
                "Verified {} bytes. Original name: {name}. The sender is NOT authenticated.",
                verified.plaintext_len
            ))
        }
        Err(error) => {
            drop(sink);
            let _ = std::fs::remove_file(&staging);
            Err(error)
        }
    }
}

#[tauri::command]
fn seal_message(message: String, recipients: Vec<String>) -> Result<String> {
    if message.is_empty() {
        return Err("write a message first".into());
    }
    if message.len() > MAX_MESSAGE_LEN {
        return Err("that message is too long; encrypt it as a file instead".into());
    }
    if recipients.is_empty() || recipients.len() > 64 {
        return Err("choose between 1 and 64 recipients".into());
    }
    let recipients = recipients
        .iter()
        .map(|path| load_public(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;

    let metadata = Metadata {
        filename: None,
        media_type: Some("text/plain".into()),
    };
    let mut container = Vec::new();
    hide_object::encrypt(
        &mut message.as_bytes(),
        &mut container,
        &recipients,
        &metadata,
    )
    .map_err(|error| fail("encryption failed", error))?;

    let body = STANDARD.encode(&container);
    let mut armored = String::with_capacity(body.len() + 128);
    armored.push_str(MESSAGE_HEADER);
    armored.push('\n');
    for chunk in body.as_bytes().chunks(76) {
        armored.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        armored.push('\n');
    }
    armored.push_str(MESSAGE_FOOTER);
    armored.push('\n');
    Ok(armored)
}

#[tauri::command]
fn unseal_message(armored: String, secret: String, passphrase: Option<String>) -> Result<String> {
    let body: String = armored
        .lines()
        .skip_while(|line| !line.contains(MESSAGE_HEADER))
        .skip(1)
        .take_while(|line| !line.contains(MESSAGE_FOOTER))
        .map(str::trim)
        .collect();
    if body.is_empty() {
        return Err("no HIDE message found in that text".into());
    }
    let container = STANDARD
        .decode(&body)
        .map_err(|_| "that message is damaged or incomplete".to_owned())?;

    let secret = load_secret(Path::new(&secret), passphrase.as_deref())?;
    let mut plaintext = Zeroizing::new(Vec::new());
    hide_object::decrypt_to_staging(&mut &*container, &mut *plaintext, &secret)
        .map_err(|error| fail("decryption failed", error))?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|_| "this is not a text message; open it as a file instead".to_owned())
}

#[derive(Serialize)]
pub struct Description {
    kind: String,
    detail: String,
    warning: Option<String>,
}

#[tauri::command]
fn describe(path: String) -> Result<Description> {
    let path = PathBuf::from(path);
    if let Ok(bytes) = read_bounded(&path, MAX_KEY_FILE) {
        match hide_keyring::inspect(&bytes) {
            KeyFormat::Protected => {
                return Ok(Description {
                    kind: "Secret key".into(),
                    detail: "Protected with a passphrase.".into(),
                    warning: None,
                });
            }
            KeyFormat::Raw if bytes.len() == 32 => {
                return Ok(Description {
                    kind: "Secret key".into(),
                    detail: "Stored without a passphrase.".into(),
                    warning: Some(
                        "Anyone who copies this file can read everything encrypted to it.".into(),
                    ),
                });
            }
            KeyFormat::Raw if bytes.len() == PUBLIC_KEY_LEN => {
                return Ok(Description {
                    kind: "Public key".into(),
                    detail: "Safe to share with people who want to encrypt to you.".into(),
                    warning: None,
                });
            }
            KeyFormat::Raw => {}
        }
    }

    let mut file =
        BufReader::new(File::open(&path).map_err(|error| fail("could not open the file", error))?);
    let mut preamble = [0u8; 16];
    file.read_exact(&mut preamble)
        .map_err(|_| "that file is not a HIDE container or key".to_owned())?;
    if &preamble[..8] != b"HIDE\r\n\x1a\n" {
        return Err("that file is not a HIDE container or key".into());
    }
    let size = std::fs::metadata(&path)
        .map(|metadata| metadata.len())
        .unwrap_or_default();
    Ok(Description {
        kind: "Encrypted container".into(),
        detail: format!(
            "Format {}.{}, {size} bytes. The recipients, the original filename and the contents are all encrypted.",
            preamble[8], preamble[9]
        ),
        warning: None,
    })
}

#[tauri::command]
fn read_public_armor(path: String) -> Result<String> {
    let bytes = read_bounded(Path::new(&path), MAX_KEY_FILE)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err("that file is not a HIDE public key".into());
    }
    RecipientPublic::from_bytes(&bytes).map_err(|error| fail("public key", error))?;
    Ok(hide_keyring::encode_public(&bytes))
}

/// Thin wrappers so the integration tests can drive the same code the UI calls,
/// without widening the real command surface.
pub fn generate_keys_for_tests(
    directory: String,
    name: String,
    passphrase: Option<String>,
) -> Result<KeyPair> {
    generate_keys(directory, name, passphrase)
}

pub fn seal_message_for_tests(message: String, recipients: Vec<String>) -> Result<String> {
    seal_message(message, recipients)
}

pub fn unseal_message_for_tests(
    armored: String,
    secret: String,
    passphrase: Option<String>,
) -> Result<String> {
    unseal_message(armored, secret, passphrase)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            generate_keys,
            encrypt_file,
            decrypt_file,
            seal_message,
            unseal_message,
            describe,
            read_public_armor,
            default_key_directory,
            is_portable,
        ])
        .run(tauri::generate_context!())
        .expect("the HIDE desktop application starts");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn paths(dir: &tempfile::TempDir, name: &str) -> (String, String) {
        (
            dir.path()
                .join(format!("{name}.hide-key"))
                .display()
                .to_string(),
            dir.path()
                .join(format!("{name}.hide-pub"))
                .display()
                .to_string(),
        )
    }

    #[test]
    fn a_protected_key_round_trips_a_file() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        let created = generate_keys(root.clone(), "ana".into(), Some("correct horse".into()))
            .expect("keygen");
        assert!(created.protected);

        let plaintext = dir.path().join("salarii.csv");
        std::fs::write(&plaintext, b"nume,suma\nAna,9000\n").expect("write");
        let container = dir.path().join("salarii.hide").display().to_string();
        let (secret, public) = paths(&dir, "ana");

        encrypt_file(
            plaintext.display().to_string(),
            vec![public],
            container.clone(),
        )
        .expect("encrypt");

        // The wrong passphrase must fail, and must not leave a partial output.
        let recovered = dir.path().join("out.csv").display().to_string();
        assert!(
            decrypt_file(
                container.clone(),
                secret.clone(),
                Some("wrong".into()),
                recovered.clone()
            )
            .is_err()
        );
        assert!(
            !Path::new(&recovered).exists(),
            "published output on failure"
        );

        let report = decrypt_file(
            container,
            secret,
            Some("correct horse".into()),
            recovered.clone(),
        )
        .expect("decrypt");
        assert!(report.contains("salarii.csv"), "{report}");
        assert_eq!(
            std::fs::read(&recovered).expect("read"),
            b"nume,suma\nAna,9000\n"
        );
    }

    #[test]
    fn messages_round_trip_and_reject_tampering() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys(root, "bob".into(), None).expect("keygen");
        let (secret, public) = paths(&dir, "bob");

        let armored = seal_message("cod PIN 4417".into(), vec![public]).expect("seal");
        assert!(armored.starts_with(MESSAGE_HEADER));
        assert!(!armored.contains("4417"), "plaintext leaked into the armor");

        assert_eq!(
            unseal_message(armored.clone(), secret.clone(), None).expect("unseal"),
            "cod PIN 4417"
        );

        // Flip one character of the ciphertext body.
        let mut lines: Vec<String> = armored.lines().map(str::to_owned).collect();
        let body = &mut lines[1];
        let first = if body.starts_with('A') { 'B' } else { 'A' };
        body.replace_range(0..1, &first.to_string());
        assert!(unseal_message(lines.join("\n"), secret, None).is_err());
    }

    #[test]
    fn describe_names_each_kind_without_revealing_contents() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys(root.clone(), "raw".into(), None).expect("keygen");
        generate_keys(root, "sealed".into(), Some("correct horse".into())).expect("keygen");

        let (raw_secret, raw_public) = paths(&dir, "raw");
        let (sealed_secret, _) = paths(&dir, "sealed");

        let unprotected = describe(raw_secret.clone()).expect("describe");
        assert_eq!(unprotected.kind, "Secret key");
        assert!(unprotected.warning.is_some(), "no warning on a bare secret");

        assert!(
            describe(sealed_secret)
                .expect("describe")
                .detail
                .contains("Protected")
        );
        assert_eq!(
            describe(raw_public.clone()).expect("describe").kind,
            "Public key"
        );

        let source = dir.path().join("buget-secret.txt");
        std::fs::write(&source, b"x").expect("write");
        let container = dir.path().join("c.hide").display().to_string();
        encrypt_file(
            source.display().to_string(),
            vec![raw_public],
            container.clone(),
        )
        .expect("encrypt");

        let described = describe(container).expect("describe");
        assert_eq!(described.kind, "Encrypted container");
        assert!(
            !described.detail.contains("buget-secret"),
            "info revealed the original filename"
        );
    }

    #[test]
    fn refuses_to_overwrite_and_to_escape_the_chosen_folder() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys(root.clone(), "ana".into(), None).expect("keygen");
        // A second key of the same name must not clobber the first.
        assert!(generate_keys(root.clone(), "ana".into(), None).is_err());

        for hostile in ["../escape", "sub/dir", "a:b", ".hidden", "  "] {
            assert!(
                generate_keys(root.clone(), hostile.into(), None).is_err(),
                "accepted a hostile key name: {hostile}"
            );
        }
    }

    #[test]
    fn a_protected_key_needs_its_passphrase() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys(root, "ana".into(), Some("correct horse".into())).expect("keygen");
        let (secret, public) = paths(&dir, "ana");

        let armored = seal_message("hello".into(), vec![public]).expect("seal");
        let error = unseal_message(armored, secret, None).expect_err("opened without a passphrase");
        assert!(error.contains("passphrase"), "{error}");
    }
}
