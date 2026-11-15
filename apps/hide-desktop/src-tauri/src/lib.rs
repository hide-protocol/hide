//! Desktop bindings for the HIDE core.
//!
//! The frontend never receives key material. Secrets are loaded, used and
//! dropped entirely inside these commands; only ciphertext, public keys and
//! human-readable status ever cross into the webview.
//!
//! It does not receive a usable path either. The operating-system file dialogs
//! run here, and every command takes an id for a path the user chose in one of
//! them, so a frontend that goes wrong cannot name a file of its own choosing.

use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_keyring::KeyFormat;
use hide_object::Metadata;
use serde::Serialize;
use tauri::State;
use tauri_plugin_dialog::{DialogExt, FileDialogBuilder};
use zeroize::Zeroizing;

const IO_BUFFER: usize = 1 << 20;
const PUBLIC_KEY_LEN: usize = 1216;
const MAX_KEY_FILE: usize = 4096;
/// Messages are held in memory, so they are bounded well below file size.
const MAX_MESSAGE_LEN: usize = 1 << 20;

const MESSAGE_HEADER: &str = "----- BEGIN HIDE MESSAGE -----";
const MESSAGE_FOOTER: &str = "----- END HIDE MESSAGE -----";

/// Errors are strings because they are shown to a person. Care is taken never
/// to include key material or plaintext in them.
type Result<T> = std::result::Result<T, String>;

fn fail(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}: {error}")
}

/// Paths the user picked, kept here rather than in the webview.
///
/// A command accepts only one of these ids, never a path, so the files it can
/// reach are exactly the ones a person selected in an operating-system dialog.
#[derive(Default)]
struct Vault {
    counter: u64,
    order: VecDeque<String>,
    chosen: HashMap<String, PathBuf>,
}

/// Bounded so a long session cannot grow without limit. The oldest id is
/// forgotten first, and using one afterwards is a clean error, not a mystery.
const MAX_CHOSEN_PATHS: usize = 256;

impl Vault {
    fn remember(&mut self, path: PathBuf) -> String {
        self.counter += 1;
        let id = format!("chosen-{}", self.counter);
        while self.order.len() >= MAX_CHOSEN_PATHS {
            if let Some(oldest) = self.order.pop_front() {
                self.chosen.remove(&oldest);
            }
        }
        self.order.push_back(id.clone());
        self.chosen.insert(id.clone(), path);
        id
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        self.chosen
            .get(id)
            .cloned()
            .ok_or_else(|| "that file is no longer selected; choose it again".to_owned())
    }
}

type VaultPointer<'a> = State<'a, Mutex<Vault>>;

fn locked<'a>(vault: &'a VaultPointer<'_>) -> Result<std::sync::MutexGuard<'a, Vault>> {
    vault
        .lock()
        .map_err(|_| "the list of chosen files is unavailable".to_owned())
}

/// Turns an id into the path it stands for, or refuses it. Nothing else is ever
/// treated as a path.
fn chosen_path(vault: &VaultPointer<'_>, id: &str) -> Result<PathBuf> {
    locked(vault)?.path(id)
}

fn remember_path(vault: &VaultPointer<'_>, path: PathBuf) -> Result<Selection> {
    let id = locked(vault)?.remember(path.clone());
    Ok(Selection {
        id,
        path: path.display().to_string(),
    })
}

/// A file the user chose: an opaque id for the commands, and the path to show.
#[derive(Serialize, Clone)]
pub struct Selection {
    pub id: String,
    pub path: String,
}

/// Which files a chooser admits. The webview names a kind and cannot widen it.
fn filters_for(kind: &str) -> Vec<(&'static str, &'static [&'static str])> {
    match kind {
        "public" => vec![("HIDE public key", &["hide-pub", "txt"])],
        "secret" => vec![("HIDE secret key", &["hide-key"])],
        "container" => vec![("HIDE container", &["hide"])],
        _ => Vec::new(),
    }
}

fn chooser<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    kind: &str,
    title: &str,
) -> FileDialogBuilder<R> {
    let mut dialog = app.dialog().file().set_title(title);
    for (name, extensions) in filters_for(kind) {
        dialog = dialog.add_filter(name, extensions);
    }
    dialog
}

/// The save dialog starts with a name, never a path. A name carrying a
/// separator is replaced by a plain one, so the prefill cannot point outside
/// the folder the dialog is showing.
fn suggested_file_name(name: &str, fallback: &str) -> String {
    if name.is_empty() || name.contains(['/', '\\', ':']) || name.starts_with('.') {
        fallback.to_owned()
    } else {
        name.to_owned()
    }
}

/// Opens the file chooser here and hands back an id, never the path to use.
#[tauri::command]
async fn choose_files(
    app: tauri::AppHandle,
    vault: VaultPointer<'_>,
    kind: String,
    multiple: bool,
) -> Result<Vec<Selection>> {
    let dialog = chooser(&app, &kind, "Choose a file");
    let picked = tauri::async_runtime::spawn_blocking(move || {
        if multiple {
            dialog.blocking_pick_files().unwrap_or_default()
        } else {
            dialog.blocking_pick_file().into_iter().collect()
        }
    })
    .await
    .map_err(|error| fail("the file chooser did not finish", error))?;

    let mut selections = Vec::with_capacity(picked.len());
    for file in picked {
        let path = file
            .into_path()
            .map_err(|error| fail("the chosen file", error))?;
        selections.push(remember_path(&vault, path)?);
    }
    Ok(selections)
}

#[tauri::command]
async fn choose_directory(
    app: tauri::AppHandle,
    vault: VaultPointer<'_>,
) -> Result<Option<Selection>> {
    let dialog = chooser(&app, "any", "Choose a folder");
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_pick_folder())
        .await
        .map_err(|error| fail("the folder chooser did not finish", error))?;
    let Some(folder) = picked else {
        return Ok(None);
    };
    let path = folder
        .into_path()
        .map_err(|error| fail("the chosen folder", error))?;
    Ok(Some(remember_path(&vault, path)?))
}

#[tauri::command]
async fn choose_save_path(
    app: tauri::AppHandle,
    vault: VaultPointer<'_>,
    kind: String,
    suggested_name: String,
) -> Result<Option<Selection>> {
    let dialog = chooser(&app, &kind, "Choose where to save")
        .set_file_name(suggested_file_name(&suggested_name, "protected.hide"));
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|error| fail("the save dialog did not finish", error))?;
    let Some(target) = picked else {
        return Ok(None);
    };
    let path = target
        .into_path()
        .map_err(|error| fail("the chosen name", error))?;
    Ok(Some(remember_path(&vault, path)?))
}

/// A portable build keeps its keys beside the executable, so the program and
/// the keys it needs can travel on a USB stick. Only the keys move: the
/// webview's own profile still lives under the user profile.
#[tauri::command]
async fn default_key_directory(vault: VaultPointer<'_>) -> Result<Option<Selection>> {
    if !cfg!(feature = "portable") {
        return Ok(None);
    }
    let executable =
        std::env::current_exe().map_err(|error| fail("could not locate the program", error))?;
    let directory = executable
        .parent()
        .ok_or("the program is not in a folder")?
        .join("hide-keys");
    std::fs::create_dir_all(&directory)
        .map_err(|error| fail("could not create the keys folder", error))?;
    Ok(Some(remember_path(&vault, directory)?))
}

/// What this build is, and what that means for the person running it.
#[derive(Serialize)]
pub struct BuildInfo {
    version: String,
    portable: bool,
}

#[tauri::command]
fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        portable: cfg!(feature = "portable"),
    }
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

/// Creates a new file, refusing to replace one that already exists.
///
/// Policy: no-clobber, and the same one for encryption and for decryption. The
/// CLI refuses to overwrite, so the desktop does too, whichever "replace"
/// answer the operating-system save dialog handed back.
fn create_new(path: &Path) -> Result<File> {
    File::create_new(path).map_err(creation_error)
}

fn creation_error(error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        "that file already exists; choose another name".to_owned()
    } else {
        fail("could not create the file", error)
    }
}

/// The staging file carries the prefix the CLI sweeps, so a stale one left by a
/// killed process is recognisable in either surface's directory.
const STAGING_PREFIX: &str = ".hide-staging-";

/// Where decrypted plaintext is staged: beside the output, so publishing it is
/// a rename within one filesystem.
fn staging_directory(output: &Path) -> &Path {
    match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn publication_error(error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        "that file already exists; choose another name".to_owned()
    } else {
        fail("could not publish the output", error)
    }
}

/// Creates a new file that only its owner can read.
///
/// `File::create_new` takes the process umask, typically 0644, which for a
/// master seed is a world-readable private key. The mode is set explicitly on
/// unix, so a secret key written here means the same as one written by the CLI.
/// Decrypted output does not come through here: its staging file is a
/// `NamedTempFile`, which unix also creates 0600.
#[cfg(unix)]
fn create_private(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(creation_error)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> Result<File> {
    create_new(path)
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
    if matches!(hide_keyring::inspect(&bytes), KeyFormat::Protected) && passphrase.is_none() {
        return Err("this key is protected; enter its passphrase".into());
    }
    // Goes through keyring::open so a key file means the same here as it does
    // to the CLI and to every SDK: an unprotected file is a master seed.
    hide_keyring::open(&bytes, passphrase).map_err(|error| error.to_string())
}

#[derive(Serialize)]
pub struct KeyPair {
    pub public_path: String,
    pub secret_path: String,
    pub armored_public: String,
    pub protected: bool,
}

/// Creates a key pair. A passphrase is required unless the caller explicitly
/// asks for a disposable test key, so the safe path is the default one.
fn create_keys(directory: &Path, name: &str, passphrase: Option<&str>) -> Result<KeyPair> {
    let name = name.trim();
    if name.is_empty() {
        return Err("choose a name for the key".into());
    }
    // Prevent the name from escaping the chosen directory.
    if name.contains(['/', '\\', ':']) || name.starts_with('.') {
        return Err("the name may not contain a path or start with a dot".into());
    }

    let secret_path = directory.join(format!("{name}.hide-key"));
    let public_path = directory.join(format!("{name}.hide-pub"));

    // An identity, not a bare recipient key: one seed backs both encryption and
    // signing, and every surface reads a key file this way.
    let identity = hide_keyring::Identity::generate().map_err(|error| error.to_string())?;
    let public = identity
        .recipient_secret()
        .map_err(|error| error.to_string())?
        .public_key()
        .map_err(|error| fail("key generation", error))?
        .to_bytes();

    let sealed = match passphrase {
        Some(passphrase) => {
            hide_keyring::protect_identity(identity.expose_seed_for_sealing(), passphrase)
                .map_err(|error| error.to_string())?
        }
        None => identity.expose_seed_for_sealing().to_vec(),
    };

    // Write the public key first: if the secret cannot be written we abandon
    // both rather than leaving a public key with no matching secret.
    let mut secret_file = create_private(&secret_path)?;
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
async fn generate_keys(
    vault: VaultPointer<'_>,
    directory: String,
    name: String,
    passphrase: Option<String>,
) -> Result<KeyPair> {
    let directory = chosen_path(&vault, &directory)?;
    tauri::async_runtime::spawn_blocking(move || {
        create_keys(&directory, &name, passphrase.as_deref())
    })
    .await
    .map_err(|error| fail("key generation did not finish", error))?
}

fn encrypt_at(input: &Path, recipients: &[PathBuf], output: &Path) -> Result<String> {
    if recipients.is_empty() || recipients.len() > 64 {
        return Err("choose between 1 and 64 recipients".into());
    }
    let recipients = recipients
        .iter()
        .map(|path| load_public(path))
        .collect::<Result<Vec<_>>>()?;

    let filename = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("that filename cannot be represented as text")?;
    let metadata = Metadata {
        filename: Some(filename.into()),
        media_type: None,
        signature: None,
        extensions: Vec::new(),
    };

    let source = File::open(input).map_err(|error| fail("could not open the input", error))?;
    let mut source = BufReader::with_capacity(IO_BUFFER, source);
    let mut sink = BufWriter::with_capacity(IO_BUFFER, create_new(output)?);

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
async fn encrypt_file(
    vault: VaultPointer<'_>,
    input: String,
    recipients: Vec<String>,
    output: String,
) -> Result<String> {
    let input = chosen_path(&vault, &input)?;
    let recipients = recipients
        .iter()
        .map(|id| chosen_path(&vault, id))
        .collect::<Result<Vec<_>>>()?;
    let output = chosen_path(&vault, &output)?;
    tauri::async_runtime::spawn_blocking(move || encrypt_at(&input, &recipients, &output))
        .await
        .map_err(|error| fail("encryption did not finish", error))?
}

/// A container that decrypted and authenticated, described without its
/// contents.
#[derive(Debug, Serialize)]
pub struct Opened {
    pub plaintext_len: u64,
    pub filename: Option<String>,
    /// The signing key's short fingerprint, when the container carried a
    /// signature that verified. Same form the CLI prints.
    pub signer: Option<String>,
}

/// A short, comparable form of a signing key, matching `hide`'s own output so
/// a person can compare the two. Not a security boundary on its own: compare
/// the full key when it matters.
fn short_fingerprint(key: &[u8]) -> String {
    let digest = hide_crypto::hash(&[key]);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Decrypts beside the target and publishes only once the FINAL record has
/// authenticated, so a truncated file never appears as a finished one.
fn decrypt_object(input: &Path, secret: &RecipientSecret, output: &Path) -> Result<Opened> {
    let source = File::open(input).map_err(|error| fail("could not open the input", error))?;
    let mut source = BufReader::with_capacity(IO_BUFFER, source);

    // A NamedTempFile owns the staging file, so every failure below deletes it
    // and no half-written plaintext is ever left under a name of its own.
    let mut staging = tempfile::Builder::new()
        .prefix(STAGING_PREFIX)
        .tempfile_in(staging_directory(output))
        .map_err(|error| fail("could not create the staging file", error))?;

    let mut sink = BufWriter::with_capacity(IO_BUFFER, staging.as_file_mut());
    let verified = hide_object::decrypt_to_staging(&mut source, &mut sink, secret)
        .map_err(|error| fail("decryption failed", error))
        .and_then(|verified| {
            sink.flush()
                .map_err(|error| fail("decryption failed", error))?;
            Ok(verified)
        })?;
    drop(sink);

    // No-clobber, the same policy encryption applies: the staging file is
    // published only under a name that is still free, so a file the user
    // already has survives whatever "replace" answer the save dialog gave.
    staging
        .persist_noclobber(output)
        .map_err(|error| publication_error(error.error))?;

    Ok(Opened {
        plaintext_len: verified.plaintext_len,
        filename: verified.metadata.filename,
        signer: verified
            .signer
            .as_ref()
            .map(|signer| short_fingerprint(&signer.to_bytes())),
    })
}

fn decrypt_at(
    input: &Path,
    secret: &Path,
    passphrase: Option<&str>,
    output: &Path,
) -> Result<Opened> {
    let secret = load_secret(secret, passphrase)?;
    decrypt_object(input, &secret, output)
}

#[tauri::command]
async fn decrypt_file(
    vault: VaultPointer<'_>,
    input: String,
    secret: String,
    passphrase: Option<String>,
    output: String,
) -> Result<Opened> {
    let input = chosen_path(&vault, &input)?;
    let secret = chosen_path(&vault, &secret)?;
    let output = chosen_path(&vault, &output)?;
    tauri::async_runtime::spawn_blocking(move || {
        decrypt_at(&input, &secret, passphrase.as_deref(), &output)
    })
    .await
    .map_err(|error| fail("decryption did not finish", error))?
}

fn seal_at(message: &str, recipients: &[PathBuf]) -> Result<String> {
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
        .map(|path| load_public(path))
        .collect::<Result<Vec<_>>>()?;

    let metadata = Metadata {
        filename: None,
        media_type: Some("text/plain".into()),
        signature: None,
        extensions: Vec::new(),
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
async fn seal_message(
    vault: VaultPointer<'_>,
    message: String,
    recipients: Vec<String>,
) -> Result<String> {
    let recipients = recipients
        .iter()
        .map(|id| chosen_path(&vault, id))
        .collect::<Result<Vec<_>>>()?;
    tauri::async_runtime::spawn_blocking(move || seal_at(&message, &recipients))
        .await
        .map_err(|error| fail("encryption did not finish", error))?
}

/// A message that decrypted and authenticated, plus who signed it if anyone.
#[derive(Serialize)]
pub struct Unsealed {
    pub text: String,
    pub signer: Option<String>,
}

fn unseal_at(armored: &str, secret: &Path, passphrase: Option<&str>) -> Result<Unsealed> {
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

    let secret = load_secret(secret, passphrase)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    let verified = hide_object::decrypt_to_staging(&mut &*container, &mut *plaintext, &secret)
        .map_err(|error| fail("decryption failed", error))?;

    Ok(Unsealed {
        text: String::from_utf8(plaintext.to_vec())
            .map_err(|_| "this is not a text message; open it as a file instead".to_owned())?,
        signer: verified
            .signer
            .as_ref()
            .map(|signer| short_fingerprint(&signer.to_bytes())),
    })
}

#[tauri::command]
async fn unseal_message(
    vault: VaultPointer<'_>,
    armored: String,
    secret: String,
    passphrase: Option<String>,
) -> Result<Unsealed> {
    let secret = chosen_path(&vault, &secret)?;
    tauri::async_runtime::spawn_blocking(move || {
        unseal_at(&armored, &secret, passphrase.as_deref())
    })
    .await
    .map_err(|error| fail("decryption did not finish", error))?
}

#[derive(Serialize)]
pub struct Description {
    kind: String,
    detail: String,
    warning: Option<String>,
}

fn describe_at(path: &Path) -> Result<Description> {
    if let Ok(bytes) = read_bounded(path, MAX_KEY_FILE) {
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
        BufReader::new(File::open(path).map_err(|error| fail("could not open the file", error))?);
    let mut preamble = [0u8; 16];
    file.read_exact(&mut preamble)
        .map_err(|_| "that file is not a HIDE container or key".to_owned())?;
    if &preamble[..8] != b"HIDE\r\n\x1a\n" {
        return Err("that file is not a HIDE container or key".into());
    }
    let size = std::fs::metadata(path)
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
async fn describe(vault: VaultPointer<'_>, path: String) -> Result<Description> {
    let path = chosen_path(&vault, &path)?;
    tauri::async_runtime::spawn_blocking(move || describe_at(&path))
        .await
        .map_err(|error| fail("the file could not be read", error))?
}

fn read_armor_at(path: &Path) -> Result<String> {
    let bytes = read_bounded(path, MAX_KEY_FILE)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err("that file is not a HIDE public key".into());
    }
    RecipientPublic::from_bytes(&bytes).map_err(|error| fail("public key", error))?;
    Ok(hide_keyring::encode_public(&bytes))
}

#[tauri::command]
async fn read_public_armor(vault: VaultPointer<'_>, path: String) -> Result<String> {
    let path = chosen_path(&vault, &path)?;
    tauri::async_runtime::spawn_blocking(move || read_armor_at(&path))
        .await
        .map_err(|error| fail("the key could not be read", error))?
}

/// Thin wrappers so the integration tests can drive the same code the UI calls,
/// without widening the real command surface.
pub fn generate_keys_for_tests(
    directory: String,
    name: String,
    passphrase: Option<String>,
) -> Result<KeyPair> {
    create_keys(Path::new(&directory), &name, passphrase.as_deref())
}

pub fn encrypt_file_for_tests(
    input: String,
    recipients: Vec<String>,
    output: String,
) -> Result<String> {
    let recipients = recipients.iter().map(PathBuf::from).collect::<Vec<_>>();
    encrypt_at(Path::new(&input), &recipients, Path::new(&output))
}

pub fn decrypt_file_for_tests(
    input: String,
    secret: String,
    passphrase: Option<String>,
    output: String,
) -> Result<Opened> {
    decrypt_at(
        Path::new(&input),
        Path::new(&secret),
        passphrase.as_deref(),
        Path::new(&output),
    )
}

/// Opens a container with a secret the caller already holds, so a frozen vector
/// whose key file predates identities can still be driven through the same
/// decrypt-and-publish path the UI uses.
pub fn decrypt_with_secret_for_tests(
    input: String,
    secret: &RecipientSecret,
    output: String,
) -> Result<Opened> {
    decrypt_object(Path::new(&input), secret, Path::new(&output))
}

pub fn seal_message_for_tests(message: String, recipients: Vec<String>) -> Result<String> {
    let recipients = recipients.iter().map(PathBuf::from).collect::<Vec<_>>();
    seal_at(&message, &recipients)
}

pub fn unseal_message_for_tests(
    armored: String,
    secret: String,
    passphrase: Option<String>,
) -> Result<String> {
    unseal_with_signer_for_tests(armored, secret, passphrase).map(|opened| opened.text)
}

pub fn unseal_with_signer_for_tests(
    armored: String,
    secret: String,
    passphrase: Option<String>,
) -> Result<Unsealed> {
    unseal_at(&armored, Path::new(&secret), passphrase.as_deref())
}

pub fn describe_for_tests(path: String) -> Result<Description> {
    describe_at(Path::new(&path))
}

pub fn read_public_armor_for_tests(path: String) -> Result<String> {
    read_armor_at(Path::new(&path))
}

pub fn fingerprint_for_tests(key: &[u8]) -> String {
    short_fingerprint(key)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(Vault::default()))
        .invoke_handler(tauri::generate_handler![
            choose_files,
            choose_directory,
            choose_save_path,
            default_key_directory,
            build_info,
            generate_keys,
            encrypt_file,
            decrypt_file,
            seal_message,
            unseal_message,
            describe,
            read_public_armor,
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
        let created =
            generate_keys_for_tests(root.clone(), "ana".into(), Some("correct horse".into()))
                .expect("keygen");
        assert!(created.protected);

        let plaintext = dir.path().join("salarii.csv");
        std::fs::write(&plaintext, b"nume,suma\nAna,9000\n").expect("write");
        let container = dir.path().join("salarii.hide").display().to_string();
        let (secret, public) = paths(&dir, "ana");

        encrypt_file_for_tests(
            plaintext.display().to_string(),
            vec![public],
            container.clone(),
        )
        .expect("encrypt");

        // The wrong passphrase must fail, and must not leave a partial output.
        let recovered = dir.path().join("out.csv").display().to_string();
        assert!(
            decrypt_file_for_tests(
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

        let report = decrypt_file_for_tests(
            container,
            secret,
            Some("correct horse".into()),
            recovered.clone(),
        )
        .expect("decrypt");
        assert_eq!(report.filename.as_deref(), Some("salarii.csv"));
        assert!(
            report.signer.is_none(),
            "an unsigned container must not name a signer"
        );
        assert_eq!(
            std::fs::read(&recovered).expect("read"),
            b"nume,suma\nAna,9000\n"
        );
    }

    #[test]
    fn messages_round_trip_and_reject_tampering() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys_for_tests(root, "bob".into(), None).expect("keygen");
        let (secret, public) = paths(&dir, "bob");

        let armored = seal_message_for_tests("cod PIN 4417".into(), vec![public]).expect("seal");
        assert!(armored.starts_with(MESSAGE_HEADER));
        assert!(!armored.contains("4417"), "plaintext leaked into the armor");

        assert_eq!(
            unseal_message_for_tests(armored.clone(), secret.clone(), None).expect("unseal"),
            "cod PIN 4417"
        );

        // Flip one character of the ciphertext body.
        let mut lines: Vec<String> = armored.lines().map(str::to_owned).collect();
        let body = &mut lines[1];
        let first = if body.starts_with('A') { 'B' } else { 'A' };
        body.replace_range(0..1, &first.to_string());
        assert!(unseal_message_for_tests(lines.join("\n"), secret, None).is_err());
    }

    #[test]
    fn describe_names_each_kind_without_revealing_contents() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys_for_tests(root.clone(), "raw".into(), None).expect("keygen");
        generate_keys_for_tests(root, "sealed".into(), Some("correct horse".into()))
            .expect("keygen");

        let (raw_secret, raw_public) = paths(&dir, "raw");
        let (sealed_secret, _) = paths(&dir, "sealed");

        let unprotected = describe_for_tests(raw_secret.clone()).expect("describe");
        assert_eq!(unprotected.kind, "Secret key");
        assert!(unprotected.warning.is_some(), "no warning on a bare secret");

        assert!(
            describe_for_tests(sealed_secret)
                .expect("describe")
                .detail
                .contains("Protected")
        );
        assert_eq!(
            describe_for_tests(raw_public.clone())
                .expect("describe")
                .kind,
            "Public key"
        );

        let source = dir.path().join("buget-secret.txt");
        std::fs::write(&source, b"x").expect("write");
        let container = dir.path().join("c.hide").display().to_string();
        encrypt_file_for_tests(
            source.display().to_string(),
            vec![raw_public],
            container.clone(),
        )
        .expect("encrypt");

        let described = describe_for_tests(container).expect("describe");
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
        generate_keys_for_tests(root.clone(), "ana".into(), None).expect("keygen");
        // A second key of the same name must not clobber the first.
        assert!(generate_keys_for_tests(root.clone(), "ana".into(), None).is_err());

        for hostile in ["../escape", "sub/dir", "a:b", ".hidden", "  "] {
            assert!(
                generate_keys_for_tests(root.clone(), hostile.into(), None).is_err(),
                "accepted a hostile key name: {hostile}"
            );
        }
    }

    #[test]
    fn a_protected_key_needs_its_passphrase() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys_for_tests(root, "ana".into(), Some("correct horse".into())).expect("keygen");
        let (secret, public) = paths(&dir, "ana");

        let armored = seal_message_for_tests("hello".into(), vec![public]).expect("seal");
        let error = unseal_message_for_tests(armored, secret, None)
            .expect_err("opened without a passphrase");
        assert!(error.contains("passphrase"), "{error}");
    }

    /// The webview never names a path, so anything it sends that was not handed
    /// back by a chooser must be refused rather than resolved.
    #[test]
    fn only_a_chosen_path_can_be_looked_up() {
        let mut vault = Vault::default();
        let path = PathBuf::from("salarii.csv");
        let id = vault.remember(path.clone());
        assert_eq!(vault.path(&id).expect("the stored id resolves"), path);

        for invented in ["salarii.csv", "/etc/shadow", "chosen-0", "chosen-", ""] {
            assert!(
                vault.path(invented).is_err(),
                "resolved a path that was never chosen: {invented}"
            );
        }
    }

    #[test]
    fn the_vault_forgets_the_oldest_choice_first() {
        let mut vault = Vault::default();
        let first = vault.remember(PathBuf::from("first"));
        for index in 0..MAX_CHOSEN_PATHS {
            vault.remember(PathBuf::from(format!("later-{index}")));
        }
        assert_eq!(vault.chosen.len(), MAX_CHOSEN_PATHS);
        assert!(
            vault.path(&first).is_err(),
            "the vault grew without bound instead of forgetting the oldest id"
        );
    }

    #[test]
    fn a_suggested_name_cannot_point_outside_the_folder() {
        assert_eq!(
            suggested_file_name("salarii.hide", "protected.hide"),
            "salarii.hide"
        );
        for hostile in ["", "../escape.hide", "sub/dir.hide", "a:b", ".hidden"] {
            assert_eq!(
                suggested_file_name(hostile, "protected.hide"),
                "protected.hide",
                "accepted a hostile suggested name: {hostile}"
            );
        }
    }

    /// Decryption is no-clobber, like encryption: the file the user already has
    /// must survive, and so must the plaintext that was going to replace it.
    #[test]
    fn decryption_refuses_to_replace_an_existing_file() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys_for_tests(root, "ana".into(), None).expect("keygen");
        let (secret, public) = paths(&dir, "ana");

        let plaintext = dir.path().join("salarii.csv");
        std::fs::write(&plaintext, b"nume,suma\nAna,9000\n").expect("write");
        let container = dir.path().join("salarii.hide").display().to_string();
        encrypt_file_for_tests(
            plaintext.display().to_string(),
            vec![public],
            container.clone(),
        )
        .expect("encrypt");

        let recovered = dir.path().join("out.csv");
        std::fs::write(&recovered, b"do not lose me\n").expect("write");
        let error = decrypt_file_for_tests(
            container.clone(),
            secret.clone(),
            None,
            recovered.display().to_string(),
        )
        .expect_err("replaced a file that already existed");
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            std::fs::read(&recovered).expect("read"),
            b"do not lose me\n",
            "the existing file was damaged"
        );
        // The refused staging file is deleted, not renamed away: the folder the
        // user chose holds no half-written plaintext under any name.
        assert!(
            std::fs::read_dir(dir.path())
                .expect("read the chosen folder")
                .all(|entry| !entry
                    .expect("a directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGING_PREFIX)),
            "the staging file was left behind"
        );

        // Once the user picks a free name the same container opens.
        let free = dir.path().join("out-2.csv").display().to_string();
        assert_eq!(
            decrypt_file_for_tests(container, secret, None, free.clone())
                .expect("decrypt")
                .plaintext_len,
            b"nume,suma\nAna,9000\n".len() as u64
        );
        assert_eq!(
            std::fs::read(&free).expect("read"),
            b"nume,suma\nAna,9000\n"
        );
    }

    /// Encryption is no-clobber for the same reason decryption is: the file the
    /// user already has must survive whatever the save dialog answered, so both
    /// halves of the policy are asserted here rather than only one.
    #[test]
    fn encryption_refuses_to_replace_an_existing_file() {
        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys_for_tests(root, "ana".into(), None).expect("keygen");
        let (_, public) = paths(&dir, "ana");

        let plaintext = dir.path().join("salarii.csv");
        std::fs::write(&plaintext, b"nume,suma\nAna,9000\n").expect("write");
        let container = dir.path().join("salarii.hide");
        std::fs::write(&container, b"do not lose me\n").expect("write");

        let error = encrypt_file_for_tests(
            plaintext.display().to_string(),
            vec![public],
            container.display().to_string(),
        )
        .expect_err("replaced a file that already existed");
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            std::fs::read(&container).expect("read"),
            b"do not lose me\n",
            "the existing file was damaged"
        );
    }

    /// A master seed that anyone at the machine can read is not protected at
    /// all, so both the key file and the decrypted plaintext are owner-only.
    #[cfg(unix)]
    #[test]
    fn a_secret_key_and_a_decrypted_file_are_readable_only_by_their_owner() {
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path) -> u32 {
            std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
        }

        let dir = workspace();
        let root = dir.path().display().to_string();
        generate_keys_for_tests(root, "ana".into(), None).expect("keygen");
        let (secret, public) = paths(&dir, "ana");

        let key_mode = mode(Path::new(&secret));
        assert_eq!(
            key_mode & 0o077,
            0,
            "the master seed is readable by others: {key_mode:o}"
        );

        let plaintext = dir.path().join("buget.txt");
        std::fs::write(&plaintext, b"confidential\n").expect("write");
        let container = dir.path().join("buget.hide").display().to_string();
        encrypt_file_for_tests(
            plaintext.display().to_string(),
            vec![public],
            container.clone(),
        )
        .expect("encrypt");

        let recovered = dir.path().join("buget-back.txt");
        decrypt_file_for_tests(container, secret, None, recovered.display().to_string())
            .expect("decrypt");
        let output_mode = mode(&recovered);
        assert_eq!(
            output_mode & 0o077,
            0,
            "the decrypted file is readable by others: {output_mode:o}"
        );
    }
}
