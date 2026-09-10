use std::{
    error::Error,
    fs::File,
    io::{self, BufReader, BufWriter, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_epoch::EpochChain;
use hide_identity::IdentityLog;
use hide_keyring::{Identity, KeyFormat, KeyPurpose, MIN_PASSPHRASE_LEN};
use hide_object::{Metadata, SignaturePlacement};
use hide_sign::{SigningIdentity, VerifyingIdentity};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

mod agent;
mod transport;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const IO_BUFFER: usize = 1 << 20;
const PUBLIC_KEY_LEN: usize = 1216;
const MAX_KEY_FILE: usize = 4096;
const SIGNING_PUBLIC_LEN: usize = hide_sign::VERIFYING_KEY_LENGTH;
const MAX_SIGNING_KEY_FILE: usize = 8192;
/// Distinct from the container context. This is belt-and-braces: the two signed
/// messages already differ structurally (a container transcript binds the
/// recipient set and metadata, which a detached signature has no room for), so
/// removing this label alone does not enable a cross-domain forgery.
const DETACHED_CONTEXT: &[u8] = b"HIDE/0.5 detached";

#[derive(Parser)]
#[command(
    name = "hide",
    version,
    about = "HIDE: experimental file encryption, signing and identity; not for sensitive data"
)]
struct Arguments {
    #[arg(
        long,
        global = true,
        help = "Acknowledge that this protocol and implementation are unaudited"
    )]
    experimental: bool,
    #[arg(long, global = true, help = "Suppress the experimental warning banner")]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Create a key pair; the secret is sealed with a passphrase by default")]
    Keygen {
        #[arg(long, help = "Where to write the secret key")]
        secret: PathBuf,
        #[arg(long, help = "Where to write the shareable public key")]
        public: PathBuf,
        #[arg(
            long,
            help = "Write the secret UNENCRYPTED; only for disposable test keys"
        )]
        insecure_plaintext: bool,
        #[arg(long, help = "Also print the public key in a pasteable text form")]
        armor: bool,
        #[arg(
            long,
            help = "Where to write the shareable signing public key; defaults to <public>.sign"
        )]
        signing_public: Option<PathBuf>,
    },
    #[command(
        name = "test-keygen",
        about = "Deprecated alias for `keygen --insecure-plaintext`",
        hide = true
    )]
    TestKeygen {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    #[command(about = "Encrypt a file for one or more recipients")]
    Encrypt {
        input: PathBuf,
        #[arg(
            long,
            required = true,
            num_args = 1,
            help = "Public key file; repeat for additional recipients"
        )]
        recipient: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, help = "Sign the container with your identity key")]
        sign: Option<PathBuf>,
        #[arg(
            long,
            help = "Put the signature in the clear, visible to anyone holding the file"
        )]
        public_signature: bool,
    },
    #[command(about = "Decrypt to an explicit new file; does not launch or execute the result")]
    Open {
        input: PathBuf,
        #[arg(long)]
        secret: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    #[command(about = "Encrypt a short text message and print it as pasteable text")]
    Seal {
        #[arg(help = "Message text; omit to read from standard input")]
        message: Option<String>,
        #[arg(long, required = true, num_args = 1)]
        recipient: Vec<PathBuf>,
        #[arg(short, long, help = "Write to a file instead of standard output")]
        output: Option<PathBuf>,
    },
    #[command(about = "Decrypt a pasteable message and print the text")]
    Unseal {
        #[arg(help = "File containing the message; omit to read from standard input")]
        input: Option<PathBuf>,
        #[arg(long)]
        secret: PathBuf,
    },
    #[command(about = "Describe a container or key file without decrypting it")]
    Info { path: PathBuf },
    #[command(about = "Print a public key in pasteable text form")]
    Share { public: PathBuf },
    #[command(about = "Change the passphrase protecting a secret key")]
    Passwd {
        #[arg(long)]
        secret: PathBuf,
    },
    #[command(about = "Sign a file, writing a detached signature alongside it")]
    Sign {
        input: PathBuf,
        #[arg(long, help = "Your identity key")]
        secret: PathBuf,
        #[arg(
            short,
            long,
            help = "Where to write the signature; defaults to <input>.hide-sig"
        )]
        output: Option<PathBuf>,
    },
    #[command(about = "Check a detached signature against a signer's public key")]
    Verify {
        input: PathBuf,
        #[arg(long, help = "The signer's public signing key")]
        signer: PathBuf,
        #[arg(long, help = "The signature file; defaults to <input>.hide-sig")]
        signature: Option<PathBuf>,
    },
    #[command(
        about = "Print the OpenSSH public key line for an identity, to paste into authorized_keys or GitHub"
    )]
    SshKey {
        #[arg(long, help = "Your identity key")]
        secret: PathBuf,
        #[arg(long, help = "The comment to place at the end of the line")]
        comment: Option<String>,
    },
    #[command(about = "Serve this identity to OpenSSH as an ssh-agent, without writing a key file")]
    Agent {
        #[arg(long, help = "Your identity key")]
        secret: PathBuf,
        #[arg(
            long,
            help = "Where to listen; a socket on Unix, a named pipe on Windows"
        )]
        endpoint: Option<String>,
        #[arg(long, help = "Sign without asking; every request then signs silently")]
        no_confirm: bool,
        #[arg(long, help = "The comment to advertise with the key")]
        comment: Option<String>,
    },
    #[command(about = "Create an identity log: a device history that can be audited")]
    IdentityCreate {
        #[arg(long, help = "The founding device's identity key")]
        secret: PathBuf,
        #[arg(long, help = "The offline recovery key's public half")]
        recovery: PathBuf,
        #[arg(long, help = "A label for the founding device")]
        label: String,
        #[arg(long, help = "Where to write the log")]
        output: PathBuf,
    },
    #[command(about = "Add a device to an identity log")]
    IdentityEnrol {
        #[arg(long, help = "The log to append to")]
        log: PathBuf,
        #[arg(long, help = "An already-trusted device's identity key")]
        secret: PathBuf,
        #[arg(long, help = "The new device's signing public key")]
        device: PathBuf,
        #[arg(long, help = "A label for the new device")]
        label: String,
        #[arg(long, help = "The offline recovery key's public half")]
        recovery: PathBuf,
    },
    #[command(about = "Remove a device from an identity log")]
    IdentityRevoke {
        #[arg(long, help = "The log to append to")]
        log: PathBuf,
        #[arg(long, help = "An already-trusted device's identity key")]
        secret: PathBuf,
        #[arg(long, help = "The signing public key of the device to remove")]
        device: PathBuf,
        #[arg(long, help = "The offline recovery key's public half")]
        recovery: PathBuf,
    },
    #[command(about = "Replay an identity log and list the devices it trusts now")]
    IdentityShow {
        #[arg(long, help = "The log to replay")]
        log: PathBuf,
        #[arg(long, help = "The offline recovery key's public half")]
        recovery: PathBuf,
    },
    #[command(
        about = "Create an epoch chain: rotating keys you can erase to make old files unreadable"
    )]
    EpochInit {
        #[arg(long, help = "Where to write the public epoch history")]
        output: PathBuf,
    },
    #[command(about = "Describe an epoch history without needing any secret")]
    EpochShow {
        #[arg(long, help = "The published epoch history")]
        chain: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hide: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<()> {
    if !arguments.experimental {
        return Err("pass --experimental; HIDE/0.5 is unaudited and not for sensitive data".into());
    }
    if !arguments.quiet {
        eprintln!(
            "WARNING: experimental, unaudited HIDE/0.5. A signature attests to a key, not to a person."
        );
    }
    match arguments.command {
        Command::Keygen {
            secret,
            public,
            insecure_plaintext,
            armor,
            signing_public,
        } => keygen(
            &secret,
            &public,
            insecure_plaintext,
            armor,
            signing_public.as_deref(),
        ),
        Command::TestKeygen { secret, public } => {
            eprintln!("note: `test-keygen` is deprecated; use `keygen --insecure-plaintext`");
            keygen(&secret, &public, true, false, None)
        }
        Command::Encrypt {
            input,
            recipient,
            output,
            sign,
            public_signature,
        } => encrypt_file(
            &input,
            &recipient,
            &output,
            sign.as_deref(),
            public_signature,
        ),
        Command::IdentityCreate {
            secret,
            recovery,
            label,
            output,
        } => identity_create(&secret, &recovery, &label, &output),
        Command::IdentityEnrol {
            log,
            secret,
            device,
            label,
            recovery,
        } => identity_enrol(&log, &secret, &device, &label, &recovery),
        Command::IdentityRevoke {
            log,
            secret,
            device,
            recovery,
        } => identity_revoke(&log, &secret, &device, &recovery),
        Command::IdentityShow { log, recovery } => identity_show(&log, &recovery),
        Command::EpochInit { output } => epoch_init(&output),
        Command::EpochShow { chain } => epoch_show(&chain),
        Command::Open {
            input,
            secret,
            output,
        } => open_file(&input, &secret, &output),
        Command::Seal {
            message,
            recipient,
            output,
        } => seal_message(message.as_deref(), &recipient, output.as_deref()),
        Command::Unseal { input, secret } => unseal_message(input.as_deref(), &secret),
        Command::Info { path } => describe(&path),
        Command::Share { public } => share(&public),
        Command::Passwd { secret } => change_passphrase(&secret),
        Command::Sign {
            input,
            secret,
            output,
        } => sign_file(&input, &secret, output.as_deref()),
        Command::Verify {
            input,
            signer,
            signature,
        } => verify_file(&input, &signer, signature.as_deref()),
        Command::SshKey { secret, comment } => print_ssh_key(&secret, comment.as_deref()),
        Command::Agent {
            secret,
            endpoint,
            no_confirm,
            comment,
        } => run_agent(&secret, endpoint.as_deref(), no_confirm, comment.as_deref()),
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(format!("{} is larger than expected for a key file", path.display()).into());
    }
    Ok(bytes)
}

/// An armored message is meant to be pasted into a chat window, so it is small
/// by construction. The same 1 MiB ceiling the desktop app applies, so a
/// message accepted by one surface is accepted by the other.
const MAX_ARMORED_MESSAGE: usize = 1024 * 1024;

/// Reads armored text from a file or stdin, bounded. An unbounded read here
/// would let a pipe or a huge file exhaust memory before any parsing happens.
fn read_armored_message(input: Option<&Path>) -> Result<String> {
    let mut bytes = Vec::new();
    match input {
        Some(path) => {
            File::open(path)?
                .take(MAX_ARMORED_MESSAGE as u64 + 1)
                .read_to_end(&mut bytes)?;
        }
        None => {
            io::stdin()
                .take(MAX_ARMORED_MESSAGE as u64 + 1)
                .read_to_end(&mut bytes)?;
        }
    }
    if bytes.len() > MAX_ARMORED_MESSAGE {
        return Err("that armored message is larger than 1 MiB; use `open` instead".into());
    }
    String::from_utf8(bytes).map_err(|_| "an armored message must be valid UTF-8".into())
}

fn new_output(path: &Path) -> Result<NamedTempFile> {
    if path.try_exists()? || path.symlink_metadata().is_ok() {
        return Err("output already exists; refusing to overwrite".into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(tempfile::Builder::new()
        .prefix(".hide-staging-")
        .tempfile_in(parent)?)
}

fn commit_output(mut staging: NamedTempFile, path: &Path) -> Result<()> {
    staging.flush()?;
    staging.as_file().sync_all()?;
    staging.persist_noclobber(path).map_err(|error| {
        io::Error::new(
            error.error.kind(),
            "could not publish output without overwriting",
        )
    })?;
    Ok(())
}

/// Reads a passphrase without echoing it, and never from a pipe: a passphrase
/// arriving on standard input would come from shell history or a CI log.
fn prompt_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        return Err("a passphrase is required, but standard input is not a terminal".into());
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn prompt_new_passphrase() -> Result<Zeroizing<String>> {
    let first = prompt_passphrase("New passphrase: ")?;
    if first.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!("passphrase must be at least {MIN_PASSPHRASE_LEN} characters").into());
    }
    let second = prompt_passphrase("Confirm passphrase: ")?;
    if *first != *second {
        return Err("passphrases did not match".into());
    }
    Ok(first)
}

/// A raw file has no purpose byte. Treating it as an identity is what makes
/// `keygen --insecure-plaintext` usable for signing too, and an old raw
/// encryption seed still decrypts because that is a separate code path.
enum LoadedKey {
    Identity(Identity),
    EncryptionOnly(RecipientSecret),
}

fn load_key(path: &Path) -> Result<LoadedKey> {
    let bytes = read_bounded(path, MAX_KEY_FILE)?;
    match hide_keyring::inspect(&bytes) {
        KeyFormat::Raw => {
            let mut seed = Zeroizing::new([0u8; 32]);
            if bytes.len() != seed.len() {
                return Err(format!("{} is not a HIDE secret key", path.display()).into());
            }
            seed.copy_from_slice(&bytes);
            Ok(LoadedKey::Identity(Identity::from_seed(seed)))
        }
        KeyFormat::Protected => {
            let passphrase = prompt_passphrase("Passphrase: ")?;
            let (seed, purpose) = hide_keyring::unprotect_seed(&bytes, &passphrase)?;
            Ok(match purpose {
                KeyPurpose::Identity => LoadedKey::Identity(Identity::from_seed(seed)),
                KeyPurpose::Encryption => {
                    LoadedKey::EncryptionOnly(RecipientSecret::from_bytes(&seed[..])?)
                }
            })
        }
    }
}

fn load_secret(path: &Path) -> Result<RecipientSecret> {
    match load_key(path)? {
        LoadedKey::Identity(identity) => Ok(identity.recipient_secret()?),
        LoadedKey::EncryptionOnly(secret) => Ok(secret),
    }
}

/// Signing needs the master seed. A key file that predates signatures does not
/// carry one, and no amount of derivation can invent it.
fn load_signing_identity(path: &Path) -> Result<SigningIdentity> {
    match load_key(path)? {
        LoadedKey::Identity(identity) => Ok(SigningIdentity::from_bytes(&*identity.signing_seed())?),
        LoadedKey::EncryptionOnly(_) => Err(format!(
            "{} predates signatures and holds no signing key; create a new identity with `hide keygen`",
            path.display()
        )
        .into()),
    }
}

fn load_verifying_identity(path: &Path) -> Result<VerifyingIdentity> {
    let bytes = read_bounded(path, MAX_SIGNING_KEY_FILE)?;
    if bytes.len() != SIGNING_PUBLIC_LEN {
        return Err(format!(
            "{} is not a HIDE signing public key ({} bytes, expected {SIGNING_PUBLIC_LEN})",
            path.display(),
            bytes.len()
        )
        .into());
    }
    Ok(VerifyingIdentity::from_bytes(&bytes)?)
}

fn load_recipients(paths: &[PathBuf]) -> Result<Vec<RecipientPublic>> {
    if paths.is_empty() || paths.len() > 64 {
        return Err("recipient count must be between 1 and 64".into());
    }
    paths
        .iter()
        .map(|path| {
            let bytes = read_bounded(path, MAX_KEY_FILE)?;
            // Accept either the raw key or the pasteable armored form.
            let raw = if bytes.starts_with(b"hide-public-key:") {
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| "armored public key is not valid UTF-8")?;
                hide_keyring::decode_public(text)?
            } else {
                bytes.to_vec()
            };
            if raw.len() != PUBLIC_KEY_LEN {
                return Err(format!(
                    "{} is not a HIDE public key ({} bytes, expected {PUBLIC_KEY_LEN})",
                    path.display(),
                    raw.len()
                )
                .into());
            }
            Ok(RecipientPublic::from_bytes(&raw)?)
        })
        .collect()
}

fn keygen(
    secret_path: &Path,
    public_path: &Path,
    plaintext: bool,
    armor: bool,
    signing_public_path: Option<&Path>,
) -> Result<()> {
    if secret_path == public_path {
        return Err("secret and public paths must differ".into());
    }
    let signing_public_path = signing_public_path
        .map(PathBuf::from)
        .unwrap_or_else(|| append_extension(public_path, "sign"));
    if signing_public_path == secret_path || signing_public_path == public_path {
        return Err("signing public key path must differ from the other two".into());
    }

    let mut secret_file = new_output(secret_path)?;
    let mut public_file = new_output(public_path)?;
    let mut signing_file = new_output(&signing_public_path)?;

    // One master seed, so there is a single thing to back up and a single
    // passphrase. The two keys derive from it and cannot be computed from
    // each other.
    let identity = Identity::generate()?;
    let secret = identity.recipient_secret()?;
    let signing = SigningIdentity::from_bytes(&*identity.signing_seed())?;

    if plaintext {
        secret_file.write_all(identity.expose_seed_for_sealing())?;
    } else {
        let passphrase = prompt_new_passphrase()?;
        secret_file.write_all(&hide_keyring::protect_identity(
            identity.expose_seed_for_sealing(),
            &passphrase,
        )?)?;
    }
    let public = secret.public_key()?.to_bytes();
    public_file.write_all(&public)?;
    signing_file.write_all(&signing.verifying_key().to_bytes())?;

    commit_output(secret_file, secret_path)?;
    commit_output(signing_file, &signing_public_path)?;
    commit_output(public_file, public_path)?;

    if armor {
        print!("{}", hide_keyring::encode_public(&public));
    }
    if plaintext {
        eprintln!("Created keys. SECRET FILE IS UNENCRYPTED; use only disposable test data.");
    } else {
        eprintln!("Created keys. The secret is sealed with your passphrase.");
        eprintln!("If you forget it, nothing encrypted to this key can be recovered.");
    }
    eprintln!(
        "Signing public key written to {}. Share it so others can check your signatures.",
        signing_public_path.display()
    );
    Ok(())
}

/// Appends a suffix rather than replacing one, so `alice.hide-pub` becomes
/// `alice.hide-pub.sign` instead of losing the original extension.
fn append_extension(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

fn encrypt_file(
    input: &Path,
    recipients: &[PathBuf],
    output: &Path,
    sign_with: Option<&Path>,
    public_signature: bool,
) -> Result<()> {
    if public_signature && sign_with.is_none() {
        return Err("--public-signature needs --sign".into());
    }
    let recipients = load_recipients(recipients)?;
    let mut source = BufReader::with_capacity(IO_BUFFER, File::open(input)?);
    let staging = new_output(output)?;
    let filename = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("input filename must be valid UTF-8")?;
    let metadata = Metadata {
        filename: Some(filename.into()),
        media_type: None,
        signature: None,
    };
    let mut buffered = BufWriter::with_capacity(IO_BUFFER, staging);
    let written = match sign_with {
        None => hide_object::encrypt(&mut source, &mut buffered, &recipients, &metadata)?,
        Some(path) => {
            let identity = load_signing_identity(path)?;
            let placement = if public_signature {
                SignaturePlacement::Public
            } else {
                SignaturePlacement::Confidential
            };
            hide_object::encrypt_signed(
                &mut source,
                &mut buffered,
                &recipients,
                &metadata,
                &identity,
                placement,
            )?
        }
    };
    commit_output(buffered.into_inner()?, output)?;
    eprintln!(
        "Encrypted {written} bytes for {} recipient(s).",
        recipients.len()
    );
    if sign_with.is_some() {
        eprintln!(
            "Signed. The signature is {}.",
            if public_signature {
                "visible to anyone holding the file"
            } else {
                "readable only by the recipients"
            }
        );
    }
    Ok(())
}

fn open_file(input: &Path, secret_path: &Path, output: &Path) -> Result<()> {
    let secret = load_secret(secret_path)?;
    let mut source = BufReader::with_capacity(IO_BUFFER, File::open(input)?);
    let mut buffered = BufWriter::with_capacity(IO_BUFFER, new_output(output)?);
    let verified = hide_object::decrypt_to_staging(&mut source, &mut buffered, &secret)?;
    commit_output(buffered.into_inner()?, output)?;
    match verified.signer {
        None => {
            eprintln!("Decrypted file written; integrity verified. Sender is not authenticated.")
        }
        Some(signer) => {
            eprintln!("Decrypted file written; integrity verified.");
            eprintln!("Signed by key {}.", fingerprint(&signer));
            // A signature proves possession of a key, and nothing more: there is
            // no directory tying that key to a person.
            eprintln!("Check that key against one you already trust; HIDE does not.");
        }
    }
    Ok(())
}

/// A short, comparable form of a signing key. Not a security boundary on its
/// own: compare the full key when it matters.
fn fingerprint(identity: &VerifyingIdentity) -> String {
    let digest = hide_crypto::hash(&[&identity.to_bytes()]);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

const MESSAGE_HEADER: &str = "----- BEGIN HIDE MESSAGE -----";
const MESSAGE_FOOTER: &str = "----- END HIDE MESSAGE -----";

/// Signs the file's hash rather than its bytes, so signing a large file costs
/// one streaming pass and no buffering. The length is redundant against
/// SHA-256 and is included only to keep the message self-describing.
fn detached_message(digest: &[u8; 32], length: u64) -> Vec<u8> {
    [
        b"HIDE/0.5 detached-file".as_slice(),
        digest,
        &length.to_be_bytes(),
    ]
    .concat()
}

fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut file = BufReader::with_capacity(IO_BUFFER, File::open(path)?);
    let mut hasher = hide_crypto::Hasher::new();
    let mut buffer = vec![0; IO_BUFFER];
    let mut length = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    Ok((hasher.finish(), length))
}

fn signature_path(input: &Path, explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(PathBuf::from)
        .unwrap_or_else(|| append_extension(input, "hide-sig"))
}

fn sign_file(input: &Path, secret_path: &Path, output: Option<&Path>) -> Result<()> {
    let output = signature_path(input, output);
    let identity = load_signing_identity(secret_path)?;
    let mut staging = new_output(&output)?;
    let (digest, length) = hash_file(input)?;
    let signature = identity.sign(DETACHED_CONTEXT, &detached_message(&digest, length));

    // The verifying key travels with the signature so `verify` can report which
    // key signed even when the caller supplies the wrong one.
    staging.write_all(&identity.verifying_key().to_bytes())?;
    staging.write_all(&signature)?;
    commit_output(staging, &output)?;

    eprintln!("Signature written to {}.", output.display());
    eprintln!(
        "Anyone checking it needs your signing public key ({}).",
        fingerprint(&identity.verifying_key())
    );
    Ok(())
}

fn verify_file(input: &Path, signer_path: &Path, signature: Option<&Path>) -> Result<()> {
    let signature_file = signature_path(input, signature);
    let expected = load_verifying_identity(signer_path)?;
    let bytes = read_bounded(&signature_file, MAX_SIGNING_KEY_FILE)?;
    if bytes.len() != SIGNING_PUBLIC_LEN + hide_sign::SIGNATURE_LENGTH {
        return Err(format!("{} is not a HIDE signature", signature_file.display()).into());
    }
    let (embedded, signature) = bytes.split_at(SIGNING_PUBLIC_LEN);

    // Check the key first: a valid signature by the wrong signer is a failure,
    // and saying so is more useful than "signature did not verify".
    if embedded != expected.to_bytes() {
        return Err(format!(
            "signature is by key {}, not {}",
            fingerprint(&VerifyingIdentity::from_bytes(embedded)?),
            fingerprint(&expected)
        )
        .into());
    }

    let (digest, length) = hash_file(input)?;
    expected.verify(
        DETACHED_CONTEXT,
        &detached_message(&digest, length),
        signature,
    )?;
    eprintln!(
        "Signature is valid for {}, by key {}.",
        input.display(),
        fingerprint(&expected)
    );
    eprintln!("This proves possession of that key, not the identity of a person.");
    Ok(())
}

/// The Ed25519 half only. OpenSSH user authentication accepts `ssh-ed25519`,
/// `sk-*` and RSA; post-quantum algorithms exist there only in key exchange,
/// so the ML-DSA half of a HIDE identity cannot be offered to a server.
fn ssh_agent_for(secret_path: &Path, comment: Option<&str>) -> Result<agent::Agent> {
    let identity = load_signing_identity(secret_path)?;
    let comment = comment
        .map(str::to_string)
        .unwrap_or_else(|| format!("hide:{}", secret_path.display()));
    Ok(agent::Agent::new(&identity, comment))
}

fn print_ssh_key(secret_path: &Path, comment: Option<&str>) -> Result<()> {
    let agent = ssh_agent_for(secret_path, comment)?;
    println!(
        "{}",
        agent::authorized_key_line(agent.public(), agent.comment())
    );
    eprintln!(
        "This is the Ed25519 half of your identity ({}).",
        agent::fingerprint(agent.public())
    );
    eprintln!("SSH cannot carry the post-quantum half, so this key is not post-quantum.");
    Ok(())
}

fn run_agent(
    secret_path: &Path,
    endpoint: Option<&str>,
    no_confirm: bool,
    comment: Option<&str>,
) -> Result<()> {
    let agent = ssh_agent_for(secret_path, comment)?;
    let endpoint = endpoint
        .map(str::to_string)
        .unwrap_or_else(transport::default_endpoint);

    let mut ask;
    let mut always;
    let approver: &mut dyn agent::Approver = if no_confirm {
        transport::check_no_confirm_allowed()?;
        always = agent::ApproveEverything;
        &mut always
    } else {
        ask = agent::AskOnTerminal::require_terminal()
            .map_err(|error| format!("cannot start the agent: {error}"))?;
        &mut ask
    };

    eprintln!("hide agent: serving {}", agent::fingerprint(agent.public()));
    eprintln!("hide agent: {}", transport::advice(&endpoint));
    if no_confirm {
        eprintln!("hide agent: --no-confirm is set; anything reaching this endpoint can sign.");
    }
    transport::listen(&agent, &endpoint, approver)
}

fn seal_message(
    message: Option<&str>,
    recipients: &[PathBuf],
    output: Option<&Path>,
) -> Result<()> {
    let recipients = load_recipients(recipients)?;
    let plaintext = match message {
        Some(text) => Zeroizing::new(text.to_owned()),
        None => {
            let mut buffer = Zeroizing::new(String::new());
            io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };
    if plaintext.is_empty() {
        return Err("refusing to seal an empty message".into());
    }

    let mut container = Vec::new();
    let metadata = Metadata {
        filename: None,
        media_type: Some("text/plain".into()),
        signature: None,
    };
    hide_object::encrypt(
        &mut plaintext.as_bytes(),
        &mut container,
        &recipients,
        &metadata,
    )?;

    let armored = armor_message(&container);
    match output {
        Some(path) => {
            let mut staging = new_output(path)?;
            staging.write_all(armored.as_bytes())?;
            commit_output(staging, path)?;
            eprintln!("Sealed message written.");
        }
        None => print!("{armored}"),
    }
    Ok(())
}

fn unseal_message(input: Option<&Path>, secret_path: &Path) -> Result<()> {
    let text = read_armored_message(input)?;
    let container = dearmor_message(&text)?;
    let secret = load_secret(secret_path)?;

    // Buffered in memory so nothing is printed before the FINAL record authenticates.
    let mut plaintext = Zeroizing::new(Vec::new());
    let verified = hide_object::decrypt_to_staging(&mut &*container, &mut *plaintext, &secret)?;
    let plaintext = String::from_utf8(plaintext.to_vec())
        .map_err(|_| "message decrypted but is not valid UTF-8; use `open` instead")?;

    print!("{plaintext}");
    if !plaintext.ends_with('\n') {
        println!();
    }
    match verified.signer {
        None => eprintln!("Integrity verified. Sender is NOT authenticated."),
        Some(signer) => {
            eprintln!(
                "Integrity verified. Signed by key {}.",
                fingerprint(&signer)
            );
            eprintln!("Check that key against one you already trust; HIDE does not.");
        }
    }
    Ok(())
}

fn armor_message(container: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let body = STANDARD.encode(container);
    let mut out = String::with_capacity(body.len() + 128);
    out.push_str(MESSAGE_HEADER);
    out.push('\n');
    for chunk in body.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(MESSAGE_FOOTER);
    out.push('\n');
    out
}

fn dearmor_message(text: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let body: String = text
        .lines()
        .skip_while(|line| !line.contains(MESSAGE_HEADER))
        .skip(1)
        .take_while(|line| !line.contains(MESSAGE_FOOTER))
        .map(str::trim)
        .collect();
    if body.is_empty() {
        return Err("no HIDE message found in the input".into());
    }
    Ok(STANDARD
        .decode(&body)
        .map_err(|_| "message body is not valid base64")?)
}

fn describe(path: &Path) -> Result<()> {
    // Large enough for a detached signature, which is the biggest key-ish file.
    if let Ok(bytes) = read_bounded(path, MAX_SIGNING_KEY_FILE) {
        match hide_keyring::inspect(&bytes) {
            KeyFormat::Protected => {
                println!("{}: HIDE secret key, passphrase-protected", path.display());
                return Ok(());
            }
            KeyFormat::Raw if bytes.len() == 32 => {
                println!(
                    "{}: HIDE secret key, UNENCRYPTED (anyone with this file can decrypt)",
                    path.display()
                );
                return Ok(());
            }
            KeyFormat::Raw if bytes.len() == PUBLIC_KEY_LEN => {
                println!("{}: HIDE public key (shareable)", path.display());
                return Ok(());
            }
            KeyFormat::Raw if bytes.len() == SIGNING_PUBLIC_LEN => {
                println!("{}: HIDE signing public key (shareable)", path.display());
                if let Ok(identity) = VerifyingIdentity::from_bytes(&bytes) {
                    println!("  fingerprint: {}", fingerprint(&identity));
                }
                return Ok(());
            }
            KeyFormat::Raw if bytes.len() == SIGNING_PUBLIC_LEN + hide_sign::SIGNATURE_LENGTH => {
                println!("{}: HIDE detached signature", path.display());
                if let Ok(identity) = VerifyingIdentity::from_bytes(&bytes[..SIGNING_PUBLIC_LEN]) {
                    println!("  signed by key: {}", fingerprint(&identity));
                }
                println!("  verify it with `hide verify <file> --signer <key>`");
                return Ok(());
            }
            KeyFormat::Raw => {}
        }
    }

    let mut file = BufReader::new(File::open(path)?);
    let mut preamble = [0u8; 16];
    file.read_exact(&mut preamble)
        .map_err(|_| "file is too short to be a HIDE container")?;
    if &preamble[..8] != b"HIDE\r\n\x1a\n" {
        return Err("not a HIDE container or key file".into());
    }
    let size = std::fs::metadata(path)?.len();
    println!("{}: HIDE container", path.display());
    println!("  format version: {}.{}", preamble[8], preamble[9]);
    println!("  container size: {size} bytes");
    // Minor 2 is the signed form; the signer is only knowable after decryption.
    println!(
        "  signed: {}",
        if preamble[9] >= 2 {
            "yes; open it to learn who signed"
        } else {
            "no"
        }
    );
    println!("  recipients, filename and contents are encrypted; open it to learn more");
    Ok(())
}

fn share(public_path: &Path) -> Result<()> {
    let bytes = read_bounded(public_path, MAX_KEY_FILE)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err("not a HIDE public key".into());
    }
    RecipientPublic::from_bytes(&bytes)?;
    print!("{}", hide_keyring::encode_public(&bytes));
    eprintln!("Share this over a channel where the recipient can confirm it came from you.");
    Ok(())
}

fn change_passphrase(secret_path: &Path) -> Result<()> {
    let bytes = read_bounded(secret_path, MAX_KEY_FILE)?;
    let secret = match hide_keyring::inspect(&bytes) {
        KeyFormat::Raw => {
            eprintln!("This key is currently unencrypted; setting a passphrase.");
            RecipientSecret::from_bytes(&bytes)?
        }
        KeyFormat::Protected => {
            let current = prompt_passphrase("Current passphrase: ")?;
            hide_keyring::unprotect(&bytes, &current)?
        }
    };
    let passphrase = prompt_new_passphrase()?;
    let sealed = hide_keyring::protect(&secret, &passphrase)?;

    // Write beside the original and replace it, so a crash cannot lose the key.
    let parent = secret_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staging = tempfile::Builder::new()
        .prefix(".hide-key-")
        .tempfile_in(parent)?;
    staging.write_all(&sealed)?;
    staging.flush()?;
    staging.as_file().sync_all()?;
    staging.persist(secret_path)?;
    sync_directory(parent)?;
    eprintln!("Passphrase changed.");
    Ok(())
}

/// Makes a completed rename durable. A renamed entry lives in the directory,
/// and on Unix the directory has to be fsynced for the rename to survive a
/// power loss. Windows has no equivalent and refuses to open a directory this
/// way, so there it is a no-op.
fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity logs and epoch chains
// ---------------------------------------------------------------------------

/// Identity logs and epoch chains are public, so a generous ceiling is fine;
/// the point is only to refuse a file that could exhaust memory.
const MAX_LOG_FILE: usize = 16 * 1024 * 1024;

fn read_public_file(path: &Path) -> Result<Vec<u8>> {
    Ok(read_bounded(path, MAX_LOG_FILE)?.to_vec())
}

/// Writes a log or chain, replacing it if present. Unlike a container, an
/// append-only log is expected to grow in place, so refusing to overwrite would
/// make it impossible to append at all. Staged and renamed so a crash mid-write
/// cannot leave a truncated history.
fn write_public_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staging = tempfile::Builder::new()
        .prefix(".hide-log-")
        .tempfile_in(parent)?;
    staging.write_all(bytes)?;
    staging.flush()?;
    staging.as_file().sync_all()?;
    // Overwrite is intended: this replaces the previous state of a growing log.
    staging.persist(path)?;
    sync_directory(parent)?;
    Ok(())
}

fn load_identity_log(log: &Path, recovery: &Path) -> Result<(IdentityLog, VerifyingIdentity)> {
    let recovery_key = load_verifying_identity(recovery)?;
    let entries = hide_identity::decode(&read_public_file(log)?)?;
    // Verify before trusting, exactly as a stranger would.
    IdentityLog::verify(&entries, &recovery_key)?;
    Ok((
        IdentityLog::from_entries(entries, recovery_key.clone())?,
        recovery_key,
    ))
}

fn identity_create(secret: &Path, recovery: &Path, label: &str, output: &Path) -> Result<()> {
    let founder = load_signing_identity(secret)?;
    let recovery_key = load_verifying_identity(recovery)?;
    let log = IdentityLog::create(&founder, label, &recovery_key)?;
    write_public_file(output, &hide_identity::encode(log.entries())?)?;
    eprintln!(
        "Identity created with one device. Head {}.",
        short_hex(&log.head())
    );
    Ok(())
}

fn identity_enrol(
    log_path: &Path,
    secret: &Path,
    device: &Path,
    label: &str,
    recovery: &Path,
) -> Result<()> {
    let (mut log, _) = load_identity_log(log_path, recovery)?;
    let author = load_signing_identity(secret)?;
    let new_device = load_verifying_identity(device)?;
    let at = log.enrol(&author, &new_device, label)?;
    write_public_file(log_path, &hide_identity::encode(log.entries())?)?;
    eprintln!("Enrolled at entry {at}. Head {}.", short_hex(&log.head()));
    Ok(())
}

fn identity_revoke(log_path: &Path, secret: &Path, device: &Path, recovery: &Path) -> Result<()> {
    let (mut log, _) = load_identity_log(log_path, recovery)?;
    let author = load_signing_identity(secret)?;
    let target = hide_identity::device_id(&load_verifying_identity(device)?);
    let at = log.revoke(&author, target)?;
    write_public_file(log_path, &hide_identity::encode(log.entries())?)?;
    eprintln!("Revoked at entry {at}. Containers that device already holds stay readable to it.");
    Ok(())
}

fn identity_show(log_path: &Path, recovery: &Path) -> Result<()> {
    let (log, _) = load_identity_log(log_path, recovery)?;
    let membership = log.membership();
    println!("head    {}", short_hex(&log.head()));
    println!("entries {}", log.entries().len());
    println!("devices {}", membership.len());
    for device in membership.devices() {
        println!(
            "  {}  {}  enrolled at {}",
            short_hex(&device.id),
            device.label,
            device.enrolled_at
        );
    }
    Ok(())
}

fn epoch_init(output: &Path) -> Result<()> {
    let chain = EpochChain::new()?;
    write_public_file(output, &hide_epoch::encode_records(chain.records())?)?;
    eprintln!(
        "Epoch 0 created. The secret exists only in this process and was not written: \
         this command publishes the history, and a persistent store is not implemented yet."
    );
    Ok(())
}

fn epoch_show(chain: &Path) -> Result<()> {
    let records = hide_epoch::decode_records(&read_public_file(chain)?)?;
    EpochChain::verify(&records)?;
    println!("epochs {}", records.len());
    for record in &records {
        println!("  {}  link {}", record.number, short_hex(&record.link));
    }
    Ok(())
}

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
