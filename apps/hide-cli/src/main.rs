use std::{
    error::Error,
    fs::File,
    io::{self, BufReader, BufWriter, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_keyring::{KeyFormat, MIN_PASSPHRASE_LEN};
use hide_object::Metadata;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const IO_BUFFER: usize = 1 << 20;
const PUBLIC_KEY_LEN: usize = 1216;
const MAX_KEY_FILE: usize = 4096;

#[derive(Parser)]
#[command(
    name = "hide",
    version,
    about = "HIDE Interop Zero: experimental file and message encryption, not for sensitive data"
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
        return Err("pass --experimental; HIDE/0.1 is unaudited and not for sensitive data".into());
    }
    if !arguments.quiet {
        eprintln!(
            "WARNING: experimental, unaudited HIDE/0.1. No identity verification or sender authentication."
        );
    }
    match arguments.command {
        Command::Keygen {
            secret,
            public,
            insecure_plaintext,
            armor,
        } => keygen(&secret, &public, insecure_plaintext, armor),
        Command::TestKeygen { secret, public } => {
            eprintln!("note: `test-keygen` is deprecated; use `keygen --insecure-plaintext`");
            keygen(&secret, &public, true, false)
        }
        Command::Encrypt {
            input,
            recipient,
            output,
        } => encrypt_file(&input, &recipient, &output),
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

fn load_secret(path: &Path) -> Result<RecipientSecret> {
    let bytes = read_bounded(path, MAX_KEY_FILE)?;
    match hide_keyring::inspect(&bytes) {
        KeyFormat::Raw => Ok(RecipientSecret::from_bytes(&bytes)?),
        KeyFormat::Protected => {
            let passphrase = prompt_passphrase("Passphrase: ")?;
            Ok(hide_keyring::unprotect(&bytes, &passphrase)?)
        }
    }
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

fn keygen(secret_path: &Path, public_path: &Path, plaintext: bool, armor: bool) -> Result<()> {
    if secret_path == public_path {
        return Err("secret and public paths must differ".into());
    }
    let mut secret_file = new_output(secret_path)?;
    let mut public_file = new_output(public_path)?;
    let secret = RecipientSecret::generate()?;

    if plaintext {
        secret_file.write_all(secret.expose_seed_for_sealing())?;
    } else {
        let passphrase = prompt_new_passphrase()?;
        secret_file.write_all(&hide_keyring::protect(&secret, &passphrase)?)?;
    }
    let public = secret.public_key()?.to_bytes();
    public_file.write_all(&public)?;

    commit_output(secret_file, secret_path)?;
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
    Ok(())
}

fn encrypt_file(input: &Path, recipients: &[PathBuf], output: &Path) -> Result<()> {
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
    };
    let mut buffered = BufWriter::with_capacity(IO_BUFFER, staging);
    let written = hide_object::encrypt(&mut source, &mut buffered, &recipients, &metadata)?;
    commit_output(buffered.into_inner()?, output)?;
    eprintln!(
        "Encrypted {written} bytes for {} recipient(s).",
        recipients.len()
    );
    Ok(())
}

fn open_file(input: &Path, secret_path: &Path, output: &Path) -> Result<()> {
    let secret = load_secret(secret_path)?;
    let mut source = BufReader::with_capacity(IO_BUFFER, File::open(input)?);
    let mut buffered = BufWriter::with_capacity(IO_BUFFER, new_output(output)?);
    hide_object::decrypt_to_staging(&mut source, &mut buffered, &secret)?;
    commit_output(buffered.into_inner()?, output)?;
    eprintln!("Decrypted file written; integrity verified. Sender is not authenticated.");
    Ok(())
}

const MESSAGE_HEADER: &str = "----- BEGIN HIDE MESSAGE -----";
const MESSAGE_FOOTER: &str = "----- END HIDE MESSAGE -----";

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
    let text = match input {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };
    let container = dearmor_message(&text)?;
    let secret = load_secret(secret_path)?;

    // Buffered in memory so nothing is printed before the FINAL record authenticates.
    let mut plaintext = Zeroizing::new(Vec::new());
    hide_object::decrypt_to_staging(&mut &*container, &mut *plaintext, &secret)?;
    let plaintext = String::from_utf8(plaintext.to_vec())
        .map_err(|_| "message decrypted but is not valid UTF-8; use `open` instead")?;

    print!("{plaintext}");
    if !plaintext.ends_with('\n') {
        println!();
    }
    eprintln!("Integrity verified. Sender is NOT authenticated.");
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
    if let Ok(bytes) = read_bounded(path, MAX_KEY_FILE) {
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
    eprintln!("Passphrase changed.");
    Ok(())
}
