use std::{
    error::Error,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_object::Metadata;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const IO_BUFFER: usize = 1 << 20;

#[derive(Parser)]
#[command(
    name = "hide",
    version,
    about = "HIDE Interop Zero: experimental file encryption, not for sensitive data"
)]
struct Arguments {
    #[arg(
        long,
        global = true,
        help = "Acknowledge that this protocol and implementation are unaudited"
    )]
    experimental: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Create raw, UNENCRYPTED test key files; not a HIDE identity or secure vault"
    )]
    TestKeygen {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    #[command(about = "Encrypt a file for one or more authenticated-out-of-band test public keys")]
    Encrypt {
        input: PathBuf,
        #[arg(
            long,
            required = true,
            num_args = 1,
            help = "Test public key file; repeat for additional recipients"
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
    eprintln!(
        "WARNING: experimental, unaudited HIDE/0.1. No identity verification or sender authentication."
    );
    match arguments.command {
        Command::TestKeygen { secret, public } => test_keygen(&secret, &public),
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
    }
}

fn read_exact_file<const LENGTH: usize>(path: &Path) -> Result<Zeroizing<[u8; LENGTH]>> {
    let mut file = File::open(path)?;
    let mut bytes = Zeroizing::new([0; LENGTH]);
    file.read_exact(bytes.as_mut_slice())?;
    let mut extra = [0; 1];
    if file.read(&mut extra)? != 0 {
        return Err("invalid test key file length".into());
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

fn test_keygen(secret_path: &Path, public_path: &Path) -> Result<()> {
    if secret_path == public_path {
        return Err("secret and public paths must differ".into());
    }
    let mut secret_file = new_output(secret_path)?;
    let mut public_file = new_output(public_path)?;
    let secret = RecipientSecret::generate()?;
    secret_file.write_all(&secret.export_test_secret())?;
    public_file.write_all(&secret.public_key()?.to_bytes())?;
    commit_output(secret_file, secret_path)?;
    commit_output(public_file, public_path)?;
    eprintln!("Created test keys. SECRET FILE IS UNENCRYPTED; use only disposable test data.");
    Ok(())
}

fn encrypt_file(input: &Path, recipients: &[PathBuf], output: &Path) -> Result<()> {
    if recipients.is_empty() || recipients.len() > 64 {
        return Err("recipient count must be between 1 and 64".into());
    }
    let recipients = recipients
        .iter()
        .map(|path| {
            let bytes = read_exact_file::<1216>(path)?;
            Ok(RecipientPublic::from_bytes(bytes.as_ref())?)
        })
        .collect::<Result<Vec<_>>>()?;
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
    hide_object::encrypt(&mut source, &mut buffered, &recipients, &metadata)?;
    commit_output(buffered.into_inner()?, output)?;
    eprintln!("Encrypted file written.");
    Ok(())
}

fn open_file(input: &Path, secret_path: &Path, output: &Path) -> Result<()> {
    let bytes = read_exact_file::<32>(secret_path)?;
    let secret = RecipientSecret::from_bytes(bytes.as_ref())?;
    let mut source = BufReader::with_capacity(IO_BUFFER, File::open(input)?);
    let mut buffered = BufWriter::with_capacity(IO_BUFFER, new_output(output)?);
    hide_object::decrypt_to_staging(&mut source, &mut buffered, &secret)?;
    commit_output(buffered.into_inner()?, output)?;
    eprintln!("Decrypted file written; integrity verified. Sender is not authenticated.");
    Ok(())
}
