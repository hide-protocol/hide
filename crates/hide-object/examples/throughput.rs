use std::{error::Error, hint::black_box, io, time::Instant};

use hide_crypto::RecipientSecret;
use hide_object::{Metadata, decrypt_to_staging, encrypt};

/// Discards output so the measurement excludes filesystem cost.
struct Sink(u64);

impl io::Write for Sink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0 += buffer.len() as u64;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn rate(bytes: usize, seconds: f64) -> String {
    format!("{:.0} MiB/s", bytes as f64 / (1024.0 * 1024.0) / seconds)
}

fn main() -> Result<(), Box<dyn Error>> {
    let megabytes: usize = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let plaintext = vec![0xa7; megabytes * 1024 * 1024];
    let secret = RecipientSecret::generate()?;
    let public = secret.public_key()?;

    let start = Instant::now();
    let mut container = Vec::with_capacity(plaintext.len() + (1 << 20));
    encrypt(
        &mut plaintext.as_slice(),
        &mut container,
        &[public],
        &Metadata::default(),
    )?;
    let sealed = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let mut sink = Sink(0);
    let verified = decrypt_to_staging(&mut container.as_slice(), &mut sink, &secret)?;
    let opened = start.elapsed().as_secs_f64();
    assert_eq!(verified.plaintext_len, plaintext.len() as u64);
    black_box(sink.0);

    println!(
        "in-memory {megabytes} MiB: encrypt {} ({sealed:.2} s), decrypt {} ({opened:.2} s)",
        rate(plaintext.len(), sealed),
        rate(plaintext.len(), opened)
    );
    println!(
        "overhead {} bytes ({:.4}%)",
        container.len() - plaintext.len(),
        (container.len() - plaintext.len()) as f64 * 100.0 / plaintext.len() as f64
    );
    Ok(())
}
