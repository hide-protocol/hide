//! Device enrollment, revocation and recovery for one identity.
//!
//! An identity is not a key. It is an ordered, hash-linked log of events, each
//! signed by a key that the log itself already authorised. Replaying the log
//! from its root yields the set of devices trusted *now*, and — because every
//! entry is bound to its predecessor — anyone can check that the history they
//! were shown is the history everyone else was shown.
//!
//! # The rule that makes revocation mean something
//!
//! Authority is evaluated **at the point in the log where the entry appears**,
//! never against the final state. A device revoked at entry *n* cannot sign
//! entry *n+1*, so it cannot re-enrol itself, revoke the device that removed
//! it, or rewrite anything after its removal. It also means entries it signed
//! *before* revocation stay valid: revocation is not retroactive, because
//! pretending otherwise would invalidate every message the device ever sent.
//!
//! # What this does not do
//!
//! Nothing here proves the log belongs to a particular person; that is what a
//! transparency log is for, and it lives in `hide-transparency`. Two divergent
//! copies of a log are both internally valid — detecting that split needs a
//! witness, not a signature. And a compromised device is trusted until someone
//! notices and revokes it; there is no automatic detection.

use hide_sign::{SIGNATURE_LENGTH, SigningIdentity, VERIFYING_KEY_LENGTH, VerifyingIdentity};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// Domain separation for the signature over an entry. A signature made here can
/// never be replayed as a file signature or a challenge response.
const ENTRY_CONTEXT: &[u8] = b"HIDE/0.6 identity entry";

/// A log longer than this is refused before anything is allocated for it.
const MAX_ENTRIES: usize = 100_000;
/// Device labels are shown to humans; an unbounded one is a denial-of-service.
const MAX_LABEL_BYTES: usize = 256;

/// Position in the log. The root is zero.
pub type Sequence = u64;

/// A device's stable name: the hash of its verifying key, so it cannot be
/// chosen and cannot collide with another device's.
pub type DeviceId = [u8; 32];

pub fn device_id(key: &VerifyingIdentity) -> DeviceId {
    let mut hasher = Sha256::new();
    hasher.update(b"HIDE/0.6 device id");
    hasher.update(key.to_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("the log is empty")]
    Empty,
    #[error("entry {0} is not signed by a device this log trusts at that point")]
    Unauthorised(Sequence),
    #[error("entry {0} has an invalid signature")]
    BadSignature(Sequence),
    #[error("entry {expected} was expected but the log contains {found}")]
    OutOfOrder { expected: Sequence, found: Sequence },
    #[error("entry {0} does not link to its predecessor")]
    BrokenLink(Sequence),
    #[error("the first entry must create the identity, not {0}")]
    BadRoot(&'static str),
    #[error("device is already enrolled at entry {0}")]
    AlreadyEnrolled(Sequence),
    #[error("entry {0} revokes a device that is not enrolled")]
    NotEnrolled(Sequence),
    #[error("entry {0} would revoke the last remaining device")]
    WouldOrphan(Sequence),
    #[error("the log is malformed")]
    Malformed,
    #[error("the log claims {0} entries, which exceeds the limit")]
    TooManyEntries(usize),
    #[error("a device label may not exceed {MAX_LABEL_BYTES} bytes")]
    LabelTooLong,
    #[error("signing failed: {0}")]
    Sign(String),
}

/// What an entry does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The first entry: establishes the identity and its founding device.
    Create { device: Vec<u8>, label: String },
    /// Adds a device, signed by one already trusted.
    Enrol { device: Vec<u8>, label: String },
    /// Removes a device. Takes effect for every later entry.
    Revoke { device: DeviceId },
    /// Replaces the whole device set, signed by the recovery key. This is how a
    /// user who lost every device gets back in.
    Recover { device: Vec<u8>, label: String },
}

impl Event {
    fn tag(&self) -> u8 {
        match self {
            Self::Create { .. } => 1,
            Self::Enrol { .. } => 2,
            Self::Revoke { .. } => 3,
            Self::Recover { .. } => 4,
        }
    }

    fn label(&self) -> Option<&str> {
        match self {
            Self::Create { label, .. }
            | Self::Enrol { label, .. }
            | Self::Recover { label, .. } => Some(label),
            Self::Revoke { .. } => None,
        }
    }
}

/// One signed, linked record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub sequence: Sequence,
    pub event: Event,
    /// Which device signed this entry.
    pub signer: DeviceId,
    /// Binds this entry to the entire history before it.
    pub link: [u8; 32],
    pub signature: Vec<u8>,
}

impl Entry {
    /// The exact bytes this entry's signature covers, laid out as in
    /// `spec/hide-0.1.md` §8. Public so a second implementation can be checked
    /// against this one instead of against prose.
    pub fn signed_bytes(&self, previous: &[u8; 32]) -> Vec<u8> {
        signed_bytes(previous, self.sequence, &self.event, &self.signer)
    }
}

/// The bytes that are signed and linked. Every field is length-prefixed, so no
/// combination of a long label and a short key can be re-parsed as another.
fn signed_bytes(
    previous: &[u8; 32],
    sequence: Sequence,
    event: &Event,
    signer: &DeviceId,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(previous);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.push(event.tag());
    out.extend_from_slice(signer);

    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    match event {
        Event::Create { device, label }
        | Event::Enrol { device, label }
        | Event::Recover { device, label } => {
            field(device);
            field(label.as_bytes());
        }
        Event::Revoke { device } => field(device),
    }
    out
}

fn link_for(signed: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"HIDE/0.6 identity link");
    hasher.update((signed.len() as u64).to_be_bytes());
    hasher.update(signed);
    hasher.update((signature.len() as u64).to_be_bytes());
    hasher.update(signature);
    hasher.finalize().into()
}

/// A device trusted at some point in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    pub key: VerifyingIdentity,
    pub label: String,
    pub enrolled_at: Sequence,
}

/// The device set produced by replaying a log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Membership {
    devices: BTreeMap<DeviceId, Device>,
    revoked: BTreeMap<DeviceId, Sequence>,
}

impl Membership {
    pub fn contains(&self, id: &DeviceId) -> bool {
        self.devices.contains_key(id)
    }

    pub fn get(&self, id: &DeviceId) -> Option<&Device> {
        self.devices.get(id)
    }

    /// Every currently trusted device, in a stable order.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// When a device was revoked, if it was. Kept so a verifier can tell
    /// "never existed" from "existed and was removed" — the second is what a
    /// user needs to see after losing a phone.
    pub fn revoked_at(&self, id: &DeviceId) -> Option<Sequence> {
        self.revoked.get(id).copied()
    }
}

/// The identity itself: an append-only log plus the membership it implies.
pub struct IdentityLog {
    entries: Vec<Entry>,
    /// The key permitted to sign `Recover`. Held offline by the user.
    recovery: VerifyingIdentity,
}

impl IdentityLog {
    /// Starts an identity. The founding device signs its own creation, which is
    /// the one place a signature is not checked against prior membership.
    pub fn create(
        founder: &SigningIdentity,
        label: &str,
        recovery: &VerifyingIdentity,
    ) -> Result<Self, IdentityError> {
        check_label(label)?;
        let key = founder.verifying_key();
        let event = Event::Create {
            device: key.to_bytes().to_vec(),
            label: label.to_owned(),
        };
        let signer = device_id(&key);
        let signed = signed_bytes(&[0u8; 32], 0, &event, &signer);
        let signature = founder.sign(ENTRY_CONTEXT, &signed).to_vec();

        Ok(Self {
            entries: vec![Entry {
                sequence: 0,
                link: link_for(&signed, &signature),
                event,
                signer,
                signature,
            }],
            recovery: recovery.clone(),
        })
    }

    fn append(
        &mut self,
        author: &SigningIdentity,
        event: Event,
    ) -> Result<Sequence, IdentityError> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(IdentityError::TooManyEntries(self.entries.len()));
        }
        if let Some(label) = event.label() {
            check_label(label)?;
        }

        let sequence = self.entries.len() as Sequence;
        let previous = self.entries.last().map_or([0u8; 32], |entry| entry.link);
        let signer = device_id(&author.verifying_key());
        let signed = signed_bytes(&previous, sequence, &event, &signer);
        let signature = author.sign(ENTRY_CONTEXT, &signed).to_vec();

        let candidate = Entry {
            sequence,
            link: link_for(&signed, &signature),
            event,
            signer,
            signature,
        };

        // Validate exactly as a stranger would, so an invalid entry can never
        // be created locally and only discovered by a remote verifier.
        let mut membership = self.membership();
        apply(&mut membership, &candidate, &self.recovery, previous)?;

        self.entries.push(candidate);
        Ok(sequence)
    }

    /// Adds a device. The author must be trusted right now.
    pub fn enrol(
        &mut self,
        author: &SigningIdentity,
        device: &VerifyingIdentity,
        label: &str,
    ) -> Result<Sequence, IdentityError> {
        self.append(
            author,
            Event::Enrol {
                device: device.to_bytes().to_vec(),
                label: label.to_owned(),
            },
        )
    }

    /// Removes a device. A device may revoke itself — that is what "log out this
    /// phone" does — but may not revoke the last one.
    pub fn revoke(
        &mut self,
        author: &SigningIdentity,
        device: DeviceId,
    ) -> Result<Sequence, IdentityError> {
        self.append(author, Event::Revoke { device })
    }

    /// Replaces every device with one new device. Only the recovery key may
    /// sign this, which is why that key is kept offline.
    pub fn recover(
        &mut self,
        recovery_key: &SigningIdentity,
        device: &VerifyingIdentity,
        label: &str,
    ) -> Result<Sequence, IdentityError> {
        self.append(
            recovery_key,
            Event::Recover {
                device: device.to_bytes().to_vec(),
                label: label.to_owned(),
            },
        )
    }

    /// Rebuilds a log from entries received elsewhere. Verified first, so an
    /// invalid history can never become an appendable one.
    pub fn from_entries(
        entries: Vec<Entry>,
        recovery: VerifyingIdentity,
    ) -> Result<Self, IdentityError> {
        replay(&entries, &recovery)?;
        Ok(Self { entries, recovery })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The head link, which identifies this exact history in one 32-byte value.
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map_or([0u8; 32], |entry| entry.link)
    }

    /// The devices trusted now.
    pub fn membership(&self) -> Membership {
        // The log was validated on the way in, so replay cannot fail here.
        replay(&self.entries, &self.recovery).unwrap_or_default()
    }

    /// Replays a log received from elsewhere, checking every signature, link
    /// and authority decision. This is the function a verifier actually runs.
    pub fn verify(
        entries: &[Entry],
        recovery: &VerifyingIdentity,
    ) -> Result<Membership, IdentityError> {
        replay(entries, recovery)
    }
}

fn check_label(label: &str) -> Result<(), IdentityError> {
    if label.len() > MAX_LABEL_BYTES {
        return Err(IdentityError::LabelTooLong);
    }
    Ok(())
}

/// Applies one entry to a membership, enforcing authority *as of that entry*.
fn apply(
    membership: &mut Membership,
    entry: &Entry,
    recovery: &VerifyingIdentity,
    previous: [u8; 32],
) -> Result<(), IdentityError> {
    if let Some(label) = entry.event.label()
        && label.len() > MAX_LABEL_BYTES
    {
        return Err(IdentityError::LabelTooLong);
    }

    let signed = signed_bytes(&previous, entry.sequence, &entry.event, &entry.signer);
    if link_for(&signed, &entry.signature) != entry.link {
        return Err(IdentityError::BrokenLink(entry.sequence));
    }
    let signature: [u8; SIGNATURE_LENGTH] = entry
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::BadSignature(entry.sequence))?;

    // Which key is allowed to have signed this, given the state so far.
    let author: VerifyingIdentity = match &entry.event {
        Event::Create { device, .. } => {
            if entry.sequence != 0 {
                return Err(IdentityError::BadRoot("a later Create"));
            }
            let key = parse_key(device, entry.sequence)?;
            if device_id(&key) != entry.signer {
                return Err(IdentityError::Unauthorised(entry.sequence));
            }
            key
        }
        Event::Recover { .. } => {
            // Only the recovery key, and it is not a device.
            if device_id(recovery) != entry.signer {
                return Err(IdentityError::Unauthorised(entry.sequence));
            }
            recovery.clone()
        }
        Event::Enrol { .. } | Event::Revoke { .. } => membership
            .devices
            .get(&entry.signer)
            .map(|device| device.key.clone())
            .ok_or(IdentityError::Unauthorised(entry.sequence))?,
    };

    author
        .verify(ENTRY_CONTEXT, &signed, &signature)
        .map_err(|_| IdentityError::BadSignature(entry.sequence))?;

    match &entry.event {
        Event::Create { device, label } => {
            let key = parse_key(device, entry.sequence)?;
            let id = device_id(&key);
            membership.devices.insert(
                id,
                Device {
                    id,
                    key,
                    label: label.clone(),
                    enrolled_at: entry.sequence,
                },
            );
        }
        Event::Enrol { device, label } => {
            let key = parse_key(device, entry.sequence)?;
            let id = device_id(&key);
            if membership.devices.contains_key(&id) {
                return Err(IdentityError::AlreadyEnrolled(entry.sequence));
            }
            membership.revoked.remove(&id);
            membership.devices.insert(
                id,
                Device {
                    id,
                    key,
                    label: label.clone(),
                    enrolled_at: entry.sequence,
                },
            );
        }
        Event::Revoke { device } => {
            if !membership.devices.contains_key(device) {
                return Err(IdentityError::NotEnrolled(entry.sequence));
            }
            // An identity with no devices could only be rescued by recovery;
            // refuse to walk into that by accident.
            if membership.devices.len() == 1 {
                return Err(IdentityError::WouldOrphan(entry.sequence));
            }
            membership.devices.remove(device);
            membership.revoked.insert(*device, entry.sequence);
        }
        Event::Recover { device, label } => {
            let key = parse_key(device, entry.sequence)?;
            let id = device_id(&key);
            for old in membership.devices.keys() {
                membership.revoked.insert(*old, entry.sequence);
            }
            membership.devices.clear();
            membership.revoked.remove(&id);
            membership.devices.insert(
                id,
                Device {
                    id,
                    key,
                    label: label.clone(),
                    enrolled_at: entry.sequence,
                },
            );
        }
    }
    Ok(())
}

fn parse_key(bytes: &[u8], sequence: Sequence) -> Result<VerifyingIdentity, IdentityError> {
    if bytes.len() != VERIFYING_KEY_LENGTH {
        return Err(IdentityError::Malformed);
    }
    VerifyingIdentity::from_bytes(bytes).map_err(|_| IdentityError::BadSignature(sequence))
}

fn replay(entries: &[Entry], recovery: &VerifyingIdentity) -> Result<Membership, IdentityError> {
    if entries.is_empty() {
        return Err(IdentityError::Empty);
    }
    if entries.len() > MAX_ENTRIES {
        return Err(IdentityError::TooManyEntries(entries.len()));
    }
    if !matches!(entries[0].event, Event::Create { .. }) {
        return Err(IdentityError::BadRoot("another event"));
    }

    let mut membership = Membership::default();
    let mut previous = [0u8; 32];
    for (index, entry) in entries.iter().enumerate() {
        let expected = index as Sequence;
        if entry.sequence != expected {
            return Err(IdentityError::OutOfOrder {
                expected,
                found: entry.sequence,
            });
        }
        apply(&mut membership, entry, recovery, previous)?;
        previous = entry.link;
    }
    Ok(membership)
}

/// Encodes a log for transport. Only public material is ever encodable.
pub fn encode(entries: &[Entry]) -> Result<Vec<u8>, IdentityError> {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder
        .array(entries.len() as u64)
        .map_err(|_| IdentityError::Malformed)?;
    for entry in entries {
        encoder
            .array(6)
            .and_then(|e| e.u64(entry.sequence))
            .and_then(|e| e.u8(entry.event.tag()))
            .map_err(|_| IdentityError::Malformed)?;
        match &entry.event {
            Event::Create { device, label }
            | Event::Enrol { device, label }
            | Event::Recover { device, label } => {
                encoder
                    .bytes(device)
                    .and_then(|e| e.str(label))
                    .map_err(|_| IdentityError::Malformed)?;
            }
            Event::Revoke { device } => {
                encoder
                    .bytes(device)
                    .and_then(|e| e.str(""))
                    .map_err(|_| IdentityError::Malformed)?;
            }
        }
        encoder
            .bytes(&entry.signer)
            .and_then(|e| e.bytes(&entry.link))
            .and_then(|e| e.bytes(&entry.signature))
            .map_err(|_| IdentityError::Malformed)?;
    }
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Entry>, IdentityError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder
        .array()
        .map_err(|_| IdentityError::Malformed)?
        .ok_or(IdentityError::Malformed)?;
    if count > MAX_ENTRIES as u64 {
        return Err(IdentityError::TooManyEntries(count as usize));
    }

    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let fields = decoder
            .array()
            .map_err(|_| IdentityError::Malformed)?
            .ok_or(IdentityError::Malformed)?;
        if fields != 6 {
            return Err(IdentityError::Malformed);
        }
        let sequence = decoder.u64().map_err(|_| IdentityError::Malformed)?;
        let tag = decoder.u8().map_err(|_| IdentityError::Malformed)?;
        let payload = decoder
            .bytes()
            .map_err(|_| IdentityError::Malformed)?
            .to_vec();
        let label = decoder
            .str()
            .map_err(|_| IdentityError::Malformed)?
            .to_owned();
        if label.len() > MAX_LABEL_BYTES {
            return Err(IdentityError::LabelTooLong);
        }

        let event = match tag {
            1 => Event::Create {
                device: payload,
                label,
            },
            2 => Event::Enrol {
                device: payload,
                label,
            },
            3 => Event::Revoke {
                device: payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityError::Malformed)?,
            },
            4 => Event::Recover {
                device: payload,
                label,
            },
            _ => return Err(IdentityError::Malformed),
        };

        let signer: DeviceId = decoder
            .bytes()
            .map_err(|_| IdentityError::Malformed)?
            .try_into()
            .map_err(|_| IdentityError::Malformed)?;
        let link: [u8; 32] = decoder
            .bytes()
            .map_err(|_| IdentityError::Malformed)?
            .try_into()
            .map_err(|_| IdentityError::Malformed)?;
        let signature = decoder
            .bytes()
            .map_err(|_| IdentityError::Malformed)?
            .to_vec();
        if signature.len() != SIGNATURE_LENGTH {
            return Err(IdentityError::Malformed);
        }

        entries.push(Entry {
            sequence,
            event,
            signer,
            link,
            signature,
        });
    }
    if decoder.position() != bytes.len() {
        return Err(IdentityError::Malformed);
    }
    // One history, one encoding. A transparency log hashes these exact bytes,
    // so two encodings of the same entries would be two different leaves. This
    // also rejects a non-empty label smuggled into a Revoke, which the typed
    // event has no field for and would otherwise silently drop.
    if encode(&entries)? != bytes {
        return Err(IdentityError::Malformed);
    }
    Ok(entries)
}
