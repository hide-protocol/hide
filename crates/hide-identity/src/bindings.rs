//! Signed statements that tie things to an identity without touching the
//! frozen identity-log layout (spec §16.1 and §16.4).
//!
//! Both are fixed-length byte strings, so each value has exactly one encoding
//! and a decoder needs no canonicality check beyond the length.

use hide_epoch::EpochRecord;
use hide_sign::{SIGNATURE_LENGTH, SigningIdentity, VERIFYING_KEY_LENGTH, VerifyingIdentity};

use crate::{DeviceId, Entry, Event, IdentityError, IdentityLog, Membership, device_id};

pub const RECOVERY_BINDING_CONTEXT: &[u8] = b"HIDE/1.0 recovery binding";
pub const EPOCH_BINDING_CONTEXT: &[u8] = b"HIDE/1.0 epoch binding";

/// `root(32) || recovery_key(1984) || signature(3373)`.
pub const RECOVERY_BINDING_LENGTH: usize = 32 + VERIFYING_KEY_LENGTH + SIGNATURE_LENGTH;
/// `root(32) || head(32) || chain_head(32) || u64be(epochs) || signer(32) || signature(3373)`.
pub const EPOCH_BINDING_LENGTH: usize = 32 * 3 + 8 + 32 + SIGNATURE_LENGTH;

/// The founding device's statement "this identity's recovery key is K".
///
/// The Create entry names only the founder, so the log alone cannot say which
/// recovery key is genuine: anyone can append a Recover signed by their own key
/// and claim it (§15.1). The root link commits to the founder's key and
/// signature, so a relying party that pins the 32-byte root and receives this
/// binding learns the one recovery key the founder chose. A forger would need
/// the founder's signature over a different key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBinding {
    pub root: [u8; 32],
    pub recovery_key: VerifyingIdentity,
    pub signature: Vec<u8>,
}

fn recovery_message(root: &[u8; 32], recovery: &VerifyingIdentity) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + VERIFYING_KEY_LENGTH);
    out.extend_from_slice(root);
    out.extend_from_slice(&recovery.to_bytes());
    out
}

fn founder_key(entries: &[Entry]) -> Result<VerifyingIdentity, IdentityError> {
    match entries.first().map(|entry| &entry.event) {
        Some(Event::Create { device, .. }) => {
            VerifyingIdentity::from_bytes(device).map_err(|_| IdentityError::BadBinding)
        }
        Some(_) => Err(IdentityError::BadRoot("another event")),
        None => Err(IdentityError::Empty),
    }
}

impl RecoveryBinding {
    /// Signed by the founding device right after `IdentityLog::create`, while
    /// it certainly holds the key. A founder that is later compromised can
    /// sign a second binding; §16.1 says what a verifier does about that.
    pub fn create(log: &IdentityLog, founder: &SigningIdentity) -> Result<Self, IdentityError> {
        let root = log.root();
        let expected = founder_key(log.entries())?;
        if founder.verifying_key() != expected {
            return Err(IdentityError::Unauthorised(0));
        }
        let signature = founder
            .sign(
                RECOVERY_BINDING_CONTEXT,
                &recovery_message(&root, &log.recovery),
            )
            .to_vec();
        Ok(Self {
            root,
            recovery_key: log.recovery.clone(),
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECOVERY_BINDING_LENGTH);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.recovery_key.to_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != RECOVERY_BINDING_LENGTH {
            return Err(IdentityError::Malformed);
        }
        let (root, rest) = bytes.split_at(32);
        let (key, signature) = rest.split_at(VERIFYING_KEY_LENGTH);
        Ok(Self {
            root: root.try_into().map_err(|_| IdentityError::Malformed)?,
            recovery_key: VerifyingIdentity::from_bytes(key)
                .map_err(|_| IdentityError::Malformed)?,
            signature: signature.to_vec(),
        })
    }

    /// Verifies the binding against the log it claims, then replays the log
    /// under the bound recovery key. Returns the verified log.
    pub fn verify(&self, entries: Vec<Entry>) -> Result<IdentityLog, IdentityError> {
        let founder = founder_key(&entries)?;
        if entries.first().map(|entry| entry.link) != Some(self.root) {
            return Err(IdentityError::WrongIdentity);
        }
        founder
            .verify(
                RECOVERY_BINDING_CONTEXT,
                &recovery_message(&self.root, &self.recovery_key),
                &self.signature,
            )
            .map_err(|_| IdentityError::BadBinding)?;
        IdentityLog::from_entries(entries, self.recovery_key.clone())
    }

    /// The call a relying party makes: `pinned_root` is the value it trusts.
    pub fn verify_pinned(
        &self,
        entries: Vec<Entry>,
        pinned_root: &[u8; 32],
    ) -> Result<IdentityLog, IdentityError> {
        if &self.root != pinned_root {
            return Err(IdentityError::WrongIdentity);
        }
        self.verify(entries)
    }
}

/// A trusted device's statement "at identity history H, my epoch chain is C,
/// with N epochs". Without it anyone can publish a chain for anyone (§15.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochBinding {
    pub identity_root: [u8; 32],
    pub identity_head: [u8; 32],
    pub chain_head: [u8; 32],
    pub epochs: u64,
    pub signer: DeviceId,
    pub signature: Vec<u8>,
}

fn chain_head(records: &[EpochRecord]) -> [u8; 32] {
    records.last().map_or([0; 32], |record| record.link)
}

impl EpochBinding {
    fn message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 4 + 8);
        out.extend_from_slice(&self.identity_root);
        out.extend_from_slice(&self.identity_head);
        out.extend_from_slice(&self.chain_head);
        out.extend_from_slice(&self.epochs.to_be_bytes());
        out.extend_from_slice(&self.signer);
        out
    }

    /// Signed by a device the log trusts now, over the log's current head and
    /// the chain as it stands. Each `advance` needs a fresh binding.
    pub fn create(
        log: &IdentityLog,
        device: &SigningIdentity,
        records: &[EpochRecord],
    ) -> Result<Self, IdentityError> {
        let signer = device_id(&device.verifying_key());
        if !log.membership().contains(&signer) {
            return Err(IdentityError::Unauthorised(log.entries().len() as u64));
        }
        hide_epoch::EpochChain::verify(records).map_err(|_| IdentityError::StaleBinding)?;
        if records.is_empty() {
            return Err(IdentityError::StaleBinding);
        }
        let mut binding = Self {
            identity_root: log.root(),
            identity_head: log.head(),
            chain_head: chain_head(records),
            epochs: records.len() as u64,
            signer,
            signature: Vec::new(),
        };
        binding.signature = device
            .sign(EPOCH_BINDING_CONTEXT, &binding.message())
            .to_vec();
        Ok(binding)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.message();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != EPOCH_BINDING_LENGTH {
            return Err(IdentityError::Malformed);
        }
        let field = |at: usize| -> Result<[u8; 32], IdentityError> {
            bytes[at..at + 32]
                .try_into()
                .map_err(|_| IdentityError::Malformed)
        };
        Ok(Self {
            identity_root: field(0)?,
            identity_head: field(32)?,
            chain_head: field(64)?,
            epochs: u64::from_be_bytes(
                bytes[96..104]
                    .try_into()
                    .map_err(|_| IdentityError::Malformed)?,
            ),
            signer: field(104)?,
            signature: bytes[136..].to_vec(),
        })
    }

    /// Checks the binding against a VERIFIED identity log (obtain it through
    /// [`RecoveryBinding::verify_pinned`]) and the exact chain it names.
    ///
    /// The signer must be trusted by the log's current membership, not merely
    /// at the bound head: revoking a device withdraws every chain it vouched
    /// for, and the remaining devices re-bind.
    pub fn verify(&self, log: &IdentityLog, records: &[EpochRecord]) -> Result<(), IdentityError> {
        if log.root() != self.identity_root {
            return Err(IdentityError::WrongIdentity);
        }
        if !log
            .entries()
            .iter()
            .any(|entry| entry.link == self.identity_head)
        {
            return Err(IdentityError::StaleBinding);
        }
        hide_epoch::EpochChain::verify(records).map_err(|_| IdentityError::StaleBinding)?;
        if records.is_empty()
            || records.len() as u64 != self.epochs
            || chain_head(records) != self.chain_head
        {
            return Err(IdentityError::StaleBinding);
        }
        verify_by_member(
            &log.membership(),
            &self.signer,
            &self.message(),
            &self.signature,
        )
    }
}

fn verify_by_member(
    membership: &Membership,
    signer: &DeviceId,
    message: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    let device = membership
        .get(signer)
        .ok_or(IdentityError::Unauthorised(0))?;
    device
        .key
        .verify(EPOCH_BINDING_CONTEXT, message, signature)
        .map_err(|_| IdentityError::BadBinding)
}
