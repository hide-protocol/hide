//! Group messaging for HIDE identities, over MLS (RFC 9420).
//!
//! Everything HIDE does elsewhere protects objects at rest. This is different:
//! a live group where members join and leave, and where a message sent today
//! must stay unreadable to a member removed yesterday and to one who joins
//! tomorrow. That is a ratchet problem, not a file-format problem, so the
//! protocol machinery is `mls-rs` and **this crate adds no cryptography**.
//!
//! What it does add is the join between an MLS group and a HIDE identity: the
//! credential carried in the group names a device from an identity log **and
//! proves it**. The HIDE hybrid signing key of that device signs the MLS
//! signature public key, so a roster entry cannot claim to be a device it does
//! not hold the key for. "Who is in this group" and "which devices does this
//! person trust" are then answered from the same place, and revoking a device
//! is not silently independent of removing it from a group.
//!
//! # Honest limits
//!
//! - **`mls-rs` has no third-party security audit**, and neither does HIDE.
//! - The cipher suite here is **classical X25519**, not post-quantum. MLS's PQ
//!   ciphersuites are still an IETF draft and no Rust provider implements them
//!   yet; see [`PQ_STATUS`]. HIDE's own object encryption *is* hybrid PQ, so a
//!   group message is protected differently from a sealed file. Saying that
//!   plainly matters more than implying uniform protection.
//! - Removing a device from an identity does not by itself evict it from every
//!   group. HIDE checks the link, it does not make eviction automatic: the
//!   group still has to remove the device with an MLS commit, and
//!   [`untrusted_members`] is how a caller finds out which ones are due.

use hide_identity::{DeviceId, Membership, device_id};
use hide_sign::{
    SIGNATURE_LENGTH, SigningIdentity as HideSigner, VERIFYING_KEY_LENGTH, VerifyingIdentity,
};
use mls_rs::client_builder::MlsConfig;
use mls_rs::group::{ReceivedMessage, Roster, Sender};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle,
};
use mls_rs::{CipherSuite, Client, CryptoProvider, MlsMessage, MlsRules};
use mls_rs_core::crypto::CipherSuiteProvider;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::extension::ExtensionList;
use mls_rs_core::identity::IdentityProvider;
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, MemberValidationContext,
};
use mls_rs_core::time::MlsTime;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use thiserror::Error;

/// Where post-quantum group messaging actually stands, so a caller reading the
/// API does not have to guess. Checked against the IETF drafts on 2026-09-07.
pub const PQ_STATUS: &str = "MLS PQ ciphersuites (draft-ietf-mls-pq-ciphersuites) are an \
Internet-Draft, not an RFC, and no Rust MLS provider implements them yet. Group messages \
here use X25519, which is not post-quantum. HIDE's object encryption is hybrid PQ.";

/// The suite used for groups. Classical, deliberately and visibly.
const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// Private-use credential type carrying a HIDE device binding. RFC 9420 §17.5
/// reserves 0xF000..=0xFFFF for private use.
pub const HIDE_CREDENTIAL: CredentialType = CredentialType::new(0xF01D);

/// Domain separator for the binding signature. Bumped with the layout.
const BINDING_CONTEXT: &[u8] = b"HIDE/0.7 mls binding";

const DEVICE_ID_LEN: usize = 32;
const CREDENTIAL_LEN: usize = DEVICE_ID_LEN + VERIFYING_KEY_LENGTH + SIGNATURE_LENGTH;

/// Largest wire message accepted from the network. `mls-rs` is third-party and
/// unaudited, so nothing arbitrary is handed to its parser: a legitimate
/// handshake or application message is orders of magnitude below this.
pub const MAX_MLS_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum MlsError {
    #[error("this device is not trusted by the identity")]
    UntrustedDevice,
    #[error("the message is larger than {MAX_MLS_MESSAGE} bytes")]
    MessageTooLarge,
    #[error("the message came from a device the identity does not trust")]
    UntrustedSender,
    #[error("the credential is not a HIDE device binding")]
    NotADeviceCredential,
    #[error("the credential's binding signature does not verify")]
    ForgedCredential,
    #[error("MLS: {0}")]
    Protocol(String),
}

fn protocol<E: core::fmt::Display>(error: E) -> MlsError {
    MlsError::Protocol(error.to_string())
}

impl IntoAnyError for MlsError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// What the HIDE key signs: the device it speaks for and the MLS key it vouches
/// for. Both fixed width, so no length prefix is needed.
fn binding_message(device: &DeviceId, mls_public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEVICE_ID_LEN + mls_public_key.len());
    out.extend_from_slice(device);
    out.extend_from_slice(mls_public_key);
    out
}

/// A parsed HIDE credential: `device_id(32) || hide_verifying_key || signature`.
struct Binding {
    device: DeviceId,
    key: VerifyingIdentity,
    signature: [u8; SIGNATURE_LENGTH],
}

impl Binding {
    fn parse(credential: &Credential) -> Result<Self, MlsError> {
        let custom = credential
            .as_custom()
            .filter(|c| c.credential_type() == HIDE_CREDENTIAL)
            .ok_or(MlsError::NotADeviceCredential)?;
        Self::parse_bytes(custom.data())
    }

    fn parse_bytes(data: &[u8]) -> Result<Self, MlsError> {
        if data.len() != CREDENTIAL_LEN {
            return Err(MlsError::NotADeviceCredential);
        }
        let device: DeviceId = data[..DEVICE_ID_LEN]
            .try_into()
            .map_err(|_| MlsError::NotADeviceCredential)?;
        let key = VerifyingIdentity::from_bytes(
            &data[DEVICE_ID_LEN..DEVICE_ID_LEN + VERIFYING_KEY_LENGTH],
        )
        .map_err(|_| MlsError::NotADeviceCredential)?;
        let signature: [u8; SIGNATURE_LENGTH] = data[DEVICE_ID_LEN + VERIFYING_KEY_LENGTH..]
            .try_into()
            .map_err(|_| MlsError::NotADeviceCredential)?;
        // The id must be the hash of the key it travels with, or the two halves
        // came from different devices.
        if device_id(&key) != device {
            return Err(MlsError::ForgedCredential);
        }
        Ok(Self {
            device,
            key,
            signature,
        })
    }

    /// The signature must cover THIS MLS key: a valid binding lifted from
    /// another key package is a forgery here.
    fn verify(&self, mls_public_key: &[u8]) -> Result<(), MlsError> {
        self.key
            .verify(
                BINDING_CONTEXT,
                &binding_message(&self.device, mls_public_key),
                &self.signature,
            )
            .map_err(|_| MlsError::ForgedCredential)
    }
}

/// Checks the HIDE device binding inside a credential, from the raw bytes it
/// carries, and returns nothing but the verdict.
///
/// A credential arrives with a message from a delivery service that is not
/// trusted, so every field in it is attacker-chosen. This is the parser
/// `Binding::parse` uses, exposed so a caller can validate a credential it
/// received outside a group — and so the parser has a fuzz target, which the
/// group-level API cannot give it: reaching `Binding::parse` otherwise requires
/// a fully joined MLS client, which is not attacker-shaped.
pub fn validate_device_credential(data: &[u8]) -> Result<(), MlsError> {
    Binding::parse_bytes(data).map(|_| ())
}

/// Validates roster entries against a HIDE identity's membership.
///
/// Every member the group admits must present a credential whose binding
/// signature verifies under a key that is currently trusted by the identity.
/// MLS calls this on join, on every commit that adds a member, and when
/// processing an external sender; it is the hook that makes `BasicCredential`'s
/// self-asserted name into something an attacker cannot simply claim.
#[derive(Clone, Debug)]
pub struct HideIdentityProvider {
    // Shared with every clone MLS makes of the provider, so `update` reaches
    // the copy inside a long-lived client (spec §15.8).
    membership: std::sync::Arc<std::sync::RwLock<Membership>>,
}

impl HideIdentityProvider {
    pub fn new(membership: Membership) -> Self {
        Self {
            membership: std::sync::Arc::new(std::sync::RwLock::new(membership)),
        }
    }

    /// Replaces the membership every clone of this provider validates
    /// against. Call it after replaying a newer identity log, so a revoked
    /// device is refused at the next commit without rebuilding the client.
    pub fn update(&self, membership: Membership) {
        match self.membership.write() {
            Ok(mut guard) => *guard = membership,
            Err(poisoned) => *poisoned.into_inner() = membership,
        }
    }

    /// The membership currently enforced.
    pub fn membership(&self) -> Membership {
        match self.membership.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn validate(&self, signing_identity: &SigningIdentity) -> Result<(), MlsError> {
        let binding = Binding::parse(&signing_identity.credential)?;
        binding.verify(signing_identity.signature_key.as_bytes())?;
        let membership = self.membership();
        let trusted = membership
            .get(&binding.device)
            .ok_or(MlsError::UntrustedDevice)?;
        // The log's key for this device, not the one in the credential, is the
        // authority; they must agree or the credential is for a different key
        // that happens to hash to the same id, which is not possible, or stale.
        if trusted.key != binding.key {
            return Err(MlsError::ForgedCredential);
        }
        Ok(())
    }

    /// Whether a signing identity is a device the identity trusts right now.
    /// Public because the MLS rules below need the same verdict.
    pub fn is_trusted(&self, signing_identity: &SigningIdentity) -> bool {
        self.validate(signing_identity).is_ok()
    }
}

impl IdentityProvider for HideIdentityProvider {
    type Error = MlsError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.validate(signing_identity)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        self.validate(signing_identity)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(Binding::parse(&signing_identity.credential)?
            .device
            .to_vec())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        // Only the same device may replace itself via external commit, and the
        // successor must itself pass member validation (spec §13 items 4-6)
        // rather than relying on the MLS library to have run it.
        let a = Binding::parse(&predecessor.credential)?;
        let b = Binding::parse(&successor.credential)?;
        if a.device != b.device {
            return Ok(false);
        }
        Ok(self.validate(successor).is_ok())
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![HIDE_CREDENTIAL]
    }
}

/// MLS checks the roster when a member is added, and never again. A device
/// that HIDE revoked afterwards is still a member MLS is happy to hear from:
/// it can commit, and it can leave a by-reference proposal in the cache for an
/// honest client to fold into its next commit (for example a Remove of the
/// honest device). These rules close that window, using the same membership
/// the identity provider validates against, so `update` reaches both.
#[derive(Clone, Debug)]
pub struct HideMlsRules {
    membership: HideIdentityProvider,
}

impl HideMlsRules {
    pub fn new(membership: HideIdentityProvider) -> Self {
        Self { membership }
    }

    /// Whether the member at `index` is a device the identity still trusts.
    /// A sender that cannot be attributed to a roster member is not trusted:
    /// HIDE configures no external senders, so there is no honest case for one.
    fn trusted_member(&self, roster: &Roster<'_>, index: u32) -> bool {
        roster
            .member_with_index(index)
            .map(|member| self.membership.is_trusted(&member.signing_identity))
            .unwrap_or(false)
    }
}

impl MlsRules for HideMlsRules {
    type Error = MlsError;

    fn filter_proposals(
        &self,
        direction: CommitDirection,
        source: CommitSource,
        current_roster: &Roster<'_>,
        _current_context: &mls_rs::group::GroupContext,
        mut proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        // The commit's own author first: a revoked device must not be able to
        // author anything at all.
        if let CommitSource::ExistingMember(member) = &source
            && !self.membership.is_trusted(&member.signing_identity)
        {
            return Err(MlsError::UntrustedSender);
        }
        let mut dropped = false;
        proposals.retain(|info| {
            let keep = match info.sender {
                Sender::Member(index) => self.trusted_member(current_roster, index),
                _ => false,
            };
            dropped |= !keep;
            Ok::<bool, MlsError>(keep)
        })?;
        // Receiving: an untrusted proposal means the group is in a state the
        // caller must not continue from. Sending: a stale by-reference proposal
        // is dropped rather than folded in, so one bad proposal cannot deadlock
        // every later commit.
        if dropped && matches!(direction, CommitDirection::Receive) {
            return Err(MlsError::UntrustedSender);
        }
        Ok(proposals)
    }

    fn commit_options(
        &self,
        _new_roster: &Roster<'_>,
        _new_context: &mls_rs::group::GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        // An update path always: a commit that removes someone must rekey the
        // epoch, not merely announce the removal.
        Ok(CommitOptions::new().with_path_required(true))
    }

    fn encryption_options(
        &self,
        _current_roster: &Roster<'_>,
        _current_context: &mls_rs::group::GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::default())
    }
}

/// Builds the MLS client for one device of a HIDE identity.
///
/// The credential carries the device id, the device's HIDE verifying key, and a
/// HIDE signature over the freshly generated MLS signature key. A group member
/// therefore cannot present a device it does not hold the signing key for, and
/// the identity provider checks every roster entry against `membership`.
pub fn client_for(
    membership: &Membership,
    device: &HideSigner,
) -> Result<Client<impl MlsConfig + use<>>, MlsError> {
    client_with_provider(HideIdentityProvider::new(membership.clone()), device)
}

/// As [`client_for`], with a provider the caller keeps a handle to, so it can
/// push a newer membership into the running client with
/// [`HideIdentityProvider::update`].
pub fn client_with_provider(
    provider_handle: HideIdentityProvider,
    device: &HideSigner,
) -> Result<Client<impl MlsConfig + use<>>, MlsError> {
    let membership = provider_handle.membership();
    let verifying = device.verifying_key();
    let id = device_id(&verifying);
    if !membership.contains(&id) {
        return Err(MlsError::UntrustedDevice);
    }

    let crypto = RustCryptoProvider::default();
    let provider = crypto.cipher_suite_provider(SUITE).ok_or_else(|| {
        MlsError::Protocol("the cipher suite is unavailable in this build".into())
    })?;
    // MLS signs with its own key; HIDE's hybrid signing key authorises the
    // device in the identity log AND vouches for the MLS key, below.
    let (secret, public) = provider.signature_key_generate().map_err(protocol)?;

    let signature = device.sign(BINDING_CONTEXT, &binding_message(&id, public.as_bytes()));
    let mut data = Vec::with_capacity(CREDENTIAL_LEN);
    data.extend_from_slice(&id);
    data.extend_from_slice(&verifying.to_bytes());
    data.extend_from_slice(&signature);
    let credential = Credential::Custom(CustomCredential::new(HIDE_CREDENTIAL, data));
    let signing = SigningIdentity::new(credential, public);

    // The rules share the provider (and therefore the same `RwLock`), so a
    // later `update` narrows what the rules accept and what the provider
    // validates, together.
    let rules = HideMlsRules::new(provider_handle.clone());
    Ok(Client::builder()
        .identity_provider(provider_handle)
        .mls_rules(rules)
        .crypto_provider(crypto)
        .signing_identity(signing, secret, SUITE)
        .build())
}

/// Extracts the HIDE device id from an MLS credential, after checking that the
/// credential's binding signature covers the MLS key it travels with.
fn credential_device(signing: &SigningIdentity) -> Result<DeviceId, MlsError> {
    let binding = Binding::parse(&signing.credential)?;
    binding.verify(signing.signature_key.as_bytes())?;
    Ok(binding.device)
}

/// Checks every member of a group against an identity's current membership.
///
/// This is the check that keeps revocation meaningful: a device removed from
/// the identity is reported here even though MLS itself has no opinion about
/// HIDE identities.
pub fn untrusted_members<C: MlsConfig>(
    group: &mls_rs::Group<C>,
    membership: &Membership,
) -> Result<Vec<DeviceId>, MlsError> {
    let mut stale = Vec::new();
    for member in group.roster().members_iter() {
        let device = credential_device(&member.signing_identity)?;
        if !membership.contains(&device) {
            stale.push(device);
        }
    }
    Ok(stale)
}

/// The device id behind a received application message, so a caller can decide
/// whether it still trusts the sender.
pub fn sender_device<C: MlsConfig>(
    group: &mls_rs::Group<C>,
    message: &ReceivedMessage,
) -> Result<Option<DeviceId>, MlsError> {
    let ReceivedMessage::ApplicationMessage(app) = message else {
        return Ok(None);
    };
    let member = group
        .member_at_index(app.sender_index)
        .ok_or_else(|| MlsError::Protocol("sender is not in the roster".into()))?;
    credential_device(&member.signing_identity).map(Some)
}

/// Rejects an application message whose sender the identity no longer trusts.
///
/// MLS guarantees the message came from a group member; it cannot know that the
/// member's device was revoked in the identity log a minute ago.
pub fn accept_from_trusted<C: MlsConfig>(
    group: &mls_rs::Group<C>,
    message: &ReceivedMessage,
    membership: &Membership,
) -> Result<(), MlsError> {
    match sender_device(group, message)? {
        Some(device) if !membership.contains(&device) => Err(MlsError::UntrustedSender),
        _ => Ok(()),
    }
}

/// Re-exported so callers need not depend on `mls-rs` directly for the common
/// path.
pub use mls_rs::MlsMessage as Message;
pub use mls_rs::group::ReceivedMessage as Received;

/// Serialises a message for transport.
pub fn encode_message(message: &MlsMessage) -> Result<Vec<u8>, MlsError> {
    message.to_bytes().map_err(protocol)
}

pub fn decode_message(bytes: &[u8]) -> Result<MlsMessage, MlsError> {
    if bytes.len() > MAX_MLS_MESSAGE {
        return Err(MlsError::MessageTooLarge);
    }
    MlsMessage::from_bytes(bytes).map_err(protocol)
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    /// A credential arrives from a delivery service, so its length is the first
    /// thing an attacker controls. The validator must refuse rather than index.
    #[test]
    fn a_credential_of_the_wrong_length_is_refused() {
        for length in [0, 1, DEVICE_ID_LEN, CREDENTIAL_LEN - 1, CREDENTIAL_LEN + 1] {
            assert!(
                matches!(
                    validate_device_credential(&vec![0x5a; length]),
                    Err(MlsError::NotADeviceCredential)
                ),
                "a {length}-byte credential was not refused"
            );
        }
    }

    #[test]
    fn a_genuine_binding_is_accepted_and_a_mismatched_id_is_a_forgery() {
        let signing = HideSigner::from_bytes(&[0x6c; 32]).expect("a seed");
        let device = device_id(&signing.verifying_key());
        let key = signing.verifying_key().to_bytes();
        let signature = signing.sign(BINDING_CONTEXT, &binding_message(&device, b"an mls key"));

        let mut data = device.to_vec();
        data.extend_from_slice(&key);
        data.extend_from_slice(&signature);
        assert!(validate_device_credential(&data).is_ok());

        // An id that is not the hash of the key it travels with is a forgery,
        // not a credential of the wrong type: the two halves came from
        // different devices.
        data[0] ^= 1;
        assert!(matches!(
            validate_device_credential(&data),
            Err(MlsError::ForgedCredential)
        ));
    }
}
