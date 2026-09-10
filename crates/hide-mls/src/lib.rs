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
//!   group; [`GroupSession::remove_device`] must be called. The link is
//!   checked, not automatic.

use hide_identity::{DeviceId, Membership, device_id};
use hide_sign::{
    SIGNATURE_LENGTH, SigningIdentity as HideSigner, VERIFYING_KEY_LENGTH, VerifyingIdentity,
};
use mls_rs::client_builder::MlsConfig;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::{CipherSuite, Client, CryptoProvider, MlsMessage};
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
        let data = custom.data();
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

/// Validates roster entries against a HIDE identity's membership.
///
/// Every member the group admits must present a credential whose binding
/// signature verifies under a key that is currently trusted by the identity.
/// MLS calls this on join, on every commit that adds a member, and when
/// processing an external sender; it is the hook that makes `BasicCredential`'s
/// self-asserted name into something an attacker cannot simply claim.
#[derive(Clone, Debug)]
pub struct HideIdentityProvider {
    membership: Membership,
}

impl HideIdentityProvider {
    pub fn new(membership: Membership) -> Self {
        Self { membership }
    }

    fn validate(&self, signing_identity: &SigningIdentity) -> Result<(), MlsError> {
        let binding = Binding::parse(&signing_identity.credential)?;
        binding.verify(signing_identity.signature_key.as_bytes())?;
        let trusted = self
            .membership
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
        // Only the same device may replace itself via external commit.
        let a = Binding::parse(&predecessor.credential)?;
        let b = Binding::parse(&successor.credential)?;
        Ok(a.device == b.device)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![HIDE_CREDENTIAL]
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

    Ok(Client::builder()
        .identity_provider(HideIdentityProvider::new(membership.clone()))
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
