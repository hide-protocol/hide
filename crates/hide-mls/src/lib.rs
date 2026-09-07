//! Group messaging for HIDE identities, over MLS (RFC 9420).
//!
//! Everything HIDE does elsewhere protects objects at rest. This is different:
//! a live group where members join and leave, and where a message sent today
//! must stay unreadable to a member removed yesterday and to one who joins
//! tomorrow. That is a ratchet problem, not a file-format problem, so the
//! protocol machinery is `mls-rs` and **this crate adds no cryptography**.
//!
//! What it does add is the join between an MLS group and a HIDE identity: the
//! credential carried in the group is a device from an [`IdentityLog`], so
//! "who is in this group" and "which devices does this person trust" are
//! answered from the same place, and revoking a device is not silently
//! independent of removing it from a group.
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
use hide_sign::VerifyingIdentity;
use mls_rs::client_builder::MlsConfig;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{CipherSuite, Client, CryptoProvider, MlsMessage};
use mls_rs_core::crypto::CipherSuiteProvider;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use thiserror::Error;

/// Where post-quantum group messaging actually stands, so a caller reading the
/// API does not have to guess. Checked against the IETF drafts on 2026-09-07.
pub const PQ_STATUS: &str = "MLS PQ ciphersuites (draft-ietf-mls-pq-ciphersuites) are an \
Internet-Draft, not an RFC, and no Rust MLS provider implements them yet. Group messages \
here use X25519, which is not post-quantum. HIDE's object encryption is hybrid PQ.";

/// The suite used for groups. Classical, deliberately and visibly.
const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

#[derive(Debug, Error)]
pub enum MlsError {
    #[error("this device is not trusted by the identity")]
    UntrustedDevice,
    #[error("the message came from a device the identity does not trust")]
    UntrustedSender,
    #[error("the sender's credential is not a HIDE device id")]
    NotADeviceCredential,
    #[error("MLS: {0}")]
    Protocol(String),
}

fn protocol<E: core::fmt::Display>(error: E) -> MlsError {
    MlsError::Protocol(error.to_string())
}

/// Builds the MLS client for one device of a HIDE identity.
///
/// The credential is the device id, so a group's membership list is meaningful
/// against the identity log rather than being an unrelated name.
pub fn client_for(
    membership: &Membership,
    device: VerifyingIdentity,
) -> Result<Client<impl MlsConfig + use<>>, MlsError> {
    let id = device_id(&device);
    if !membership.contains(&id) {
        return Err(MlsError::UntrustedDevice);
    }

    let crypto = RustCryptoProvider::default();
    let provider = crypto.cipher_suite_provider(SUITE).ok_or_else(|| {
        MlsError::Protocol("the cipher suite is unavailable in this build".into())
    })?;
    // MLS signs with its own key; HIDE's hybrid signing key is what authorises
    // the device in the identity log, and the two are deliberately separate.
    let (secret, public) = provider.signature_key_generate().map_err(protocol)?;

    let signing = SigningIdentity::new(BasicCredential::new(id.to_vec()).into_credential(), public);

    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .signing_identity(signing, secret, SUITE)
        .build())
}

/// Extracts the HIDE device id from an MLS credential.
fn credential_device(signing: &SigningIdentity) -> Result<DeviceId, MlsError> {
    let basic = signing
        .credential
        .as_basic()
        .ok_or(MlsError::NotADeviceCredential)?;
    basic
        .identifier()
        .try_into()
        .map_err(|_| MlsError::NotADeviceCredential)
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
    MlsMessage::from_bytes(bytes).map_err(protocol)
}
