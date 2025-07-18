// Copyright 2019-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod apdu;
mod client_pin;
pub mod command;
#[cfg(feature = "config_command")]
mod config_command;
mod credential_management;
pub mod crypto_wrapper;
#[cfg(feature = "with_ctap1")]
mod ctap1;
pub mod data_formats;
#[cfg(feature = "fingerprint")]
pub mod fingerprint;
pub mod hid;
mod large_blobs;
pub mod main_hid;
mod pin_protocol;
pub mod response;
pub mod secret;
pub mod status_code;
mod storage;
mod token_state;
#[cfg(feature = "with_ctap1")]
mod u2f_up;
#[cfg(feature = "vendor_hid")]
pub mod vendor_hid;

pub use self::client_pin::PIN_AUTH_LENGTH;
use self::client_pin::{ClientPin, PinPermission};
use self::command::{
    AuthenticatorGetAssertionParameters, AuthenticatorMakeCredentialParameters, Command,
};
#[cfg(feature = "config_command")]
use self::config_command::process_config;
use self::credential_management::process_credential_management;
use self::data_formats::{
    AuthenticatorTransport, CredentialProtectionPolicy, EnterpriseAttestationMode,
    GetAssertionExtensions, PackedAttestationStatement, PinUvAuthProtocol,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameter, PublicKeyCredentialSource,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, SignatureAlgorithm,
};
#[cfg(feature = "fingerprint")]
use self::fingerprint::{perform_built_in_uv, process_bio_enrollment};
use self::hid::{
    ChannelID, CtapHid, CtapHidCommand, HidPacketIterator, KeepaliveStatus, ProcessedPacket,
};
use self::large_blobs::LargeBlobState;
use self::response::{
    AuthenticatorGetAssertionResponse, AuthenticatorGetInfoResponse,
    AuthenticatorMakeCredentialResponse, ResponseData,
};
use self::secret::Secret;
use self::status_code::{Ctap2StatusCode, CtapResult};
#[cfg(feature = "with_ctap1")]
use self::u2f_up::U2fUserPresenceState;
use crate::api::clock::Clock;
use crate::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use crate::api::crypto::ecdsa::{SecretKey as _, Signature};
use crate::api::crypto::hkdf256::Hkdf256;
use crate::api::crypto::sha256::Sha256;
use crate::api::crypto::HASH_SIZE;
use crate::api::customization::Customization;
#[cfg(feature = "fingerprint")]
use crate::api::fingerprint::Fingerprint;
use crate::api::key_store::{CredentialSource, KeyStore, MAX_CREDENTIAL_ID_SIZE};
use crate::api::persist::{Attestation, AttestationId, Persist};
use crate::api::private_key::PrivateKey;
use crate::api::rng::Rng;
use crate::api::user_presence::{UserPresence, UserPresenceError};
use crate::env::{EcdsaSk, Env, Hkdf, Sha};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use rand_core::RngCore;
use sk_cbor as cbor;
use sk_cbor::cbor_map_options;

// Set this bit when checking user presence.
const UP_FLAG: u8 = 0x01;
// Set this bit when checking user verification.
const UV_FLAG: u8 = 0x04;
// Set this bit when performing attestation.
const AT_FLAG: u8 = 0x40;
// Set this bit when an extension is used.
const ED_FLAG: u8 = 0x80;

// CTAP2 specification section 6 requires that the depth of nested CBOR structures be limited to at most four levels.
const MAX_CBOR_NESTING_DEPTH: i8 = 4;

pub const KEEPALIVE_DELAY_MS: usize = 100;
pub const TOUCH_TIMEOUT_MS: usize = 30000;
const RESET_TIMEOUT_DURATION_MS: usize = 10000;
const STATEFUL_COMMAND_TIMEOUT_DURATION_MS: usize = 30000;

pub const FIDO2_VERSION_STRING: &str = "FIDO_2_0";
#[cfg(feature = "with_ctap1")]
pub const U2F_VERSION_STRING: &str = "U2F_V2";
pub const FIDO2_1_VERSION_STRING: &str = "FIDO_2_1";

// We currently only support one algorithm for signatures: ES256.
// This algorithm is requested in MakeCredential and advertized in GetInfo.
pub const ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Es256,
};

#[cfg(feature = "ed25519")]
pub const EDDSA_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Eddsa,
};

const SUPPORTED_CRED_PARAMS: &[PublicKeyCredentialParameter] = &[
    ES256_CRED_PARAM,
    #[cfg(feature = "ed25519")]
    EDDSA_CRED_PARAM,
];

fn get_preferred_cred_param(
    params: &[PublicKeyCredentialParameter],
) -> Option<&PublicKeyCredentialParameter> {
    params
        .iter()
        .find(|&param| SUPPORTED_CRED_PARAMS.contains(param))
}

/// Transports supported by OpenSK.
///
/// An OpenSK library user annotates incoming data with this data type.
///
/// The difference between this data type and `AuthenticatorTransport` is that the latter
/// corresponds to the communication defined in the CTAP specification. This data type describes
/// the hardware path a packet took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Corresponds to CTAP's USB transport.
    MainHid,
    /// No equivalent in CTAP, used for communication outside the specification.
    #[cfg(feature = "vendor_hid")]
    VendorHid,
}

impl Transport {
    pub fn usb_endpoint(self) -> UsbEndpoint {
        match self {
            Transport::MainHid => UsbEndpoint::MainHid,
            #[cfg(feature = "vendor_hid")]
            Transport::VendorHid => UsbEndpoint::VendorHid,
        }
    }
}

/// Communication channels between authenticator and client.
///
/// From OpenSK's perspective, a channel represents a client. When we receive data from a new
/// channel, we have to assume it's a new client.
///
/// For HID, communication channels coincide with the channel ID. NFC and HID transports are unique
/// channels themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Corresponds to CTAP's USB transport.
    MainHid(ChannelID),
    /// No equivalent in CTAP, used for communication outside the specification.
    #[cfg(feature = "vendor_hid")]
    VendorHid(ChannelID),
}

// Helpers to perform CBOR read/write while respecting CTAP2 nesting limits.
pub fn cbor_read(encoded_cbor: &[u8]) -> CtapResult<cbor::Value> {
    cbor::reader::read_nested(encoded_cbor, Some(MAX_CBOR_NESTING_DEPTH))
        .map_err(|_e| Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
}

pub fn cbor_write(value: cbor::Value, encoded_cbor: &mut Vec<u8>) -> CtapResult<()> {
    cbor::writer::write_nested(value, encoded_cbor, Some(MAX_CBOR_NESTING_DEPTH))
        .map_err(|_e| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

/// Resets the all state for a CTAP Reset command.
pub fn reset(env: &mut impl Env) -> CtapResult<()> {
    env.persist().reset()?;
    env.key_store().reset()?;
    storage::init(env)
}

/// Filters the credential from the option if credProtect criteria are not met.
pub fn filter_listed_credential(
    credential: Option<CredentialSource>,
    has_uv: bool,
) -> Option<CredentialSource> {
    credential.filter(|c| {
        has_uv
            || !matches!(
                c.cred_protect_policy,
                Some(CredentialProtectionPolicy::UserVerificationRequired)
            )
    })
}

/// Filters the resident key from the option if credProtect criteria are not met.
fn filter_listed_resident_credential(
    credential: Option<PublicKeyCredentialSource>,
    has_uv: bool,
) -> Option<PublicKeyCredentialSource> {
    credential.filter(|c| {
        has_uv
            || !matches!(
                c.cred_protect_policy,
                Some(CredentialProtectionPolicy::UserVerificationRequired)
            )
    })
}

/// Populates all matching fields in a `PublicKeyCredentialSource`.
fn to_public_source(
    credential_id: Vec<u8>,
    credential_source: CredentialSource,
) -> PublicKeyCredentialSource {
    PublicKeyCredentialSource {
        key_type: PublicKeyCredentialType::PublicKey,
        credential_id,
        private_key: credential_source.private_key,
        rp_id: String::new(),
        user_handle: Vec::new(),
        user_display_name: None,
        cred_protect_policy: credential_source.cred_protect_policy,
        creation_order: 0,
        user_name: None,
        user_icon: None,
        cred_blob: credential_source.cred_blob,
        large_blob_key: None,
    }
}

// This function is adapted from https://doc.rust-lang.org/nightly/src/core/str/mod.rs.html#2110
// (as of 2020-01-20) and truncates to "max" bytes, not breaking the encoding.
// We change the return value, since we don't need the bool.
fn truncate_to_char_boundary(s: &str, mut max: usize) -> &str {
    if max >= s.len() {
        s
    } else {
        while !s.is_char_boundary(max) {
            max -= 1;
        }
        &s[..max]
    }
}

/// Send non-critical packets using fire-and-forget.
pub fn send_packets<E: Env>(
    env: &mut E,
    endpoint: UsbEndpoint,
    packets: HidPacketIterator,
) -> CtapResult<()> {
    for pkt in packets {
        env.hid_connection().send(&pkt, endpoint)?;
    }
    Ok(())
}

fn is_cancel(packet: &ProcessedPacket) -> bool {
    match packet {
        ProcessedPacket::InitPacket { cmd, .. } => *cmd == CtapHidCommand::Cancel as u8,
        ProcessedPacket::ContinuationPacket { .. } => false,
    }
}

fn wait_and_respond_busy<E: Env>(env: &mut E, channel: Channel) -> CtapResult<()> {
    let (cid, transport) = match channel {
        Channel::MainHid(cid) => (cid, Transport::MainHid),
        #[cfg(feature = "vendor_hid")]
        Channel::VendorHid(cid) => (cid, Transport::VendorHid),
    };
    let endpoint = transport.usb_endpoint();

    let mut packet = [0; 64];
    let (up_status, recv_status) = env
        .user_presence()
        .wait_with_timeout(&mut packet, KEEPALIVE_DELAY_MS)?;
    match recv_status {
        RecvStatus::Timeout => (),
        RecvStatus::Received(rx_endpoint) => {
            let (received_cid, processed_packet) = CtapHid::<E>::process_single_packet(&packet);
            if rx_endpoint != endpoint || received_cid != cid {
                debug_ctap!(
                    env,
                    "Received an unrelated packet on endpoint {:?} while sending a KEEPALIVE packet",
                     rx_endpoint,
                );
                let busy_error = CtapHid::<E>::busy_error(received_cid);
                // Don't send errors from other channels on the active channel.
                let _ = send_packets(env, rx_endpoint, busy_error);
            } else if is_cancel(&processed_packet) {
                // Ignored, CANCEL specification says: "the authenticator MUST NOT reply"
                debug_ctap!(env, "User presence check cancelled");
                return Err(UserPresenceError::Canceled.into());
            } else {
                // Ignored. A client shouldn't try to talk to us on this channel yet.
                debug_ctap!(env, "Discarded packet while checking user presence.");
            }
        }
    }
    if matches!(up_status, Err(UserPresenceError::Timeout)) {
        let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
        send_packets(env, endpoint, keepalive_msg)?;
    }
    up_status.map_err(|e| e.into())
}

/// Blocks for user presence.
///
/// Returns an error in case of timeout, user declining presence request, or keepalive error.
pub fn check_user_presence<E: Env>(env: &mut E, channel: Channel) -> CtapResult<()> {
    const TIMEOUT_ERROR: Ctap2StatusCode = Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT;

    env.user_presence().check_init();
    let loop_timer = env.clock().make_timer(TOUCH_TIMEOUT_MS);

    // We don't use the '?' operator to always reach check_complete(...).
    let mut result = Err(TIMEOUT_ERROR);
    while !env.clock().is_elapsed(&loop_timer) {
        match wait_and_respond_busy(env, channel) {
            Err(TIMEOUT_ERROR) => (),
            r => {
                result = r;
                // We want to break on Ok(()) too, indicating touch.
                break;
            }
        }
    }

    env.user_presence().check_complete();
    result
}

/// Holds data necessary to sign an assertion for a credential.
#[derive(Clone)]
pub struct AssertionInput {
    client_data_hash: Vec<u8>,
    auth_data: Vec<u8>,
    extensions: GetAssertionExtensions,
    has_uv: bool,
}

/// Contains the state we need to store for GetNextAssertion.
pub struct AssertionState {
    assertion_input: AssertionInput,
    // Sorted by ascending order of creation, so the last element is the most recent one.
    next_credential_keys: Vec<usize>,
}

/// Stores which command currently holds state for subsequent calls.
pub enum StatefulCommand {
    Reset,
    GetAssertion(Box<AssertionState>),
    EnumerateRps(usize),
    EnumerateCredentials(Vec<usize>),
    LargeBlob(LargeBlobState),
}

/// Stores the current CTAP command state and when it times out.
///
/// Some commands are executed in a series of calls to the authenticator.
/// Interleaving calls to other commands interrupt the current command and
/// remove all state and permissions. Power cycling allows the Reset command,
/// and to prevent misuse or accidents, we disallow Reset after receiving
/// different commands. Therefore, Reset behaves just like all other stateful
/// commands and is included here. Please note that the allowed time for Reset
/// differs from all other stateful commands.
///
/// Additionally, state that is held over multiple commands is assigned to a channel. We discard
/// all state when we receive data on a different channel.
pub struct StatefulPermission<E: Env> {
    permission: <E::Clock as Clock>::Timer,
    command_type: Option<StatefulCommand>,
    channel: Option<Channel>,
}

impl<E: Env> Default for StatefulPermission<E> {
    /// Creates the command state at device startup without user action.
    ///
    /// Reset is not granted after a forced reboot. The user replugging the device is a required
    /// to avoid accidental data loss.
    fn default() -> StatefulPermission<E> {
        StatefulPermission {
            permission: <E::Clock as Clock>::Timer::default(),
            command_type: None,
            channel: None,
        }
    }
}

impl<E: Env> StatefulPermission<E> {
    /// Creates the command state at device startup.
    ///
    /// Resets are only possible after a power cycle. Therefore, there is no way to grant the Reset
    /// permission outside of this function. If you initialize the app without a power cycle
    /// (potentially after waking up from sleep), call `default` instead.
    pub fn new_reset(env: &mut E) -> StatefulPermission<E> {
        StatefulPermission {
            permission: env.clock().make_timer(RESET_TIMEOUT_DURATION_MS),
            command_type: Some(StatefulCommand::Reset),
            channel: None,
        }
    }

    /// Clears all permissions and state.
    pub fn clear(&mut self) {
        self.permission = <E::Clock as Clock>::Timer::default();
        self.command_type = None;
        self.channel = None;
    }

    /// Clears all state if communication is coming from a different channel.
    pub fn clear_old_channels(&mut self, channel: Channel) {
        // There are different possible choices for incoming traffic on a different channel:
        // A) Always reset state (our choice).
        // B) Only reset state if the new command is stateful.
        // C) Keep state on all channels until timeout.
        //
        // If we wanted to switch to (B) or (C), we'd have to be very careful that the state does
        // not go stale. For example, we keep credential keys that we expect to still exist.
        // However, interleaving (stateless) commands could delete credentials or change the PIN,
        // which could invalidate our access. Some read-only commands should be okay to run,
        // but (A) is the safest and easiest solution.
        if let Some(c) = self.channel {
            if c != channel {
                self.clear();
            }
        }
    }

    /// Clears all state if the permission timed out.
    fn clear_timer(&mut self, env: &mut E) {
        if env.clock().is_elapsed(&self.permission) {
            self.clear();
        }
    }

    /// Gets a reference to the current command state, if any exists.
    pub fn get_command(&mut self, env: &mut E) -> CtapResult<&StatefulCommand> {
        self.clear_timer(env);
        self.command_type
            .as_ref()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
    }

    /// Sets a new command state, and starts a new clock for timeouts.
    pub fn set_command(
        &mut self,
        env: &mut E,
        new_command_type: StatefulCommand,
        channel: Channel,
    ) {
        match &new_command_type {
            // Reset is only allowed after a power cycle.
            StatefulCommand::Reset => unreachable!(),
            _ => {
                self.permission = env.clock().make_timer(STATEFUL_COMMAND_TIMEOUT_DURATION_MS);
                self.command_type = Some(new_command_type);
                self.channel = Some(channel);
            }
        }
    }

    /// Returns the state for the next assertion and advances it.
    ///
    /// The state includes all information from GetAssertion and the storage key
    /// to the next credential that needs to be processed.
    pub fn next_assertion_credential(
        &mut self,
        env: &mut E,
    ) -> Result<(AssertionInput, usize), Ctap2StatusCode> {
        self.clear_timer(env);
        if let Some(StatefulCommand::GetAssertion(assertion_state)) = &mut self.command_type {
            let credential_key = assertion_state
                .next_credential_keys
                .pop()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)?;
            Ok((assertion_state.assertion_input.clone(), credential_key))
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the index to the next RP ID for enumeration and advances it.
    pub fn next_enumerate_rp(&mut self, env: &mut E) -> CtapResult<usize> {
        self.clear_timer(env);
        if let Some(StatefulCommand::EnumerateRps(rp_id_index)) = &mut self.command_type {
            let current_index = *rp_id_index;
            *rp_id_index += 1;
            Ok(current_index)
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the next storage credential key for enumeration and advances it.
    pub fn next_enumerate_credential(&mut self, env: &mut E) -> CtapResult<usize> {
        self.clear_timer(env);
        if let Some(StatefulCommand::EnumerateCredentials(rp_credentials)) = &mut self.command_type
        {
            rp_credentials
                .pop()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the large blob state. If none is hold, create and hold a new state.
    pub fn large_blob(&mut self, env: &mut E, channel: Channel) -> &mut LargeBlobState {
        self.clear_timer(env);
        if let Some(StatefulCommand::LargeBlob(_)) = &self.command_type {
        } else {
            self.set_command(
                env,
                StatefulCommand::LargeBlob(LargeBlobState::default()),
                channel,
            );
        }
        if let Some(StatefulCommand::LargeBlob(large_blob_state)) = &mut self.command_type {
            large_blob_state
        } else {
            unreachable!();
        }
    }
}

// This struct currently holds all state, not only the persistent memory. The persistent members are
// in the persistent store field.
pub struct CtapState<E: Env> {
    client_pin: ClientPin<E>,
    #[cfg(feature = "with_ctap1")]
    pub(crate) u2f_up_state: U2fUserPresenceState<E>,
    // The state initializes to Reset and its timeout, and never goes back to Reset.
    stateful_command_permission: StatefulPermission<E>,
}

impl<E: Env> CtapState<E> {
    pub fn new(env: &mut E) -> Self {
        storage::init(env).ok().unwrap();
        let client_pin = ClientPin::new(env);
        let stateful_command_permission = if env.boots_after_soft_reset() {
            StatefulPermission::default()
        } else {
            StatefulPermission::new_reset(env)
        };
        CtapState {
            client_pin,
            #[cfg(feature = "with_ctap1")]
            u2f_up_state: U2fUserPresenceState::new(),
            stateful_command_permission,
        }
    }

    pub fn increment_global_signature_counter(&mut self, env: &mut E) -> CtapResult<()> {
        if env.customization().use_signature_counter() {
            let increment = env.rng().next_u32() % 8 + 1;
            env.persist().incr_global_signature_counter(increment)?;
        }
        Ok(())
    }

    // Returns whether CTAP1 commands are currently supported.
    // If alwaysUv is enabled and the authenticator does not support internal UV,
    // CTAP1 needs to be disabled.
    #[cfg(feature = "with_ctap1")]
    pub fn allows_ctap1(&self, env: &mut E) -> CtapResult<bool> {
        Ok(!storage::has_always_uv(env)?)
    }

    fn clear_other_channels(&mut self, channel: Channel) {
        // Correct behavior between CTAP1 and CTAP2 isn't defined yet. Just a guess.
        #[cfg(feature = "with_ctap1")]
        {
            // We create a block statement to wrap this assignment expression, because attributes
            // (like #[cfg]) are not supported on expressions.
            self.u2f_up_state = U2fUserPresenceState::new();
        }
        self.stateful_command_permission.clear_old_channels(channel);
    }

    /// Checks if the application has any timers running.
    pub fn can_sleep(&mut self, env: &mut E) -> bool {
        !self.client_pin.has_token(env)
            && self.stateful_command_permission.get_command(env).is_err()
    }

    pub fn process_command(
        &mut self,
        env: &mut E,
        command_cbor: &[u8],
        channel: Channel,
    ) -> Vec<u8> {
        if let Some(response) = env.process_vendor_command(command_cbor, channel) {
            self.clear_other_channels(channel);
            self.stateful_command_permission.clear();
            return response;
        }
        let cmd = Command::deserialize(command_cbor);
        debug_ctap!(env, "Received command: {:#?}", cmd);
        let response = cmd.and_then(|command| self.process_parsed_command(env, command, channel));
        debug_ctap!(env, "Sending response: {:#?}", response);
        match response {
            Ok(response_data) => {
                let mut response_vec = vec![Ctap2StatusCode::CTAP2_OK as u8];
                if let Some(value) = response_data.into() {
                    if cbor_write(value, &mut response_vec).is_err() {
                        response_vec = vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8];
                    }
                }
                response_vec
            }
            Err(error_code) => vec![error_code as u8],
        }
    }

    /// Processed a command after parsing from CBOR, returning its structured output.
    ///
    /// This function contains the logic of `parse_command`, minus all CBOR encoding and decoding.
    /// It should make command parsing easier to test.
    pub fn process_parsed_command(
        &mut self,
        env: &mut E,
        command: Command,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        // The auth token timeouts are checked once here, to make error codes consistent. If your
        // auth token hasn't timed out now, you can fully use it for this command.
        self.client_pin.update_timeouts(env);
        if !matches!(&command, Command::AuthenticatorGetInfo) {
            self.clear_other_channels(channel);
        }
        match (&command, self.stateful_command_permission.get_command(env)) {
            (Command::AuthenticatorGetNextAssertion, Ok(StatefulCommand::GetAssertion(_)))
            | (Command::AuthenticatorLargeBlobs(_), Ok(StatefulCommand::LargeBlob(_)))
            | (Command::AuthenticatorReset, Ok(StatefulCommand::Reset))
            // AuthenticatorGetInfo still allows Reset.
            | (Command::AuthenticatorGetInfo, Ok(StatefulCommand::Reset))
            // AuthenticatorSelection still allows Reset.
            | (Command::AuthenticatorSelection, Ok(StatefulCommand::Reset))
            // AuthenticatorMakeCredential is used like AuthenticatorSelection in 2.0.
            | (Command::AuthenticatorMakeCredential(_), Ok(StatefulCommand::Reset))
            // AuthenticatorCredentialManagement handles its subcommands later.
            | (
                Command::AuthenticatorCredentialManagement(_),
                Ok(StatefulCommand::EnumerateRps(_)),
            )
            | (
                Command::AuthenticatorCredentialManagement(_),
                Ok(StatefulCommand::EnumerateCredentials(_)),
            ) => (),
            (_, _) => self.stateful_command_permission.clear(),
        }
        match channel {
            Channel::MainHid(_) => self.process_fido_command(env, command, channel),
            #[cfg(feature = "vendor_hid")]
            Channel::VendorHid(_) => self.process_vendor_command(env, command),
        }
    }

    fn process_fido_command(
        &mut self,
        env: &mut E,
        command: Command,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        match command {
            Command::AuthenticatorMakeCredential(params) => {
                self.process_make_credential(env, params, channel)
            }
            Command::AuthenticatorGetAssertion(params) => {
                self.process_get_assertion(env, params, channel)
            }
            Command::AuthenticatorGetNextAssertion => self.process_get_next_assertion(env),
            Command::AuthenticatorGetInfo => self.process_get_info(env),
            Command::AuthenticatorClientPin(params) => {
                self.client_pin.process_command(env, params, channel)
            }
            Command::AuthenticatorReset => self.process_reset(env, channel),
            #[cfg(feature = "fingerprint")]
            Command::AuthenticatorBioEnrollment(params) => {
                process_bio_enrollment(env, &mut self.client_pin, params)
            }
            Command::AuthenticatorCredentialManagement(params) => process_credential_management(
                env,
                &mut self.stateful_command_permission,
                &mut self.client_pin,
                params,
                channel,
            ),
            Command::AuthenticatorSelection => self.process_selection(env, channel),
            Command::AuthenticatorLargeBlobs(params) => {
                let large_blob_state = self.stateful_command_permission.large_blob(env, channel);
                large_blob_state.process_command(env, &mut self.client_pin, params)
            }
            #[cfg(feature = "config_command")]
            Command::AuthenticatorConfig(params) => {
                process_config(env, &mut self.client_pin, params)
            }
        }
    }

    #[cfg(feature = "vendor_hid")]
    fn process_vendor_command(
        &mut self,
        env: &mut E,
        command: Command,
    ) -> CtapResult<ResponseData> {
        match command {
            Command::AuthenticatorGetInfo => self.process_get_info(env),
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND),
        }
    }

    fn pin_uv_auth_precheck(
        &mut self,
        env: &mut E,
        pin_uv_auth_param: &Option<Vec<u8>>,
        pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
        channel: Channel,
    ) -> CtapResult<()> {
        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                check_user_presence(env, channel)?;
                if env.persist().pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }
            pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
        }
        Ok(())
    }

    fn process_make_credential(
        &mut self,
        env: &mut E,
        make_credential_params: AuthenticatorMakeCredentialParameters,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        let AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
            enterprise_attestation,
        } = make_credential_params;

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, channel)?;

        // When more algorithms are supported, iterate and pick the first match.
        let cred_param = get_preferred_cred_param(&pub_key_cred_params)
            .ok_or(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
        let algorithm = cred_param.alg;

        let rp_id = rp.rp_id;
        let ep_att = if let Some(enterprise_attestation) = enterprise_attestation {
            let authenticator_mode = env
                .customization()
                .enterprise_attestation_mode()
                .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
            if !storage::enterprise_attestation(env)? {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
            }
            match (
                EnterpriseAttestationMode::try_from(enterprise_attestation)?,
                authenticator_mode,
            ) {
                (
                    EnterpriseAttestationMode::PlatformManaged,
                    EnterpriseAttestationMode::PlatformManaged,
                ) => true,
                _ => env.customization().is_enterprise_rp_id(&rp_id),
            }
        } else {
            false
        };

        // MakeCredential always requires user presence.
        // User verification depends on the PIN auth inputs, which are checked here.
        // The ED flag is added later, if applicable.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if env.persist().pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                self.client_pin.verify_pin_uv_auth_token(
                    &client_data_hash,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                self.client_pin
                    .has_permission(PinPermission::MakeCredential)?;
                self.client_pin.check_user_verified_flag()?;
                // Checking for the correct permissions_rp_id is specified earlier.
                // Error codes are identical though, so the implementation can be identical with
                // GetAssertion.
                self.client_pin.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    #[cfg(not(feature = "fingerprint"))]
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                    // The specification says:
                    // If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED.
                    // But I assume this is a typo and should be UV_BLOCKED instead.
                    // https://github.com/fido-alliance/fido-2-specs/issues/1672
                    #[cfg(feature = "fingerprint")]
                    perform_built_in_uv(env, channel, true)?;
                    #[cfg(feature = "fingerprint")]
                    UV_FLAG
                } else {
                    if storage::has_always_uv(env)? {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                    }
                    // Corresponds to makeCredUvNotRqd set to true.
                    if options.rk && env.persist().pin_hash()?.is_some() {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                    }
                    0x00
                }
            }
        };
        flags |= UP_FLAG | AT_FLAG;

        let rp_id_hash = Sha::<E>::digest(rp_id.as_bytes());
        if let Some(exclude_list) = exclude_list {
            for cred_desc in exclude_list {
                if filter_listed_resident_credential(
                    storage::find_credential(env, &rp_id, &cred_desc.key_id)?,
                    has_uv,
                )
                .is_some()
                    || filter_listed_credential(
                        env.key_store()
                            .unwrap_credential(&cred_desc.key_id, &rp_id_hash)?,
                        has_uv,
                    )
                    .is_some()
                {
                    // Perform this check, so bad actors can't brute force exclude_list
                    // without user interaction.
                    let _ = check_user_presence(env, channel);
                    return Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        check_user_presence(env, channel)?;
        self.client_pin.clear_token_flags();

        let default_cred_protect = env.customization().default_cred_protect();
        let mut cred_protect_policy = extensions.cred_protect;
        if cred_protect_policy.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
            < default_cred_protect.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
        {
            cred_protect_policy = default_cred_protect;
        }
        let min_pin_length =
            extensions.min_pin_length && storage::min_pin_length_rp_ids(env)?.contains(&rp_id);
        // None for no input, false for invalid input, true for valid input.
        let has_cred_blob_output = extensions.cred_blob.is_some();
        let cred_blob = extensions
            .cred_blob
            .filter(|c| c.len() <= env.customization().max_cred_blob_length());
        let cred_blob_output = if has_cred_blob_output {
            Some(cred_blob.is_some())
        } else {
            None
        };
        let has_extension_output = extensions.hmac_secret
            || extensions.cred_protect.is_some()
            || min_pin_length
            || has_cred_blob_output;
        if has_extension_output {
            flags |= ED_FLAG
        };
        let large_blob_key = match (options.rk, extensions.large_blob_key) {
            (true, Some(true)) => Some(env.rng().gen_uniform_u8x32().to_vec()),
            _ => None,
        };

        // We decide on the algorithm early, but delay key creation since it takes time.
        // We rather do that later so all intermediate checks may return faster.
        let private_key = PrivateKey::new(env, algorithm);
        let credential_id = if options.rk {
            let random_id = env.rng().gen_uniform_u8x32().to_vec();
            let credential_source = PublicKeyCredentialSource {
                key_type: PublicKeyCredentialType::PublicKey,
                credential_id: random_id.clone(),
                private_key: private_key.clone(),
                rp_id,
                user_handle: user.user_id,
                // This input is user provided, so we crop it to 64 byte for storage.
                // The UTF8 encoding is always preserved, so the string might end up shorter.
                user_display_name: user
                    .user_display_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_protect_policy,
                creation_order: storage::new_creation_order(env)?,
                user_name: user
                    .user_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                user_icon: user
                    .user_icon
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_blob,
                large_blob_key: large_blob_key.clone(),
            };
            storage::store_credential(env, credential_source)?;
            random_id
        } else {
            let credential_source = CredentialSource {
                private_key: private_key.clone(),
                rp_id_hash,
                cred_protect_policy,
                cred_blob,
            };
            env.key_store()
                .wrap_credential(credential_source)
                .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?
        };

        let mut auth_data = self.generate_auth_data(env, &rp_id_hash, flags)?;
        auth_data.extend(env.customization().aaguid());
        // The length is fixed to 0x20 or 0x80 and fits one byte.
        if credential_id.len() > 0xFF {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        auth_data.extend(vec![0x00, credential_id.len() as u8]);
        auth_data.extend(&credential_id);
        let public_cose_key = private_key.get_pub_key::<E>()?;
        cbor_write(cbor::Value::from(public_cose_key), &mut auth_data)?;
        if has_extension_output {
            let hmac_secret_output = if extensions.hmac_secret {
                Some(true)
            } else {
                None
            };
            let min_pin_length_output = if min_pin_length {
                Some(storage::min_pin_length(env)? as u64)
            } else {
                None
            };
            let cred_protect_output = extensions.cred_protect.and(cred_protect_policy);
            let extensions_output = cbor_map_options! {
                "credBlob" => cred_blob_output,
                "credProtect" => cred_protect_output,
                "hmac-secret" => hmac_secret_output,
                "minPinLength" => min_pin_length_output,
            };
            cbor_write(extensions_output, &mut auth_data)?;
        }

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);

        let attestation_id = if ep_att {
            Some(AttestationId::Enterprise)
        } else if env.customization().use_batch_attestation() {
            Some(AttestationId::Batch)
        } else {
            None
        };
        let (signature, x5c) = match attestation_id {
            Some(id) => {
                let Attestation {
                    private_key,
                    certificate,
                } = env
                    .persist()
                    .get_attestation(id)?
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let attestation_key = EcdsaSk::<E>::from_slice(&private_key).unwrap();
                (
                    attestation_key.sign(&signature_data).to_der(),
                    Some(vec![certificate]),
                )
            }
            None => (private_key.sign_and_encode::<E>(&signature_data)?, None),
        };
        let attestation_statement = PackedAttestationStatement {
            alg: SignatureAlgorithm::Es256 as i64,
            sig: signature,
            x5c,
            ecdaa_key_id: None,
        };
        let ep_att = if ep_att { Some(true) } else { None };
        Ok(ResponseData::AuthenticatorMakeCredential(
            AuthenticatorMakeCredentialResponse {
                fmt: String::from("packed"),
                auth_data,
                att_stmt: attestation_statement,
                ep_att,
                large_blob_key,
            },
        ))
    }

    // Generates a different per-credential secret for each UV mode.
    // The computation is deterministic, and private_key expected to be unique.
    fn generate_cred_random(
        &mut self,
        env: &mut E,
        private_key: &PrivateKey,
        has_uv: bool,
    ) -> CtapResult<Secret<[u8; HASH_SIZE]>> {
        let private_key_bytes = private_key.to_bytes();
        let salt = array_ref!(private_key_bytes, 0, 32);
        let key = env.key_store().cred_random(has_uv)?;
        let mut output = Secret::default();
        Hkdf::<E>::hkdf_256(&*key, salt, b"credRandom", &mut output);
        Ok(output)
    }

    // Processes the input of a get_assertion operation for a given credential
    // and returns the correct Get(Next)Assertion response.
    fn assertion_response(
        &mut self,
        env: &mut E,
        mut credential: PublicKeyCredentialSource,
        assertion_input: AssertionInput,
        number_of_credentials: Option<usize>,
        is_next: bool,
    ) -> CtapResult<ResponseData> {
        let AssertionInput {
            client_data_hash,
            mut auth_data,
            extensions,
            has_uv,
        } = assertion_input;

        // Process extensions.
        if extensions.hmac_secret.is_some() || extensions.cred_blob {
            let encrypted_output = if let Some(hmac_secret_input) = extensions.hmac_secret {
                let cred_random =
                    self.generate_cred_random(env, &credential.private_key, has_uv)?;
                Some(
                    self.client_pin
                        .process_hmac_secret(env, hmac_secret_input, &cred_random)?,
                )
            } else {
                None
            };
            // This could be written more nicely with `then_some` when stable.
            let cred_blob = if extensions.cred_blob {
                Some(credential.cred_blob.unwrap_or_default())
            } else {
                None
            };
            let extensions_output = cbor_map_options! {
                "credBlob" => cred_blob,
                "hmac-secret" => encrypted_output,
            };
            cbor_write(extensions_output, &mut auth_data)?;
        }
        let large_blob_key = match extensions.large_blob_key {
            Some(true) => credential.large_blob_key,
            _ => None,
        };

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);
        let signature = credential
            .private_key
            .sign_and_encode::<E>(&signature_data)?;

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential.credential_id,
            transports: None, // You can set USB as a hint here.
        };
        // Remove user identifiable information without uv.
        if !has_uv {
            credential.user_name = None;
            credential.user_display_name = None;
            credential.user_icon = None;
        }
        let user = if !credential.user_handle.is_empty() {
            Some(PublicKeyCredentialUserEntity {
                user_id: credential.user_handle,
                user_name: credential.user_name,
                user_display_name: credential.user_display_name,
                user_icon: credential.user_icon,
            })
        } else {
            None
        };
        let response_data = AuthenticatorGetAssertionResponse {
            credential: Some(cred_desc),
            auth_data,
            signature,
            user,
            number_of_credentials: number_of_credentials.map(|n| n as u64),
            large_blob_key,
        };
        // Only returned for the first GetAssertion, not for Next calls.
        if is_next {
            Ok(ResponseData::AuthenticatorGetNextAssertion(response_data))
        } else {
            Ok(ResponseData::AuthenticatorGetAssertion(response_data))
        }
    }

    // Returns the first applicable credential from the allow list.
    fn get_any_credential_from_allow_list(
        &mut self,
        env: &mut E,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        rp_id: &str,
        rp_id_hash: &[u8],
        has_uv: bool,
    ) -> CtapResult<Option<PublicKeyCredentialSource>> {
        for allowed_credential in allow_list {
            let credential = filter_listed_resident_credential(
                storage::find_credential(env, rp_id, &allowed_credential.key_id)?,
                has_uv,
            );
            if credential.is_some() {
                return Ok(credential);
            }
            let credential = filter_listed_credential(
                env.key_store()
                    .unwrap_credential(&allowed_credential.key_id, rp_id_hash)?,
                has_uv,
            );
            if credential.is_some() {
                return Ok(credential.map(|c| to_public_source(allowed_credential.key_id, c)));
            }
        }
        Ok(None)
    }

    fn process_get_assertion(
        &mut self,
        env: &mut E,
        get_assertion_params: AuthenticatorGetAssertionParameters,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        let AuthenticatorGetAssertionParameters {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        } = get_assertion_params;

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, channel)?;

        if extensions.hmac_secret.is_some() && !options.up {
            // The extension is actually supported, but we need user presence.
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_OPTION);
        }

        // The user verification bit depends on the existance of PIN auth, since we do
        // not support internal UV. User presence is requested as an option.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if env.persist().pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                self.client_pin.verify_pin_uv_auth_token(
                    &client_data_hash,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                self.client_pin
                    .has_permission(PinPermission::GetAssertion)?;
                // Checking for the UV flag is specified earlier for GetAssertion.
                // Error codes are identical though, so the implementation can be identical with
                // MakeCredential.
                self.client_pin.check_user_verified_flag()?;
                self.client_pin.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    #[cfg(not(feature = "fingerprint"))]
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                    // Same error code ambiguity as in MakeCredential.
                    // https://github.com/fido-alliance/fido-2-specs/issues/1672
                    #[cfg(feature = "fingerprint")]
                    perform_built_in_uv(env, channel, true)?;
                    #[cfg(feature = "fingerprint")]
                    UV_FLAG
                } else {
                    if options.up && storage::has_always_uv(env)? {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                    }
                    0x00
                }
            }
        };

        if options.up {
            flags |= UP_FLAG;
        }
        if extensions.hmac_secret.is_some() || extensions.cred_blob {
            flags |= ED_FLAG;
        }

        let rp_id_hash = Sha::<E>::digest(rp_id.as_bytes());
        let (credential, next_credential_keys) = if let Some(allow_list) = allow_list {
            (
                self.get_any_credential_from_allow_list(
                    env,
                    allow_list,
                    &rp_id,
                    &rp_id_hash,
                    has_uv,
                )?,
                vec![],
            )
        } else {
            let mut iter_result = Ok(());
            let iter = storage::iter_credentials(env, &mut iter_result)?;
            let mut stored_credentials: Vec<(usize, u64)> = iter
                .filter_map(|(key, credential)| {
                    if credential.rp_id == rp_id && (has_uv || credential.is_discoverable()) {
                        Some((key, credential.creation_order))
                    } else {
                        None
                    }
                })
                .collect();
            iter_result?;
            stored_credentials.sort_unstable_by_key(|&(_key, order)| order);
            let mut stored_credentials: Vec<usize> = stored_credentials
                .into_iter()
                .map(|(key, _order)| key)
                .collect();
            let credential = stored_credentials
                .pop()
                .map(|key| storage::get_credential(env, key))
                .transpose()?;
            (credential, stored_credentials)
        };

        let credential = credential.ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;

        // This check comes before CTAP2_ERR_NO_CREDENTIALS in CTAP 2.0.
        if options.up {
            check_user_presence(env, channel)?;
            self.client_pin.clear_token_flags();
        }

        self.increment_global_signature_counter(env)?;

        let assertion_input = AssertionInput {
            client_data_hash,
            auth_data: self.generate_auth_data(env, &rp_id_hash, flags)?,
            extensions,
            has_uv,
        };
        let number_of_credentials = if next_credential_keys.is_empty() {
            None
        } else {
            let number_of_credentials = Some(next_credential_keys.len() + 1);
            let assertion_state = StatefulCommand::GetAssertion(Box::new(AssertionState {
                assertion_input: assertion_input.clone(),
                next_credential_keys,
            }));
            self.stateful_command_permission
                .set_command(env, assertion_state, channel);
            number_of_credentials
        };
        self.assertion_response(
            env,
            credential,
            assertion_input,
            number_of_credentials,
            false,
        )
    }

    fn process_get_next_assertion(&mut self, env: &mut E) -> CtapResult<ResponseData> {
        let (assertion_input, credential_key) = self
            .stateful_command_permission
            .next_assertion_credential(env)?;
        let credential = storage::get_credential(env, credential_key)?;
        self.assertion_response(env, credential, assertion_input, None, true)
    }

    fn process_get_info(&self, env: &mut E) -> CtapResult<ResponseData> {
        let has_always_uv = storage::has_always_uv(env)?;
        #[cfg_attr(not(feature = "with_ctap1"), allow(unused_mut))]
        let mut versions = vec![
            String::from(FIDO2_VERSION_STRING),
            String::from(FIDO2_1_VERSION_STRING),
        ];
        #[cfg(feature = "with_ctap1")]
        if !has_always_uv {
            versions.insert(0, String::from(U2F_VERSION_STRING))
        }
        let mut options = vec![
            (String::from("rk"), true),
            (
                String::from("clientPin"),
                env.persist().pin_hash()?.is_some(),
            ),
            (String::from("up"), true),
            (String::from("pinUvAuthToken"), true),
            (String::from("largeBlobs"), true),
            #[cfg(feature = "config_command")]
            (String::from("authnrCfg"), true),
            #[cfg(feature = "config_command")]
            (String::from("uvAcfg"), true),
            (String::from("credMgmt"), true),
            #[cfg(feature = "config_command")]
            (String::from("setMinPINLength"), true),
            (String::from("makeCredUvNotRqd"), !has_always_uv),
            (String::from("alwaysUv"), has_always_uv),
        ];
        #[cfg(feature = "fingerprint")]
        {
            let has_fingerprint = !env.persist().template_infos()?.is_empty();
            options.push((String::from("uv"), has_fingerprint));
            options.push((String::from("bioEnroll"), has_fingerprint));
        }
        if env.customization().enterprise_attestation_mode().is_some() {
            options.push((String::from("ep"), storage::enterprise_attestation(env)?));
        }
        let mut pin_protocols = vec![PinUvAuthProtocol::V2 as u64];
        if env.customization().allows_pin_protocol_v1() {
            pin_protocols.push(PinUvAuthProtocol::V1 as u64);
        }

        Ok(ResponseData::AuthenticatorGetInfo(
            AuthenticatorGetInfoResponse {
                versions,
                extensions: Some(vec![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ]),
                aaguid: *env.customization().aaguid(),
                options: Some(options),
                max_msg_size: Some(env.customization().max_msg_size() as u64),
                // The order implies preference. We favor the new V2.
                pin_protocols: Some(pin_protocols),
                max_credential_count_in_list: env
                    .customization()
                    .max_credential_count_in_list()
                    .map(|c| c as u64),
                max_credential_id_length: Some(MAX_CREDENTIAL_ID_SIZE as u64),
                transports: Some(vec![AuthenticatorTransport::Usb]),
                algorithms: Some(SUPPORTED_CRED_PARAMS.to_vec()),
                max_serialized_large_blob_array: Some(
                    env.customization().max_large_blob_array_size() as u64,
                ),
                force_pin_change: Some(env.persist().has_force_pin_change()?),
                min_pin_length: storage::min_pin_length(env)?,
                firmware_version: env.firmware_version(),
                max_cred_blob_length: Some(env.customization().max_cred_blob_length() as u64),
                max_rp_ids_for_set_min_pin_length: Some(
                    env.customization().max_rp_ids_length() as u64
                ),
                #[cfg(feature = "fingerprint")]
                preferred_platform_uv_attempts: Some(
                    env.customization().preferred_platform_uv_attempts() as u64,
                ),
                #[cfg(not(feature = "fingerprint"))]
                preferred_platform_uv_attempts: None,
                // https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods
                #[cfg(feature = "fingerprint")]
                uv_modality: Some(0x02),
                #[cfg(not(feature = "fingerprint"))]
                uv_modality: None,
                certifications: None,
                remaining_discoverable_credentials: Some(
                    storage::remaining_credentials(env)? as u64
                ),
            },
        ))
    }

    fn process_reset(&mut self, env: &mut E, channel: Channel) -> CtapResult<ResponseData> {
        if !matches!(
            self.stateful_command_permission.get_command(env)?,
            StatefulCommand::Reset
        ) {
            return Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED);
        }
        check_user_presence(env, channel)?;

        reset(env)?;
        self.client_pin.reset(env);

        #[cfg(feature = "fingerprint")]
        {
            let template_infos = env.persist().template_infos()?;
            for template_info in template_infos {
                env.fingerprint()
                    .remove_enrollment(&template_info.template_id)?;
                env.persist()
                    .remove_template_id(&template_info.template_id)?;
            }
        }

        #[cfg(feature = "with_ctap1")]
        {
            // We create a block statement to wrap this assignment expression, because attributes
            // (like #[cfg]) are not supported on expressions.
            self.u2f_up_state = U2fUserPresenceState::new();
        }
        Ok(ResponseData::AuthenticatorReset)
    }

    fn process_selection(&self, env: &mut E, channel: Channel) -> CtapResult<ResponseData> {
        check_user_presence(env, channel)?;
        Ok(ResponseData::AuthenticatorSelection)
    }

    pub fn generate_auth_data(
        &self,
        env: &mut E,
        rp_id_hash: &[u8],
        flag_byte: u8,
    ) -> CtapResult<Vec<u8>> {
        let mut auth_data = vec![];
        auth_data.extend(rp_id_hash);
        auth_data.push(flag_byte);
        // The global counter is only increased if use_signature_counter() is true.
        // It uses a big-endian representation.
        let mut signature_counter = [0u8; 4];
        BigEndian::write_u32(
            &mut signature_counter,
            env.persist().global_signature_counter()?,
        );
        auth_data.extend(&signature_counter);
        Ok(auth_data)
    }

    #[cfg(feature = "with_ctap1")]
    pub fn u2f_grant_user_presence(&mut self, env: &mut E) {
        self.u2f_up_state.grant_up(env)
    }

    #[cfg(feature = "with_ctap1")]
    pub fn u2f_needs_user_presence(&mut self, env: &mut E) -> bool {
        self.u2f_up_state.is_up_needed(env)
    }
}

#[cfg(test)]
mod test {
    use super::client_pin::PIN_TOKEN_LENGTH;
    use super::command::{
        AuthenticatorClientPinParameters, AuthenticatorCredentialManagementParameters,
    };
    use super::data_formats::{
        ClientPinSubCommand, CoseKey, CredentialManagementSubCommand, GetAssertionHmacSecretInput,
        GetAssertionOptions, MakeCredentialExtensions, MakeCredentialOptions, PinUvAuthProtocol,
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };
    use super::pin_protocol::{authenticate_pin_uv_auth_token, PinProtocol};
    use super::*;
    use crate::api::crypto::ecdh::SecretKey as _;
    use crate::api::customization;
    use crate::api::key_store::CBOR_CREDENTIAL_ID_SIZE;
    use crate::ctap::command::AuthenticatorLargeBlobsParameters;
    use crate::env::test::TestEnv;
    use crate::env::EcdhSk;
    use crate::test_helpers;
    use cbor::{cbor_array, cbor_array_vec, cbor_map};

    // The keep-alive logic in the processing of some commands needs a channel ID to send
    // keep-alive packets to.
    // In tests where we define a dummy user-presence check that immediately returns, the channel
    // ID is irrelevant, so we pass this (dummy but valid) value.
    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
    #[cfg(feature = "vendor_hid")]
    const VENDOR_CHANNEL: Channel = Channel::VendorHid([0x12, 0x34, 0x56, 0x78]);

    fn check_make_response(
        env: &mut impl Env,
        make_credential_response: &CtapResult<ResponseData>,
        flags: u8,
        expected_credential_id_size: u8,
        expected_extension_cbor: &[u8],
    ) {
        let expected_aaguid = env.customization().aaguid();
        let signature_counter = env.persist().global_signature_counter().unwrap();
        match make_credential_response.as_ref().unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let AuthenticatorMakeCredentialResponse {
                    fmt,
                    auth_data,
                    att_stmt,
                    ep_att,
                    large_blob_key,
                } = make_credential_response;
                // The expected response is split to only assert the non-random parts.
                assert_eq!(fmt, "packed");
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, flags,
                ];
                expected_auth_data.extend(&signature_counter.to_be_bytes());
                expected_auth_data.extend(expected_aaguid);
                expected_auth_data.extend(&[0x00, expected_credential_id_size]);
                assert_eq!(
                    auth_data[0..expected_auth_data.len()],
                    expected_auth_data[..]
                );
                assert_eq!(
                    &auth_data[auth_data.len() - expected_extension_cbor.len()..auth_data.len()],
                    expected_extension_cbor
                );
                assert!(ep_att.is_none());
                assert_eq!(att_stmt.alg, SignatureAlgorithm::Es256 as i64);
                assert_eq!(large_blob_key, &None);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_get_info() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let info_reponse = ctap_state.process_command(&mut env, &[0x04], DUMMY_CHANNEL);

        // Fails when removing `to_vec` for `SUPPORTED_CRED_PARAMS` as linted.
        #[allow(clippy::unnecessary_to_owned)]
        let expected_cbor = cbor_map_options! {
             0x01 => cbor_array_vec![vec![
                    #[cfg(feature = "with_ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                ]],
            0x02 => cbor_array![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ],
            0x03 => env.customization().aaguid(),
            0x04 => cbor_map_options! {
                "ep" => env.customization().enterprise_attestation_mode().map(|_| false),
                "rk" => true,
                "up" => true,
                "uv" => false,
                #[cfg(feature = "config_command")]
                "uvAcfg" => true,
                #[cfg(feature = "config_command")]
                "alwaysUv" => false,
                "credMgmt" => true,
                #[cfg(feature = "config_command")]
                "authnrCfg" => true,
                "bioEnroll" => false,
                "clientPin" => false,
                "largeBlobs" => true,
                "pinUvAuthToken" => true,
                #[cfg(feature = "config_command")]
                "setMinPINLength" => true,
                "makeCredUvNotRqd" => true,
            },
            0x05 => env.customization().max_msg_size() as u64,
            0x06 => cbor_array![2, 1],
            0x07 => env.customization().max_credential_count_in_list().map(|c| c as u64),
            0x08 => MAX_CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array!["usb"],
            0x0A => cbor_array_vec!(SUPPORTED_CRED_PARAMS.to_vec()),
            0x0B => env.customization().max_large_blob_array_size() as u64,
            0x0C => false,
            0x0D => storage::min_pin_length(&mut env).unwrap() as u64,
            0x0E => 0,
            0x0F => env.customization().max_cred_blob_length() as u64,
            0x10 => env.customization().max_rp_ids_length() as u64,
            0x11 => env.customization().preferred_platform_uv_attempts() as u64,
            0x12 => 0x02,
            0x14 => storage::remaining_credentials(&mut env).unwrap() as u64,
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor_write(expected_cbor, &mut response_cbor).is_ok());
        assert_eq!(info_reponse, response_cbor);
    }

    #[test]
    #[cfg(not(feature = "fingerprint"))]
    fn test_get_info() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let info_reponse = ctap_state.process_command(&mut env, &[0x04], DUMMY_CHANNEL);

        // Fails when removing `to_vec` for `SUPPORTED_CRED_PARAMS` as linted.
        #[allow(clippy::unnecessary_to_owned)]
        let expected_cbor = cbor_map_options! {
             0x01 => cbor_array_vec![vec![
                    #[cfg(feature = "with_ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                ]],
            0x02 => cbor_array![
                    String::from("hmac-secret"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                ],
            0x03 => env.customization().aaguid(),
            0x04 => cbor_map_options! {
                "ep" => env.customization().enterprise_attestation_mode().map(|_| false),
                "rk" => true,
                "up" => true,
                #[cfg(feature = "config_command")]
                "uvAcfg" => true,
                #[cfg(feature = "config_command")]
                "alwaysUv" => false,
                "credMgmt" => true,
                #[cfg(feature = "config_command")]
                "authnrCfg" => true,
                "clientPin" => false,
                "largeBlobs" => true,
                "pinUvAuthToken" => true,
                #[cfg(feature = "config_command")]
                "setMinPINLength" => true,
                "makeCredUvNotRqd" => true,
            },
            0x05 => env.customization().max_msg_size() as u64,
            0x06 => cbor_array![2, 1],
            0x07 => env.customization().max_credential_count_in_list().map(|c| c as u64),
            0x08 => MAX_CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array!["usb"],
            0x0A => cbor_array_vec!(SUPPORTED_CRED_PARAMS.to_vec()),
            0x0B => env.customization().max_large_blob_array_size() as u64,
            0x0C => false,
            0x0D => storage::min_pin_length(&mut env).unwrap() as u64,
            0x0E => 0,
            0x0F => env.customization().max_cred_blob_length() as u64,
            0x10 => env.customization().max_rp_ids_length() as u64,
            0x14 => storage::remaining_credentials(&mut env).unwrap() as u64,
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor_write(expected_cbor, &mut response_cbor).is_ok());
        assert_eq!(info_reponse, response_cbor);
    }

    #[test]
    fn test_get_info_no_pin_protocol_v1() {
        let mut env = TestEnv::default();
        env.customization_mut().set_allows_pin_protocol_v1(false);
        let ctap_state = CtapState::new(&mut env);
        let info_response = ctap_state.process_get_info(&mut env).unwrap();
        match info_response {
            ResponseData::AuthenticatorGetInfo(response) => {
                assert_eq!(
                    response.pin_protocols,
                    Some(vec![PinUvAuthProtocol::V2 as u64])
                );
            }
            _ => panic!("Invalid response type"),
        }
    }

    fn create_minimal_make_credential_parameters() -> AuthenticatorMakeCredentialParameters {
        let client_data_hash = vec![0xCD];
        let rp = PublicKeyCredentialRpEntity {
            rp_id: String::from("example.com"),
            rp_name: None,
            rp_icon: None,
        };
        let user = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D],
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        let pub_key_cred_params = vec![ES256_CRED_PARAM];
        let options = MakeCredentialOptions {
            rk: true,
            uv: false,
        };
        AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list: None,
            extensions: MakeCredentialExtensions::default(),
            options,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
        }
    }

    fn create_make_credential_parameters_with_exclude_list(
        excluded_credential_id: &[u8],
    ) -> AuthenticatorMakeCredentialParameters {
        let excluded_credential_descriptor = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: excluded_credential_id.to_vec(),
            transports: None,
        };
        let exclude_list = Some(vec![excluded_credential_descriptor]);
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.exclude_list = exclude_list;
        make_credential_params
    }

    fn create_make_credential_parameters_with_cred_protect_policy(
        policy: CredentialProtectionPolicy,
    ) -> AuthenticatorMakeCredentialParameters {
        let extensions = MakeCredentialExtensions {
            cred_protect: Some(policy),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params
    }

    fn parse_credential_id_from_non_resident_make_credential_response(
        env: &mut impl Env,
        make_credential_response: ResponseData,
    ) -> Vec<u8> {
        match make_credential_response {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let auth_data = make_credential_response.auth_data;
                let offset = 37 + env.customization().aaguid().len();
                assert_eq!(auth_data[offset], 0x00);
                assert_eq!(auth_data[offset + 1] as usize, CBOR_CREDENTIAL_ID_SIZE);
                auth_data[offset + 2..offset + 2 + CBOR_CREDENTIAL_ID_SIZE].to_vec()
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_resident_process_make_credential() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(&mut env, &make_credential_response, 0x41, 0x20, &[]);
    }

    #[test]
    fn test_non_resident_process_make_credential() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &mut env,
            &make_credential_response,
            0x41,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_process_make_credential_unsupported_algorithm() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pub_key_cred_params = vec![];
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_process_make_credential_credential_excluded() {
        let mut env = TestEnv::default();
        let excluded_private_key = PrivateKey::new_ecdsa(&mut env);
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let excluded_credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&excluded_credential_id);
        let excluded_credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: excluded_credential_id,
            private_key: excluded_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, excluded_credential_source).is_ok());

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );
    }

    #[test]
    fn test_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_non_resident_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_process_make_credential_hmac_secret() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_hmac_secret_resident_key() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_min_pin_length() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // First part: The extension is ignored, since the RP ID is not on the list.
        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_make_response(&mut env, &make_credential_response, 0x41, 0x20, &[]);

        // Second part: The extension is used.
        assert_eq!(
            storage::set_min_pin_length_rp_ids(&mut env, vec!["example.com".to_string()]),
            Ok(())
        );

        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x6C, 0x6D, 0x69, 0x6E, 0x50, 0x69, 0x6E, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68,
            0x04,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_cred_blob_ok() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, Some(vec![0xCB]));
    }

    #[test]
    fn test_process_make_credential_cred_blob_too_big() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB; env.customization().max_cred_blob_length() + 1]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF4,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, None);
    }

    #[test]
    fn test_process_make_credential_large_blob_key() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let large_blob_key = match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                make_credential_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key.len(), 32);

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.large_blob_key.unwrap(), large_blob_key);
    }

    fn test_helper_process_make_credential_with_pin_and_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        ctap_state.client_pin = client_pin;
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let client_data_hash = [0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.uv = true;
        make_credential_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        make_credential_params.pin_uv_auth_protocol = Some(pin_uv_auth_protocol);
        let make_credential_response = ctap_state.process_make_credential(
            &mut env,
            make_credential_params.clone(),
            DUMMY_CHANNEL,
        );

        check_make_response(&mut env, &make_credential_response, 0x45, 0x20, &[]);

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        )
    }

    #[test]
    fn test_process_make_credential_with_pin_and_uv_v1() {
        test_helper_process_make_credential_with_pin_and_uv(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_make_credential_with_pin_and_uv_v2() {
        test_helper_process_make_credential_with_pin_and_uv(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_non_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &mut env,
            &make_credential_response,
            0x41,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );
    }

    #[test]
    fn test_process_make_credential_with_pin_always_uv() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        storage::toggle_always_uv(&mut env).unwrap();
        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );

        env.persist().set_pin(&[0x88; 16], 4).unwrap();
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pin_uv_auth_param = Some(vec![0xA4; 16]);
        make_credential_params.pin_uv_auth_protocol = Some(PinUvAuthProtocol::V1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    fn check_ep(make_credential_response: CtapResult<ResponseData>, has_ep: bool) {
        let ep_att = if has_ep { Some(true) } else { None };
        match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                assert_eq!(make_credential_response.ep_att, ep_att);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_vendor_facilitated() {
        let mut env = TestEnv::default();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::VendorFacilitated),
            Some(vec!["example.com".to_string()]),
        );

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_platform_managed() {
        let mut env = TestEnv::default();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::PlatformManaged),
            Some(vec!["example.com".to_string()]),
        );
        assert!(customization::is_valid(env.customization()));

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_invalid() {
        let mut env = TestEnv::default();
        env.customization_mut()
            .setup_enterprise_attestation(Some(EnterpriseAttestationMode::PlatformManaged), None);

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(3);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );
    }

    #[test]
    fn test_process_make_credential_cancelled() {
        let mut env = TestEnv::default();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    fn check_assertion_response_with_user(
        response: CtapResult<ResponseData>,
        expected_user: Option<PublicKeyCredentialUserEntity>,
        flags: u8,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let assertion_response = match response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(r) => r,
            ResponseData::AuthenticatorGetNextAssertion(r) => r,
            _ => panic!("Invalid response type"),
        };
        let AuthenticatorGetAssertionResponse {
            auth_data,
            user,
            number_of_credentials,
            ..
        } = assertion_response;
        let mut expected_auth_data = vec![
            0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34,
            0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55,
            0x86, 0xCE, 0x19, 0x47, flags, 0x00, 0x00, 0x00, 0x00,
        ];
        let signature_counter_position = expected_auth_data.len() - 4;
        BigEndian::write_u32(
            &mut expected_auth_data[signature_counter_position..],
            signature_counter,
        );
        expected_auth_data.extend(expected_extension_cbor);
        assert_eq!(auth_data, expected_auth_data);
        assert_eq!(user, expected_user);
        assert_eq!(number_of_credentials, expected_number_of_credentials);
    }

    fn check_assertion_response_with_extension(
        response: CtapResult<ResponseData>,
        expected_user_id: Option<Vec<u8>>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let expected_user = expected_user_id.map(|user_id| PublicKeyCredentialUserEntity {
            user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        });
        check_assertion_response_with_user(
            response,
            expected_user,
            0x80,
            signature_counter,
            expected_number_of_credentials,
            expected_extension_cbor,
        );
    }

    fn check_assertion_response(
        response: CtapResult<ResponseData>,
        expected_user_id: Vec<u8>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
    ) {
        let expected_user = PublicKeyCredentialUserEntity {
            user_id: expected_user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        check_assertion_response_with_user(
            response,
            Some(expected_user),
            0x00,
            signature_counter,
            expected_number_of_credentials,
            &[],
        );
    }

    #[test]
    fn test_resident_process_get_assertion() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);
    }

    fn get_assertion_hmac_secret_params(
        key_agreement_key: EcdhSk<TestEnv>,
        key_agreement_response: ResponseData,
        credential_id: Option<Vec<u8>>,
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> AuthenticatorGetAssertionParameters {
        let mut env = TestEnv::default();
        let platform_public_key = key_agreement_key.public_key();
        let public_key = match key_agreement_response {
            ResponseData::AuthenticatorClientPin(Some(client_pin_response)) => {
                client_pin_response.key_agreement.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        let pin_protocol = PinProtocol::<TestEnv>::new_test(key_agreement_key, [0x91; 32]);
        let shared_secret = pin_protocol
            .decapsulate(public_key, pin_uv_auth_protocol)
            .unwrap();

        let salt = vec![0x01; 32];
        let salt_enc = shared_secret.encrypt(&mut env, &salt).unwrap();
        let salt_auth = shared_secret.authenticate(&salt_enc);
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from_ecdh_public_key(platform_public_key),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        };
        let get_extensions = GetAssertionExtensions {
            hmac_secret: Some(hmac_secret_input),
            ..Default::default()
        };

        let credential_descriptor = credential_id.map(|key_id| PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id,
            transports: None,
        });
        let allow_list = credential_descriptor.map(|c| vec![c]);
        AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list,
            extensions: get_extensions,
            options: GetAssertionOptions {
                up: true,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        }
    }

    fn test_helper_process_get_assertion_hmac_secret(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = make_extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response =
            ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, DUMMY_CHANNEL);
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            Some(credential_id),
            pin_uv_auth_protocol,
        );
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());
    }

    #[test]
    fn test_process_get_assertion_hmac_secret_v1() {
        test_helper_process_get_assertion_hmac_secret(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_assertion_hmac_secret_v2() {
        test_helper_process_get_assertion_hmac_secret(PinUvAuthProtocol::V2);
    }

    fn test_helper_resident_process_get_assertion_hmac_secret(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = make_extensions;
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response =
            ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, DUMMY_CHANNEL);
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            None,
            pin_uv_auth_protocol,
        );
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());
    }

    #[test]
    fn test_process_resident_get_assertion_hmac_secret_v1() {
        test_helper_resident_process_get_assertion_hmac_secret(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_resident_process_get_assertion_hmac_secret_v2() {
        test_helper_resident_process_get_assertion_hmac_secret(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_resident_process_get_assertion_with_cred_protect() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id.clone(),
            transports: None,
        };
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: credential_id.clone(),
            private_key: private_key.clone(),
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: Some(
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            ),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc.clone()]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationRequired),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_non_resident_process_get_assertion_with_cred_protect() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_process_get_assertion_with_cred_blob() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: Some(vec![0xCB]),
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let extensions = GetAssertionExtensions {
            cred_blob: true,
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            Some(vec![0x1D]),
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_non_resident_process_get_assertion_with_cred_blob() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );

        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let extensions = GetAssertionExtensions {
            cred_blob: true,
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            None,
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_get_assertion_with_large_blob_key() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: Some(vec![0x1C; 32]),
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let extensions = GetAssertionExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let large_blob_key = match get_assertion_response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(get_assertion_response) => {
                get_assertion_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key, vec![0x1C; 32]);
    }

    fn test_helper_process_get_next_assertion_two_credentials_with_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x88; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user1 = PublicKeyCredentialUserEntity {
            user_id: vec![0x01],
            user_name: Some("user1".to_string()),
            user_display_name: Some("User One".to_string()),
            user_icon: Some("icon1".to_string()),
        };
        make_credential_params.user = user1.clone();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user2 = PublicKeyCredentialUserEntity {
            user_id: vec![0x02],
            user_name: Some("user2".to_string()),
            user_display_name: Some("User Two".to_string()),
            user_icon: Some("icon2".to_string()),
        };
        make_credential_params.user = user2.clone();
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        ctap_state.client_pin = client_pin;
        // The PIN length is outside of the test scope and most likely incorrect.
        env.persist().set_pin(&[0u8; 16], 4).unwrap();
        let client_data_hash = vec![0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash,
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param: Some(pin_uv_auth_param),
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response_with_user(
            get_assertion_response,
            Some(user2),
            0x04,
            signature_counter,
            Some(2),
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response_with_user(
            get_assertion_response,
            Some(user1),
            0x04,
            signature_counter,
            None,
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv_v1() {
        test_helper_process_get_next_assertion_two_credentials_with_uv(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv_v2() {
        test_helper_process_get_next_assertion_two_credentials_with_uv(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_process_get_next_assertion_three_credentials_no_uv() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x03];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response(
            get_assertion_response,
            vec![0x03],
            signature_counter,
            Some(3),
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response(get_assertion_response, vec![0x02], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response(get_assertion_response, vec![0x01], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_not_allowed() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        assert!(ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());

        // This is a MakeCredential command.
        let mut command_cbor = vec![0x01];
        let cbor_value = cbor_map! {
            1 => vec![0xCD; 16],
            2 => cbor_map! {
                "id" => "example.com",
            },
            3 => cbor_map! {
                "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
            },
            4 => cbor_array![ES256_CRED_PARAM],
        };
        assert!(cbor_write(cbor_value, &mut command_cbor).is_ok());
        ctap_state.process_command(&mut env, &command_cbor, DUMMY_CHANNEL);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_reset() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert!(storage::store_credential(&mut env, credential_source).is_ok());
        assert!(storage::count_credentials(&mut env).unwrap() > 0);

        let reset_reponse = ctap_state.process_command(&mut env, &[0x07], DUMMY_CHANNEL);
        let expected_response = vec![0x00];
        assert_eq!(reset_reponse, expected_response);
        assert!(storage::count_credentials(&mut env).unwrap() == 0);
    }

    #[test]
    fn test_process_reset_cancelled() {
        let mut env = TestEnv::default();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL);

        assert_eq!(
            reset_reponse,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_process_reset_not_first() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // This is a GetNextAssertion command.
        ctap_state.process_command(&mut env, &[0x08], DUMMY_CHANNEL);

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL);
        assert_eq!(reset_reponse, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_process_credential_management_unknown_subcommand() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // The subcommand 0xEE does not exist.
        let reponse =
            ctap_state.process_command(&mut env, &[0x0A, 0xA1, 0x01, 0x18, 0xEE], DUMMY_CHANNEL);
        let expected_response = vec![Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_process_unknown_command() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // This command does not exist.
        let reponse = ctap_state.process_command(&mut env, &[0xDF], DUMMY_CHANNEL);
        let expected_response = vec![Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_signature_counter() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut last_counter = env.persist().global_signature_counter().unwrap();
        assert!(last_counter > 0);
        for _ in 0..100 {
            assert!(ctap_state
                .increment_global_signature_counter(&mut env)
                .is_ok());
            let next_counter = env.persist().global_signature_counter().unwrap();
            assert!(next_counter > last_counter);
            last_counter = next_counter;
        }
    }

    #[test]
    fn test_permission_timeout() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // Write 2 credentials for later assertions.
        for i in 0..3 {
            let mut make_credential_params = create_minimal_make_credential_parameters();
            make_credential_params.user.user_id = vec![i as u8];
            assert!(ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok());
        }

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetAssertion(get_assertion_params),
            DUMMY_CHANNEL,
        );
        env.clock()
            .advance(STATEFUL_COMMAND_TIMEOUT_DURATION_MS - 1);
        assert!(get_assertion_response.is_ok());
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert!(get_next_assertion_response.is_ok());
        env.clock().advance(1);
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_reset_timeout() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        env.clock().advance(RESET_TIMEOUT_DURATION_MS);
        let response =
            ctap_state.process_parsed_command(&mut env, Command::AuthenticatorReset, DUMMY_CHANNEL);
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_credential_management_timeout() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x01],
            user_display_name: Some("display_name".to_string()),
            cred_protect_policy: None,
            creation_order: 0,
            user_name: Some("name".to_string()),
            user_icon: Some("icon".to_string()),
            cred_blob: None,
            large_blob_key: None,
        };

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        ctap_state.client_pin = client_pin;

        for i in 0..3 {
            let mut credential = credential_source.clone();
            credential.rp_id = i.to_string();
            storage::store_credential(&mut env, credential).unwrap();
        }

        env.persist().set_pin(&[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0x1A, 0xA4, 0x96, 0xDA, 0x62, 0x80, 0x28, 0x13, 0xEB, 0x32, 0xB9, 0xF1, 0xD2, 0xA9,
            0xD0, 0xD1,
        ]);

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorCredentialManagement(_))
        ));

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        env.clock()
            .advance(STATEFUL_COMMAND_TIMEOUT_DURATION_MS - 1);
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorCredentialManagement(_))
        ));

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        env.clock().advance(1);
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_check_user_presence() {
        // This TestEnv always returns successful user_presence checks.
        let mut env = TestEnv::default();
        let response = check_user_presence(&mut env, DUMMY_CHANNEL);
        assert!(matches!(response, Ok(_)));
    }

    #[test]
    fn test_check_user_presence_timeout() {
        let mut env = TestEnv::default();
        let clock = env.clock().clone();
        env.user_presence().set(move || {
            clock.advance(100);
            Err(UserPresenceError::Timeout)
        });
        let response = check_user_presence(&mut env, DUMMY_CHANNEL);
        assert!(matches!(
            response,
            Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
        ));
    }

    #[test]
    fn test_channel_interleaving() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        const NEW_CHANNEL: Channel = Channel::MainHid([0xAA, 0xAA, 0xAA, 0xAA]);

        // Write 3 credentials for later assertions.
        for i in 0..3 {
            let mut make_credential_params = create_minimal_make_credential_parameters();
            make_credential_params.user.user_id = vec![i as u8];
            assert!(ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok());
        }

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetAssertion(get_assertion_params),
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            get_assertion_response,
            Ok(ResponseData::AuthenticatorGetAssertion(_))
        ));
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert!(get_next_assertion_response.is_ok());
        assert!(matches!(
            get_next_assertion_response,
            Ok(ResponseData::AuthenticatorGetNextAssertion(_))
        ));
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            NEW_CHANNEL,
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_get_info_command() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetInfo,
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorGetInfo(_))
        ));
        #[cfg(feature = "vendor_hid")]
        {
            let response = ctap_state.process_parsed_command(
                &mut env,
                Command::AuthenticatorGetInfo,
                VENDOR_CHANNEL,
            );
            assert!(matches!(
                response,
                Ok(ResponseData::AuthenticatorGetInfo(_))
            ));
        }
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_vendor_hid_does_not_support_fido_command() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            VENDOR_CHANNEL,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_vendor_hid() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetInfo,
            VENDOR_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorGetInfo(_))
        ));
    }

    #[test]
    fn test_large_blob_stateful() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        const EMPTY_BLOB_ARRAY: [u8; 17] = [
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[..1].to_vec()),
            offset: 0,
            length: Some(EMPTY_BLOB_ARRAY.len()),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorLargeBlobs(None)));

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[1..].to_vec()),
            offset: 1,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorLargeBlobs(None)));
    }

    #[test]
    fn test_large_blob_stateful_interleaved() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        const EMPTY_BLOB_ARRAY: [u8; 17] = [
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[..1].to_vec()),
            offset: 0,
            length: Some(EMPTY_BLOB_ARRAY.len()),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorLargeBlobs(None)));

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorSelection,
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorSelection));

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[1..].to_vec()),
            offset: 1,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_SEQ));
    }
}
