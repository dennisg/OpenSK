// Copyright 2019-2023 Google LLC
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

use crate::api::customization::Customization;
use crate::api::key_store::KeyStore;
use crate::api::persist::{Persist, PersistCredentialIter};
use crate::ctap::data_formats::{
    extract_array, extract_text_string, PublicKeyCredentialSource, PublicKeyCredentialUserEntity,
};
use crate::ctap::status_code::{Ctap2StatusCode, CtapResult};
use crate::env::{AesKey, Env};
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "config_command")]
use sk_cbor::cbor_array_vec;

/// Initializes the store by creating missing objects.
pub fn init(env: &mut impl Env) -> CtapResult<()> {
    env.persist().init()?;
    env.key_store().init()?;
    Ok(())
}

/// Returns the credential at the given key.
///
/// # Errors
///
/// Returns `CTAP2_ERR_VENDOR_INTERNAL_ERROR` if the key does not hold a valid credential.
pub fn get_credential<E: Env>(env: &mut E, key: usize) -> CtapResult<PublicKeyCredentialSource> {
    let credential_entry = env.persist().credential_bytes(key)?;
    let wrap_key = env.key_store().wrap_key::<E>()?;
    deserialize_credential::<E>(&wrap_key, &credential_entry)
        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

/// Finds the key and value for a given credential ID.
///
/// # Errors
///
/// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
pub fn find_credential_item(
    env: &mut impl Env,
    credential_id: &[u8],
) -> Result<(usize, PublicKeyCredentialSource), Ctap2StatusCode> {
    let mut iter_result = Ok(());
    let iter = iter_credentials(env, &mut iter_result)?;
    let mut credentials: Vec<(usize, PublicKeyCredentialSource)> = iter
        .filter(|(_, credential)| credential.credential_id == credential_id)
        .collect();
    iter_result?;
    if credentials.len() > 1 {
        return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
    }
    credentials
        .pop()
        .ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
}

/// Returns the first matching credential.
///
/// Returns `None` if no credentials are matched or if `check_cred_protect` is set and the first
/// matched credential requires user verification.
pub fn find_credential(
    env: &mut impl Env,
    rp_id: &str,
    credential_id: &[u8],
) -> CtapResult<Option<PublicKeyCredentialSource>> {
    let credential = match find_credential_item(env, credential_id) {
        Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS) => return Ok(None),
        Err(e) => return Err(e),
        Ok((_key, credential)) => credential,
    };
    if credential.rp_id != rp_id {
        return Ok(None);
    }
    Ok(Some(credential))
}

/// Stores or updates a credential.
///
/// If a credential with the same RP id and user handle already exists, it is replaced.
pub fn store_credential<E: Env>(
    env: &mut E,
    new_credential: PublicKeyCredentialSource,
) -> CtapResult<()> {
    // Holds the key of the existing credential if this is an update.
    let mut old_key = None;
    let mut iter_result = Ok(());
    let iter = iter_credentials(env, &mut iter_result)?;
    for (key, credential) in iter {
        if credential.rp_id == new_credential.rp_id
            && credential.user_handle == new_credential.user_handle
        {
            old_key = Some(key);
            break;
        }
    }
    iter_result?;
    let max_supported_resident_keys = env.customization().max_supported_resident_keys();
    if old_key.is_none() && count_credentials(env)? >= max_supported_resident_keys {
        return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
    }
    let key = match old_key {
        // This is a new credential being added, we need to allocate a free key. We choose the
        // first available key.
        None => env.persist().free_credential_key()?,
        // This is an existing credential being updated, we reuse its key.
        Some(x) => x,
    };
    let wrap_key = env.key_store().wrap_key::<E>()?;
    let value = serialize_credential::<E>(env, &wrap_key, new_credential)?;
    env.persist().write_credential_bytes(key, &value)?;
    Ok(())
}

/// Deletes a credential.
///
/// # Errors
///
/// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
pub fn delete_credential(env: &mut impl Env, credential_id: &[u8]) -> CtapResult<()> {
    let (key, _) = find_credential_item(env, credential_id)?;
    env.persist().remove_credential(key)
}

/// Updates a credential's user information.
///
/// # Errors
///
/// Returns `CTAP2_ERR_NO_CREDENTIALS` if the credential is not found.
pub fn update_credential<E: Env>(
    env: &mut E,
    credential_id: &[u8],
    user: PublicKeyCredentialUserEntity,
) -> CtapResult<()> {
    let (key, mut credential) = find_credential_item(env, credential_id)?;
    credential.user_name = user.user_name;
    credential.user_display_name = user.user_display_name;
    credential.user_icon = user.user_icon;
    let wrap_key = env.key_store().wrap_key::<E>()?;
    let value = serialize_credential::<E>(env, &wrap_key, credential)?;
    env.persist().write_credential_bytes(key, &value)
}

/// Returns the number of credentials.
pub fn count_credentials(env: &mut impl Env) -> CtapResult<usize> {
    Ok(env.persist().iter_credentials()?.count())
}

/// Returns the estimated number of credentials that can still be stored.
pub fn remaining_credentials(env: &mut impl Env) -> CtapResult<usize> {
    env.customization()
        .max_supported_resident_keys()
        .checked_sub(count_credentials(env)?)
        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

/// Iterates through the credentials.
///
/// If an error is encountered during iteration, it is written to `result`.
pub fn iter_credentials<'a, E: Env>(
    env: &'a mut E,
    result: &'a mut CtapResult<()>,
) -> Result<IterCredentials<'a, E>, Ctap2StatusCode> {
    IterCredentials::new(env, result)
}

/// Returns the next creation order.
pub fn new_creation_order(env: &mut impl Env) -> CtapResult<u64> {
    let mut iter_result = Ok(());
    let iter = iter_credentials(env, &mut iter_result)?;
    let max = iter.map(|(_, credential)| credential.creation_order).max();
    iter_result?;
    Ok(max.unwrap_or(0).wrapping_add(1))
}

/// Returns the number of remaining PIN retries.
pub fn pin_retries(env: &mut impl Env) -> CtapResult<u8> {
    Ok(env
        .customization()
        .max_pin_retries()
        .saturating_sub(env.persist().pin_fails()?))
}

/// Decrements the number of remaining PIN retries.
pub fn decr_pin_retries(env: &mut impl Env) -> CtapResult<()> {
    env.persist().incr_pin_fails()
}

/// Resets the number of remaining PIN retries.
pub fn reset_pin_retries(env: &mut impl Env) -> CtapResult<()> {
    env.persist().reset_pin_retries()
}

/// Returns the number of remaining UV retries.
#[cfg(feature = "fingerprint")]
pub fn uv_retries(env: &mut impl Env) -> CtapResult<u8> {
    Ok(env
        .customization()
        .max_uv_retries()
        .saturating_sub(env.persist().uv_fails()?))
}

/// Decrements the number of remaining UV retries.
#[cfg(feature = "fingerprint")]
pub fn decr_uv_retries(env: &mut impl Env) -> CtapResult<()> {
    env.persist().incr_uv_fails()
}

/// Resets the number of remaining UV retries.
#[cfg(feature = "fingerprint")]
pub fn reset_uv_retries(env: &mut impl Env) -> CtapResult<()> {
    env.persist().reset_uv_retries()
}

/// Returns the minimum PIN length.
pub fn min_pin_length(env: &mut impl Env) -> CtapResult<u8> {
    Ok(env
        .persist()
        .min_pin_length()?
        .unwrap_or(env.customization().default_min_pin_length()))
}

/// Sets the minimum PIN length.
#[cfg(feature = "config_command")]
pub fn set_min_pin_length(env: &mut impl Env, min_pin_length: u8) -> CtapResult<()> {
    env.persist().set_min_pin_length(min_pin_length)
}

/// Returns the list of RP IDs that are used to check if reading the minimum PIN length is
/// allowed.
pub fn min_pin_length_rp_ids(env: &mut impl Env) -> CtapResult<Vec<String>> {
    let rp_ids_bytes = env.persist().min_pin_length_rp_ids_bytes()?;
    let rp_ids = if rp_ids_bytes.is_empty() {
        Some(env.customization().default_min_pin_length_rp_ids())
    } else {
        deserialize_min_pin_length_rp_ids(&rp_ids_bytes)
    };
    debug_assert!(rp_ids.is_some());
    Ok(rp_ids.unwrap_or_default())
}

/// Sets the list of RP IDs that are used to check if reading the minimum PIN length is allowed.
#[cfg(feature = "config_command")]
pub fn set_min_pin_length_rp_ids(
    env: &mut impl Env,
    mut min_pin_length_rp_ids: Vec<String>,
) -> CtapResult<()> {
    for rp_id in env.customization().default_min_pin_length_rp_ids() {
        if !min_pin_length_rp_ids.contains(&rp_id) {
            min_pin_length_rp_ids.push(rp_id);
        }
    }
    if min_pin_length_rp_ids.len() > env.customization().max_rp_ids_length() {
        return Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL);
    }
    env.persist()
        .set_min_pin_length_rp_ids(&serialize_min_pin_length_rp_ids(min_pin_length_rp_ids)?)
}

/// Returns whether enterprise attestation is enabled.
///
/// Without the AuthenticatorConfig command, customization determines the result.
#[cfg(not(feature = "config_command"))]
pub fn enterprise_attestation(env: &mut impl Env) -> CtapResult<bool> {
    Ok(env.customization().enterprise_attestation_mode().is_some())
}

/// Returns whether enterprise attestation is enabled.
///
/// Use the AuthenticatorConfig command to turn it on.
#[cfg(feature = "config_command")]
pub fn enterprise_attestation(env: &mut impl Env) -> CtapResult<bool> {
    env.persist().enterprise_attestation()
}

/// Marks enterprise attestation as enabled.
#[cfg(feature = "config_command")]
pub fn enable_enterprise_attestation(env: &mut impl Env) -> CtapResult<()> {
    env.persist().enable_enterprise_attestation()
}

/// Returns whether alwaysUv is enabled.
pub fn has_always_uv(env: &mut impl Env) -> CtapResult<bool> {
    if env.customization().enforce_always_uv() {
        return Ok(true);
    }
    env.persist().has_always_uv()
}

/// Enables alwaysUv, when disabled, and vice versa.
#[cfg(feature = "config_command")]
pub fn toggle_always_uv(env: &mut impl Env) -> CtapResult<()> {
    if env.customization().enforce_always_uv() {
        return Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED);
    }
    env.persist().toggle_always_uv()
}

/// Iterator for credentials.
pub struct IterCredentials<'a, E: Env> {
    /// The key store for credential unwrapping.
    wrap_key: AesKey<E>,

    /// The store iterator.
    iter: PersistCredentialIter<'a>,

    /// The iteration result.
    ///
    /// It starts as success and gets written at most once with an error if something fails. The
    /// iteration stops as soon as an error is encountered.
    result: &'a mut CtapResult<()>,
}

impl<'a, E: Env> IterCredentials<'a, E> {
    /// Creates a credential iterator.
    fn new(env: &'a mut E, result: &'a mut CtapResult<()>) -> CtapResult<Self> {
        let wrap_key = env.key_store().wrap_key::<E>()?;
        let iter = env.persist().iter_credentials()?;
        Ok(IterCredentials {
            wrap_key,
            iter,
            result,
        })
    }

    /// Marks the iteration as failed if the content is absent.
    ///
    /// For convenience, the function takes and returns ownership instead of taking a shared
    /// reference and returning nothing. This permits to use it in both expressions and statements
    /// instead of statements only.
    fn unwrap<T>(&mut self, x: Option<T>) -> Option<T> {
        if x.is_none() {
            *self.result = Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        x
    }
}

impl<'a, E: Env> Iterator for IterCredentials<'a, E> {
    type Item = (usize, PublicKeyCredentialSource);

    fn next(&mut self) -> Option<(usize, PublicKeyCredentialSource)> {
        if self.result.is_err() {
            return None;
        }
        let next = self.iter.next()?;
        let (key, value) = self.unwrap(next.ok())?;
        let deserialized = deserialize_credential::<E>(&self.wrap_key, &value);
        let credential = self.unwrap(deserialized)?;
        Some((key, credential))
    }
}

/// Deserializes a credential from storage representation.
fn deserialize_credential<E: Env>(
    wrap_key: &AesKey<E>,
    data: &[u8],
) -> Option<PublicKeyCredentialSource> {
    let cbor = super::cbor_read(data).ok()?;
    PublicKeyCredentialSource::from_cbor::<E>(wrap_key, cbor).ok()
}

/// Serializes a credential to storage representation.
fn serialize_credential<E: Env>(
    env: &mut E,
    wrap_key: &AesKey<E>,
    credential: PublicKeyCredentialSource,
) -> CtapResult<Vec<u8>> {
    let mut data = Vec::new();
    super::cbor_write(credential.to_cbor::<E>(env.rng(), wrap_key)?, &mut data)?;
    Ok(data)
}

/// Deserializes a list of RP IDs from storage representation.
fn deserialize_min_pin_length_rp_ids(data: &[u8]) -> Option<Vec<String>> {
    let cbor = super::cbor_read(data).ok()?;
    extract_array(cbor)
        .ok()?
        .into_iter()
        .map(extract_text_string)
        .collect::<CtapResult<Vec<String>>>()
        .ok()
}

/// Serializes a list of RP IDs to storage representation.
#[cfg(feature = "config_command")]
fn serialize_min_pin_length_rp_ids(rp_ids: Vec<String>) -> CtapResult<Vec<u8>> {
    let mut data = Vec::new();
    super::cbor_write(cbor_array_vec!(rp_ids), &mut data)?;
    Ok(data)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::persist::{Attestation, AttestationId, Persist};
    use crate::api::private_key::PrivateKey;
    use crate::api::rng::Rng;
    use crate::ctap::data_formats::{
        CredentialProtectionPolicy, PublicKeyCredentialSource, PublicKeyCredentialType,
    };
    use crate::ctap::reset;
    use crate::ctap::secret::Secret;
    use crate::env::test::TestEnv;

    fn create_credential_source(
        env: &mut TestEnv,
        rp_id: &str,
        user_handle: Vec<u8>,
    ) -> PublicKeyCredentialSource {
        let private_key = PrivateKey::new_ecdsa(env);
        PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from(rp_id),
            user_handle,
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        }
    }

    #[test]
    fn test_store() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);
        let credential_source = create_credential_source(&mut env, "example.com", vec![]);
        assert!(store_credential(&mut env, credential_source).is_ok());
        assert!(count_credentials(&mut env).unwrap() > 0);
    }

    #[test]
    fn test_delete_credential() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);

        let mut credential_ids = vec![];
        for i in 0..env.customization().max_supported_resident_keys() {
            let user_handle = (i as u32).to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut env, "example.com", user_handle);
            credential_ids.push(credential_source.credential_id.clone());
            assert!(store_credential(&mut env, credential_source).is_ok());
            assert_eq!(count_credentials(&mut env).unwrap(), i + 1);
        }
        let mut count = count_credentials(&mut env).unwrap();
        for credential_id in credential_ids {
            assert!(delete_credential(&mut env, &credential_id).is_ok());
            count -= 1;
            assert_eq!(count_credentials(&mut env).unwrap(), count);
        }
    }

    #[test]
    fn test_update_credential() {
        let mut env = TestEnv::default();
        let user = PublicKeyCredentialUserEntity {
            // User ID is ignored.
            user_id: vec![0x00],
            user_name: Some("name".to_string()),
            user_display_name: Some("display_name".to_string()),
            user_icon: Some("icon".to_string()),
        };
        assert_eq!(
            update_credential(&mut env, &[0x1D], user.clone()),
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
        );

        let credential_source = create_credential_source(&mut env, "example.com", vec![0x1D]);
        let credential_id = credential_source.credential_id.clone();
        assert!(store_credential(&mut env, credential_source).is_ok());
        let stored_credential = find_credential(&mut env, "example.com", &credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_credential.user_name, None);
        assert_eq!(stored_credential.user_display_name, None);
        assert_eq!(stored_credential.user_icon, None);
        assert!(update_credential(&mut env, &credential_id, user.clone()).is_ok());
        let stored_credential = find_credential(&mut env, "example.com", &credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_credential.user_name, user.user_name);
        assert_eq!(stored_credential.user_display_name, user.user_display_name);
        assert_eq!(stored_credential.user_icon, user.user_icon);
    }

    #[test]
    fn test_credential_order() {
        let mut env = TestEnv::default();
        let credential_source = create_credential_source(&mut env, "example.com", vec![]);
        let current_latest_creation = credential_source.creation_order;
        assert!(store_credential(&mut env, credential_source).is_ok());
        let mut credential_source = create_credential_source(&mut env, "example.com", vec![]);
        credential_source.creation_order = new_creation_order(&mut env).unwrap();
        assert!(credential_source.creation_order > current_latest_creation);
        let current_latest_creation = credential_source.creation_order;
        assert!(store_credential(&mut env, credential_source).is_ok());
        assert!(new_creation_order(&mut env).unwrap() > current_latest_creation);
    }

    #[test]
    fn test_fill_store() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);

        let max_supported_resident_keys = env.customization().max_supported_resident_keys();
        for i in 0..max_supported_resident_keys {
            let user_handle = (i as u32).to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut env, "example.com", user_handle);
            assert!(store_credential(&mut env, credential_source).is_ok());
            assert_eq!(count_credentials(&mut env).unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut env,
            "example.com",
            vec![max_supported_resident_keys as u8],
        );
        assert_eq!(
            store_credential(&mut env, credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            count_credentials(&mut env).unwrap(),
            max_supported_resident_keys
        );
    }

    #[test]
    fn test_overwrite() {
        let mut env = TestEnv::default();
        init(&mut env).unwrap();

        assert_eq!(count_credentials(&mut env).unwrap(), 0);
        // These should have different IDs.
        let credential_source0 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_id0 = credential_source0.credential_id.clone();
        let credential_id1 = credential_source1.credential_id.clone();

        assert!(store_credential(&mut env, credential_source0).is_ok());
        assert!(store_credential(&mut env, credential_source1).is_ok());
        assert_eq!(count_credentials(&mut env).unwrap(), 1);
        assert!(find_credential(&mut env, "example.com", &credential_id0)
            .unwrap()
            .is_none());
        assert!(find_credential(&mut env, "example.com", &credential_id1)
            .unwrap()
            .is_some());

        reset(&mut env).unwrap();
        let max_supported_resident_keys = env.customization().max_supported_resident_keys();
        for i in 0..max_supported_resident_keys {
            let user_handle = (i as u32).to_ne_bytes().to_vec();
            let credential_source = create_credential_source(&mut env, "example.com", user_handle);
            assert!(store_credential(&mut env, credential_source).is_ok());
            assert_eq!(count_credentials(&mut env).unwrap(), i + 1);
        }
        let credential_source = create_credential_source(
            &mut env,
            "example.com",
            vec![max_supported_resident_keys as u8],
        );
        assert_eq!(
            store_credential(&mut env, credential_source),
            Err(Ctap2StatusCode::CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(
            count_credentials(&mut env).unwrap(),
            max_supported_resident_keys
        );
    }

    #[test]
    fn test_get_credential() {
        let mut env = TestEnv::default();
        let credential_source0 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut env, "example.com", vec![0x01]);
        let credential_source2 =
            create_credential_source(&mut env, "another.example.com", vec![0x02]);
        let credential_sources = vec![credential_source0, credential_source1, credential_source2];
        for credential_source in credential_sources.into_iter() {
            let cred_id = credential_source.credential_id.clone();
            assert!(store_credential(&mut env, credential_source).is_ok());
            let (key, _) = find_credential_item(&mut env, &cred_id).unwrap();
            let cred = get_credential(&mut env, key).unwrap();
            assert_eq!(&cred_id, &cred.credential_id);
        }
    }

    #[test]
    fn test_find() {
        let mut env = TestEnv::default();
        assert_eq!(count_credentials(&mut env).unwrap(), 0);
        let credential_source0 = create_credential_source(&mut env, "example.com", vec![0x00]);
        let credential_source1 = create_credential_source(&mut env, "example.com", vec![0x01]);
        let id0 = credential_source0.credential_id.clone();
        let key0 = credential_source0.private_key.clone();
        assert!(store_credential(&mut env, credential_source0).is_ok());
        assert!(store_credential(&mut env, credential_source1).is_ok());

        let no_credential = find_credential(&mut env, "another.example.com", &id0).unwrap();
        assert_eq!(no_credential, None);
        let found_credential = find_credential(&mut env, "example.com", &id0).unwrap();
        let expected_credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: id0,
            private_key: key0,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
        };
        assert_eq!(found_credential, Some(expected_credential));
    }

    #[test]
    fn test_pin_retries() {
        let mut env = TestEnv::default();

        // The pin retries is initially at the maximum.
        assert_eq!(
            pin_retries(&mut env),
            Ok(env.customization().max_pin_retries())
        );

        // Decrementing the pin retries decrements the pin retries.
        for retries in (0..env.customization().max_pin_retries()).rev() {
            decr_pin_retries(&mut env).unwrap();
            assert_eq!(pin_retries(&mut env), Ok(retries));
        }

        // Decrementing the pin retries after zero does not modify the pin retries.
        decr_pin_retries(&mut env).unwrap();
        assert_eq!(pin_retries(&mut env), Ok(0));

        // Resetting the pin retries resets the pin retries.
        reset_pin_retries(&mut env).unwrap();
        assert_eq!(
            pin_retries(&mut env),
            Ok(env.customization().max_pin_retries())
        );
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_uv_retries() {
        let mut env = TestEnv::default();

        // The uv retries is initially at the maximum.
        assert_eq!(
            uv_retries(&mut env),
            Ok(env.customization().max_uv_retries())
        );

        // Decrementing the uv retries decrements the uv retries.
        for retries in (0..env.customization().max_uv_retries()).rev() {
            decr_uv_retries(&mut env).unwrap();
            assert_eq!(uv_retries(&mut env), Ok(retries));
        }

        // Decrementing the uv retries after zero does not modify the uv retries.
        decr_uv_retries(&mut env).unwrap();
        assert_eq!(uv_retries(&mut env), Ok(0));

        // Resetting the uv retries resets the uv retries.
        reset_uv_retries(&mut env).unwrap();
        assert_eq!(
            uv_retries(&mut env),
            Ok(env.customization().max_uv_retries())
        );
    }

    #[test]
    fn test_persistent_keys() {
        let mut env = TestEnv::default();
        init(&mut env).unwrap();

        // Make sure the attestation are absent. There is no batch attestation in tests.
        assert_eq!(
            env.persist().get_attestation(AttestationId::Batch),
            Ok(None)
        );

        // Make sure the persistent keys are initialized to dummy values.
        let dummy_attestation = Attestation {
            private_key: Secret::from_exposed_secret([0x41; 32]),
            certificate: vec![0xdd; 20],
        };
        env.persist()
            .set_attestation(AttestationId::Batch, Some(&dummy_attestation))
            .unwrap();

        // The persistent keys stay initialized and preserve their value after a reset.
        reset(&mut env).unwrap();
        assert_eq!(
            env.persist().get_attestation(AttestationId::Batch),
            Ok(Some(dummy_attestation))
        );
    }

    #[test]
    fn test_min_pin_length() {
        let mut env = TestEnv::default();

        // The minimum PIN length is initially at the default.
        assert_eq!(
            min_pin_length(&mut env).unwrap(),
            env.customization().default_min_pin_length()
        );

        // Changes by the setter are reflected by the getter..
        let new_min_pin_length = 8;
        set_min_pin_length(&mut env, new_min_pin_length).unwrap();
        assert_eq!(min_pin_length(&mut env).unwrap(), new_min_pin_length);
    }

    #[test]
    fn test_min_pin_length_rp_ids() {
        let mut env = TestEnv::default();

        // The minimum PIN length RP IDs are initially at the default.
        assert_eq!(
            min_pin_length_rp_ids(&mut env).unwrap(),
            env.customization().default_min_pin_length_rp_ids()
        );

        // Changes by the setter are reflected by the getter.
        let mut rp_ids = vec![String::from("example.com")];
        assert_eq!(set_min_pin_length_rp_ids(&mut env, rp_ids.clone()), Ok(()));
        for rp_id in env.customization().default_min_pin_length_rp_ids() {
            if !rp_ids.contains(&rp_id) {
                rp_ids.push(rp_id);
            }
        }
        assert_eq!(min_pin_length_rp_ids(&mut env).unwrap(), rp_ids);
    }

    #[test]
    fn test_enterprise_attestation() {
        let mut env = TestEnv::default();

        let dummy_attestation = Attestation {
            private_key: Secret::from_exposed_secret([0x41; 32]),
            certificate: vec![0xdd; 20],
        };
        env.persist()
            .set_attestation(AttestationId::Enterprise, Some(&dummy_attestation))
            .unwrap();

        assert!(!enterprise_attestation(&mut env).unwrap());
        assert_eq!(enable_enterprise_attestation(&mut env), Ok(()));
        assert!(enterprise_attestation(&mut env).unwrap());
        reset(&mut env).unwrap();
        assert!(!enterprise_attestation(&mut env).unwrap());
    }

    #[test]
    fn test_always_uv() {
        let mut env = TestEnv::default();

        if env.customization().enforce_always_uv() {
            assert!(has_always_uv(&mut env).unwrap());
            assert_eq!(
                toggle_always_uv(&mut env),
                Err(Ctap2StatusCode::CTAP2_ERR_OPERATION_DENIED)
            );
        } else {
            assert!(!has_always_uv(&mut env).unwrap());
            assert_eq!(toggle_always_uv(&mut env), Ok(()));
            assert!(has_always_uv(&mut env).unwrap());
            assert_eq!(toggle_always_uv(&mut env), Ok(()));
            assert!(!has_always_uv(&mut env).unwrap());
        }
    }

    #[test]
    fn test_serialize_deserialize_credential() {
        let mut env = TestEnv::default();
        let wrap_key = env.key_store().wrap_key::<TestEnv>().unwrap();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            user_display_name: Some(String::from("Display Name")),
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationOptional),
            creation_order: 0,
            user_name: Some(String::from("name")),
            user_icon: Some(String::from("icon")),
            cred_blob: Some(vec![0xCB]),
            large_blob_key: Some(vec![0x1B]),
        };
        let serialized =
            serialize_credential::<TestEnv>(&mut env, &wrap_key, credential.clone()).unwrap();
        let reconstructed = deserialize_credential::<TestEnv>(&wrap_key, &serialized).unwrap();
        assert_eq!(credential, reconstructed);
    }

    #[test]
    fn test_serialize_deserialize_min_pin_length_rp_ids() {
        let rp_ids = vec![String::from("example.com")];
        let serialized = serialize_min_pin_length_rp_ids(rp_ids.clone()).unwrap();
        let reconstructed = deserialize_min_pin_length_rp_ids(&serialized).unwrap();
        assert_eq!(rp_ids, reconstructed);
    }
}
