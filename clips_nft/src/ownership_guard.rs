//! Ownership authorization guard.
//!
//! Validates that the caller owns the NFT or resource being modified.
//! This guard ensures that only the token owner can perform operations
//! on their tokens (e.g., transfer, burn, update metadata).
//!
//! # Design
//! The guard retrieves the stored ownership information for the resource
//! and compares it against the caller address. Combined with signature
//! validation, this ensures both identity and authorization.
//!
//! # Security Properties
//! - Requires cryptographic signature from the claimed owner
//! - Returns specific error codes for ownership vs. existence failures
//! - Supports ownership transfers via update operations

use soroban_sdk::{Address, Env};

use crate::types::{DataKey, Error, TokenId};

/// Validate that the caller owns the specified NFT token.
///
/// This guard performs three checks:
/// 1. Verifies the token exists
/// 2. Retrieves the token's owner address
/// 3. Compares owner address with caller and validates signature
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `caller`: The address claiming ownership
/// - `token_id`: The token to validate ownership of
///
/// # Returns
/// - `Ok(())` if the caller owns the token and is authenticated
///
/// # Errors
/// - [`Error::TokenNotFound`] if the token does not exist
/// - [`Error::NotTokenOwner`] if the caller does not own the token
///
/// # Example
/// ```text
/// pub fn transfer(env: Env, token_id: TokenId, to: Address) -> Result<(), Error> {
///     let caller = env.invoker();
///     require_token_owner(&env, &caller, token_id)?;
///     // Perform transfer
///     Ok(())
/// }
/// ```
pub fn require_token_owner(env: &Env, caller: &Address, token_id: TokenId) -> Result<(), Error> {
    // Step 1: Retrieve token owner
    let owner = get_token_owner(env, token_id)?;

    // Step 2: Verify caller is the owner
    if *caller != owner {
        return Err(Error::NotTokenOwner);
    }

    // Step 3: Require signature validation
    caller.require_auth();

    Ok(())
}

/// Retrieve the owner of a token without authorization checks.
///
/// Returns the stored owner address for a token, or an error if the token
/// does not exist. This is a read-only query.
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `token_id`: The token to query
///
/// # Returns
/// - `Ok(Address)` containing the token owner
/// - `Err(Error::TokenNotFound)` if the token does not exist
pub fn get_token_owner(env: &Env, token_id: TokenId) -> Result<Address, Error> {
    env.storage()
        .persistent()
        .get::<DataKey, Address>(&DataKey::Owner(token_id))
        .ok_or(Error::TokenNotFound)
}

/// Check if an address owns a token without requiring authorization.
///
/// Performs an identity-only check that does not call `require_auth()`.
/// Useful for conditional logic or read operations.
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `address`: The address to check
/// - `token_id`: The token to check ownership of
///
/// # Returns
/// - `Ok(true)` if the address owns the token
/// - `Ok(false)` if the address does not own the token
/// - `Err(Error::TokenNotFound)` if the token does not exist
pub fn is_token_owner(env: &Env, address: &Address, token_id: TokenId) -> Result<bool, Error> {
    let owner = get_token_owner(env, token_id)?;
    Ok(*address == owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Env as _};

    fn create_token_with_owner(env: &Env, token_id: TokenId, owner: &Address) {
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), owner);
    }

    #[test]
    fn test_require_token_owner_succeeds_for_owner() {
        let env = Env::default();
        let owner = Address::random(&env);
        let token_id: TokenId = 1;

        create_token_with_owner(&env, token_id, &owner);

        assert!(require_token_owner(&env, &owner, token_id).is_ok());
    }

    #[test]
    fn test_require_token_owner_fails_when_token_not_found() {
        let env = Env::default();
        let caller = Address::random(&env);
        let token_id: TokenId = 999;

        let result = require_token_owner(&env, &caller, token_id);
        assert_eq!(result, Err(Error::TokenNotFound));
    }

    #[test]
    fn test_require_token_owner_fails_for_non_owner() {
        let env = Env::default();
        let owner = Address::random(&env);
        let not_owner = Address::random(&env);
        let token_id: TokenId = 1;

        create_token_with_owner(&env, token_id, &owner);

        let result = require_token_owner(&env, &not_owner, token_id);
        assert_eq!(result, Err(Error::NotTokenOwner));
    }

    #[test]
    fn test_get_token_owner_returns_owner() {
        let env = Env::default();
        let owner = Address::random(&env);
        let token_id: TokenId = 1;

        create_token_with_owner(&env, token_id, &owner);

        let retrieved = get_token_owner(&env, token_id).unwrap();
        assert_eq!(retrieved, owner);
    }

    #[test]
    fn test_get_token_owner_fails_for_missing_token() {
        let env = Env::default();
        let token_id: TokenId = 999;

        let result = get_token_owner(&env, token_id);
        assert_eq!(result, Err(Error::TokenNotFound));
    }

    #[test]
    fn test_is_token_owner_returns_true_for_owner() {
        let env = Env::default();
        let owner = Address::random(&env);
        let token_id: TokenId = 1;

        create_token_with_owner(&env, token_id, &owner);

        let result = is_token_owner(&env, &owner, token_id).unwrap();
        assert!(result);
    }

    #[test]
    fn test_is_token_owner_returns_false_for_non_owner() {
        let env = Env::default();
        let owner = Address::random(&env);
        let not_owner = Address::random(&env);
        let token_id: TokenId = 1;

        create_token_with_owner(&env, token_id, &owner);

        let result = is_token_owner(&env, &not_owner, token_id).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_is_token_owner_fails_for_missing_token() {
        let env = Env::default();
        let address = Address::random(&env);
        let token_id: TokenId = 999;

        let result = is_token_owner(&env, &address, token_id);
        assert_eq!(result, Err(Error::TokenNotFound));
    }
}
