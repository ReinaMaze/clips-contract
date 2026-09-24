//! Administrative access control guard.
//!
//! Restricts administrative contract operations to authorized administrators.
//! This guard validates that the caller matches the configured admin address
//! and holds the appropriate signing authority.
//!
//! # Security Properties
//! - Requires both address identity match and cryptographic signature validation
//! - Returns specific error types to distinguish initialization from authorization failures
//! - Follows fail-fast pattern to prevent unnecessary storage access
//!
//! # Usage
//! ```text
//! let caller = get_invoking_contract();
//! require_admin(&env, &caller)?;  // Guards admin operations
//! ```

use soroban_sdk::{Address, Env};

use crate::types::{DataKey, Error};

/// Validate that the caller is the contract administrator.
///
/// Performs a two-step authorization check:
/// 1. Verifies the contract has been initialized (admin exists).
/// 2. Compares caller identity with stored admin address.
/// 3. Validates caller signature via `require_auth()`.
///
/// This guard must be called at the entry point of all administrative operations.
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `caller`: The address attempting the admin operation
///
/// # Returns
/// - `Ok(())` if the caller is authenticated as admin
///
/// # Errors
/// - [`Error::NotInitialized`] if the contract has not been initialized
/// - [`Error::UnauthorizedAdmin`] if the caller is not the admin address
///
/// # Example
/// ```text
/// pub fn pause_contract(env: Env) -> Result<(), Error> {
///     let caller = env.invoker();
///     require_admin(&env, &caller)?;
///     // Perform privileged operation
///     Ok(())
/// }
/// ```
pub fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
    // Step 1: Check initialization
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)?;

    // Step 2: Check caller identity
    if *caller != admin {
        return Err(Error::UnauthorizedAdmin);
    }

    // Step 3: Require signature validation
    caller.require_auth();

    Ok(())
}

/// Retrieve the configured administrator address.
///
/// Returns the current admin address if the contract has been initialized.
///
/// # Parameters
/// - `env`: The Soroban environment
///
/// # Returns
/// - `Ok(Address)` containing the admin address
/// - `Err(Error::NotInitialized)` if no admin has been set
pub fn get_admin(env: &Env) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)
}

/// Check if an address is the administrator without requiring authorization.
///
/// This is a read-only check that does not call `require_auth()`.
/// Use this for conditional logic that does not require cryptographic proof.
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `address`: The address to check
///
/// # Returns
/// - `Ok(true)` if the address is the admin
/// - `Ok(false)` if the address is not the admin
/// - `Err(Error::NotInitialized)` if the contract is not initialized
pub fn is_admin(env: &Env, address: &Address) -> Result<bool, Error> {
    let admin = get_admin(env)?;
    Ok(*address == admin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Env as _};

    #[test]
    fn test_require_admin_success_when_caller_is_admin() {
        let env = Env::default();
        let admin = Address::random(&env);

        // Initialize admin
        env.storage()
            .instance()
            .set(&DataKey::Admin, &admin);

        // Admin calls require_admin - should succeed
        assert!(require_admin(&env, &admin).is_ok());
    }

    #[test]
    fn test_require_admin_fails_when_not_initialized() {
        let env = Env::default();
        let caller = Address::random(&env);

        // No admin configured
        let result = require_admin(&env, &caller);
        assert_eq!(result, Err(Error::NotInitialized));
    }

    #[test]
    fn test_require_admin_fails_when_caller_is_not_admin() {
        let env = Env::default();
        let admin = Address::random(&env);
        let not_admin = Address::random(&env);

        // Initialize admin
        env.storage()
            .instance()
            .set(&DataKey::Admin, &admin);

        // Non-admin caller - should fail without require_auth check
        let result = require_admin(&env, &not_admin);
        assert_eq!(result, Err(Error::UnauthorizedAdmin));
    }

    #[test]
    fn test_get_admin_returns_stored_admin() {
        let env = Env::default();
        let admin = Address::random(&env);

        // Initialize admin
        env.storage()
            .instance()
            .set(&DataKey::Admin, &admin);

        let retrieved = get_admin(&env).unwrap();
        assert_eq!(retrieved, admin);
    }

    #[test]
    fn test_get_admin_fails_when_not_initialized() {
        let env = Env::default();
        let result = get_admin(&env);
        assert_eq!(result, Err(Error::NotInitialized));
    }

    #[test]
    fn test_is_admin_returns_true_for_admin() {
        let env = Env::default();
        let admin = Address::random(&env);

        env.storage()
            .instance()
            .set(&DataKey::Admin, &admin);

        let result = is_admin(&env, &admin);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_is_admin_returns_false_for_non_admin() {
        let env = Env::default();
        let admin = Address::random(&env);
        let not_admin = Address::random(&env);

        env.storage()
            .instance()
            .set(&DataKey::Admin, &admin);

        let result = is_admin(&env, &not_admin);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_is_admin_fails_when_not_initialized() {
        let env = Env::default();
        let address = Address::random(&env);

        let result = is_admin(&env, &address);
        assert_eq!(result, Err(Error::NotInitialized));
    }
}
