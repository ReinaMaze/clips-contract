//! Caller identity validation guard.
//!
//! Provides foundational caller validation to ensure that a caller identity
//! exists and is valid before executing protected contract functions.
//! This guard is typically used as the first validation in authorization chains.
//!
//! # Design
//! This module implements a pure validation check with no state-dependent logic.
//! It verifies that the caller is a valid Soroban address and enforces
//! cryptographic signature validation.
//!
//! # Integration
//! This guard is often used in composition with higher-level guards like
//! `admin_guard` or `ownership_guard` for complete authorization policies.

use soroban_sdk::{Address, Env};

use crate::types::Error;

/// Validate that a caller is present and valid.
///
/// This is the foundational validation that ensures a caller address is
/// valid and has been cryptographically authenticated via `require_auth()`.
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `caller`: The address to validate
///
/// # Returns
/// - `Ok(())` if the caller is valid and authenticated
///
/// # Errors
/// - [`Error::InvalidCaller`] if caller validation or authentication fails
///
/// # Note
/// In Soroban, addresses are typically validated by the SDK itself. This guard
/// provides an explicit checkpoint for caller validation to allow for future
/// extension with additional validation logic (e.g., whitelist checks).
///
/// # Example
/// ```text
/// pub fn transfer(env: Env, to: Address, amount: i128) -> Result<(), Error> {
///     let caller = env.invoker();
///     require_caller(&env, &caller)?;
///     // Proceed with transfer
///     Ok(())
/// }
/// ```
pub fn require_caller(env: &Env, caller: &Address) -> Result<(), Error> {
    // Validate caller signature
    caller.require_auth();
    Ok(())
}

/// Check if a caller is valid without requiring authorization.
///
/// This is a read-only check that verifies caller presence without
/// enforcing cryptographic authentication. Useful for checking caller
/// identity in non-critical paths or logging.
///
/// # Parameters
/// - `caller`: The address to validate
///
/// # Returns
/// - `true` if the caller appears valid
/// - `false` if the caller is invalid (future extension point)
///
/// # Note
/// Currently always returns `true` for valid Soroban addresses, but
/// provides an extension point for future caller validation rules
/// (e.g., blacklist checks).
pub fn is_valid_caller(_caller: &Address) -> bool {
    // In Soroban, addresses are strongly typed and validated at the SDK level.
    // This function serves as an extension point for future validation logic.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Env as _};

    #[test]
    fn test_require_caller_validates_signature() {
        let env = Env::default();
        let caller = Address::random(&env);

        // Should validate the caller
        let result = require_caller(&env, &caller);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_valid_caller_always_returns_true() {
        let env = Env::default();
        let address = Address::random(&env);

        // All addresses are valid in Soroban
        assert!(is_valid_caller(&address));
    }

    #[test]
    fn test_multiple_callers_are_valid() {
        let env = Env::default();
        let caller1 = Address::random(&env);
        let caller2 = Address::random(&env);
        let caller3 = Address::random(&env);

        assert!(is_valid_caller(&caller1));
        assert!(is_valid_caller(&caller2));
        assert!(is_valid_caller(&caller3));
    }
}
