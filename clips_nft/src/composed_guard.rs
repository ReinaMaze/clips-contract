//! Composed guard system for complex authorization policies.
//!
//! Implements support for combining multiple guards for operations that require
//! several authorization checks. This module provides a composable guard framework
//! where multiple authorization checks can be combined and executed in a
//! deterministic order.
//!
//! # Design Principles
//! - Guards execute in a strict, deterministic order
//! - Execution stops immediately when a guard fails (fail-fast)
//! - Each guard returns the same [`Error`] type for consistent error handling
//! - Composable via function pointers for flexible policy combinations
//!
//! # Architecture
//! Guards are represented as function types that take the environment and
//! caller, perform a check, and return a result. The composition system
//! provides utilities to combine these guards efficiently.
//!
//! # Performance
//! Composed guards execute sequentially without allocations on the stack,
//! making them suitable for resource-constrained blockchain environments.
//!
//! # Example Usage
//! ```text
//! // Compose two guards for an operation that requires both caller and admin checks
//! let result = require_caller_and_admin(&env, &caller, &admin)?;
//!
//! // Or use the builder pattern for more complex compositions
//! let is_authorized = check_caller(&env, &caller)
//!     .and_then(|_| check_admin(&env, &caller, &admin))?;
//! ```

use soroban_sdk::{Address, Env};

use crate::types::Error;
use crate::admin_guard;
use crate::caller_guard;

/// Result type for guard operations.
pub type GuardResult = Result<(), Error>;

/// Execute a composed guard check for caller identity followed by admin check.
///
/// This is a common pattern where operations require both valid caller presence
/// and admin privileges. Executes in order:
/// 1. Validate caller identity
/// 2. Validate admin privileges
///
/// Stops at the first failure and returns the error.
///
/// # Parameters
/// - `env`: The Soroban environment
/// - `caller`: The address to authorize
///
/// # Returns
/// - `Ok(())` if both guards pass
/// - `Err(Error)` with the specific failure reason
///
/// # Errors
/// Returns errors from either `require_caller` or `require_admin` depending
/// on which guard fails first.
///
/// # Example
/// ```text
/// pub fn pause_contract(env: Env) -> Result<(), Error> {
///     let caller = env.invoker();
///     require_caller_and_admin(&env, &caller)?;
///     // Perform admin operation
///     Ok(())
/// }
/// ```
pub fn require_caller_and_admin(env: &Env, caller: &Address) -> GuardResult {
    // Guard 1: Validate caller
    caller_guard::require_caller(env)?;

    // Guard 2: Validate admin
    admin_guard::require_admin(env, caller)?;

    Ok(())
}

/// Execute a series of guard checks in sequence.
///
/// Provides a generic composition mechanism where multiple guard functions
/// can be combined and executed in order. Uses a slice of function pointers
/// to allow for flexible guard combinations without requiring special types.
///
/// # Parameters
/// - `guards`: A slice of functions that perform guard checks
///
/// # Returns
/// - `Ok(())` if all guards pass
/// - `Err(Error)` from the first failing guard
///
/// # Note
/// This function is useful for building custom authorization policies
/// that combine multiple guard functions. Guards are executed in the order
/// they appear in the slice.
///
/// # Example
/// ```text
/// let guards: &[fn() -> GuardResult] = &[
///     || check_initialized(),
///     || check_caller_valid(),
///     || check_admin_privileges(),
/// ];
/// execute_guards(guards)?;
/// ```
pub fn execute_guards(guards: &[fn() -> GuardResult]) -> GuardResult {
    for guard in guards {
        guard()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Env as _};

    #[test]
    fn test_require_caller_and_admin_succeeds_when_caller_is_admin() {
        let env = Env::default();
        let admin = Address::random(&env);

        // Initialize admin
        env.storage()
            .instance()
            .set(&crate::types::DataKey::Admin, &admin);

        // Should pass both guards
        let result = require_caller_and_admin(&env, &admin);
        assert!(result.is_ok());
    }

    #[test]
    fn test_require_caller_and_admin_fails_when_not_initialized() {
        let env = Env::default();
        let caller = Address::random(&env);

        // No admin configured
        let result = require_caller_and_admin(&env, &caller);
        assert_eq!(result, Err(Error::NotInitialized));
    }

    #[test]
    fn test_require_caller_and_admin_fails_when_not_admin() {
        let env = Env::default();
        let admin = Address::random(&env);
        let not_admin = Address::random(&env);

        // Initialize admin
        env.storage()
            .instance()
            .set(&crate::types::DataKey::Admin, &admin);

        // Non-admin caller should fail
        let result = require_caller_and_admin(&env, &not_admin);
        assert_eq!(result, Err(Error::UnauthorizedAdmin));
    }

    #[test]
    fn test_execute_guards_all_pass() {
        let pass_guard: fn() -> GuardResult = || Ok(());
        let guards: &[fn() -> GuardResult] = &[pass_guard, pass_guard];

        let result = execute_guards(guards);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_guards_fails_on_first_failure() {
        let pass_guard: fn() -> GuardResult = || Ok(());
        let fail_guard: fn() -> GuardResult = || Err(Error::Unauthorized);

        let guards: &[fn() -> GuardResult] = &[pass_guard, fail_guard, pass_guard];

        let result = execute_guards(guards);
        assert_eq!(result, Err(Error::Unauthorized));
    }

    #[test]
    fn test_execute_guards_empty_slice() {
        let guards: &[fn() -> GuardResult] = &[];
        let result = execute_guards(guards);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_guards_deterministic_order() {
        static mut CALL_COUNT: u32 = 0;

        let guard1: fn() -> GuardResult = || {
            unsafe { CALL_COUNT += 1; }
            Ok(())
        };

        let guards: &[fn() -> GuardResult] = &[guard1, guard1, guard1];
        execute_guards(guards).unwrap();

        unsafe { assert_eq!(CALL_COUNT, 3); }
    }
}
