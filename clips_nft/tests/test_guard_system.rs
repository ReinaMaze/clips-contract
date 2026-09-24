//! Comprehensive tests for the guard system (admin, caller, ownership, and composition).
//!
//! Tests the four main guard types:
//! 1. Admin authorization guard
//! 2. Caller validation guard
//! 3. Ownership verification guard
//! 4. Guard composition system
//!
//! Each test validates both success paths and failure modes.

use clips_nft::{Error, TokenId};
use soroban_sdk::testutils::{Address as _, Env as _};
use soroban_sdk::{Address, Env};

// ─── Admin Guard Tests ────────────────────────────────────────────────────────

#[test]
fn test_admin_guard_require_admin_success() {
    let env = Env::default();
    let admin = Address::random(&env);

    // Initialize admin in storage
    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    // Admin should pass authorization
    let result = clips_nft::admin_guard::require_admin(&env, &admin);
    assert!(result.is_ok());
}

#[test]
fn test_admin_guard_require_admin_fails_not_initialized() {
    let env = Env::default();
    let caller = Address::random(&env);

    // No admin configured
    let result = clips_nft::admin_guard::require_admin(&env, &caller);
    assert_eq!(result, Err(Error::NotInitialized));
}

#[test]
fn test_admin_guard_require_admin_fails_unauthorized() {
    let env = Env::default();
    let admin = Address::random(&env);
    let not_admin = Address::random(&env);

    // Initialize admin
    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    // Non-admin should be rejected before require_auth check
    let result = clips_nft::admin_guard::require_admin(&env, &not_admin);
    assert_eq!(result, Err(Error::UnauthorizedAdmin));
}

#[test]
fn test_admin_guard_get_admin_success() {
    let env = Env::default();
    let admin = Address::random(&env);

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    let retrieved = clips_nft::admin_guard::get_admin(&env).unwrap();
    assert_eq!(retrieved, admin);
}

#[test]
fn test_admin_guard_get_admin_fails_not_initialized() {
    let env = Env::default();
    let result = clips_nft::admin_guard::get_admin(&env);
    assert_eq!(result, Err(Error::NotInitialized));
}

#[test]
fn test_admin_guard_is_admin_true() {
    let env = Env::default();
    let admin = Address::random(&env);

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    let result = clips_nft::admin_guard::is_admin(&env, &admin).unwrap();
    assert!(result);
}

#[test]
fn test_admin_guard_is_admin_false() {
    let env = Env::default();
    let admin = Address::random(&env);
    let not_admin = Address::random(&env);

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    let result = clips_nft::admin_guard::is_admin(&env, &not_admin).unwrap();
    assert!(!result);
}

// ─── Caller Guard Tests ───────────────────────────────────────────────────────

#[test]
fn test_caller_guard_require_caller_validates() {
    let env = Env::default();
    let caller = Address::random(&env);

    // Should validate the caller successfully
    let result = clips_nft::caller_guard::require_caller(&env, &caller);
    assert!(result.is_ok());
}

#[test]
fn test_caller_guard_is_valid_caller_always_true() {
    let env = Env::default();
    let address = Address::random(&env);

    // In Soroban, all addresses are valid
    assert!(clips_nft::caller_guard::is_valid_caller(&address));
}

#[test]
fn test_caller_guard_multiple_addresses_valid() {
    let env = Env::default();
    let addr1 = Address::random(&env);
    let addr2 = Address::random(&env);
    let addr3 = Address::random(&env);

    assert!(clips_nft::caller_guard::is_valid_caller(&addr1));
    assert!(clips_nft::caller_guard::is_valid_caller(&addr2));
    assert!(clips_nft::caller_guard::is_valid_caller(&addr3));

    // All should be distinct
    assert_ne!(addr1, addr2);
    assert_ne!(addr2, addr3);
    assert_ne!(addr1, addr3);
}

// ─── Ownership Guard Tests ────────────────────────────────────────────────────

#[test]
fn test_ownership_guard_require_token_owner_success() {
    let env = Env::default();
    let owner = Address::random(&env);
    let token_id: TokenId = 1;

    // Set token owner
    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id), &owner);

    // Owner should pass
    let result = clips_nft::ownership_guard::require_token_owner(&env, &owner, token_id);
    assert!(result.is_ok());
}

#[test]
fn test_ownership_guard_require_token_owner_fails_token_not_found() {
    let env = Env::default();
    let caller = Address::random(&env);
    let token_id: TokenId = 999;

    // Token doesn't exist
    let result = clips_nft::ownership_guard::require_token_owner(&env, &caller, token_id);
    assert_eq!(result, Err(Error::TokenNotFound));
}

#[test]
fn test_ownership_guard_require_token_owner_fails_not_owner() {
    let env = Env::default();
    let owner = Address::random(&env);
    let not_owner = Address::random(&env);
    let token_id: TokenId = 1;

    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id), &owner);

    // Non-owner should fail
    let result = clips_nft::ownership_guard::require_token_owner(&env, &not_owner, token_id);
    assert_eq!(result, Err(Error::NotTokenOwner));
}

#[test]
fn test_ownership_guard_get_token_owner_success() {
    let env = Env::default();
    let owner = Address::random(&env);
    let token_id: TokenId = 1;

    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id), &owner);

    let retrieved = clips_nft::ownership_guard::get_token_owner(&env, token_id).unwrap();
    assert_eq!(retrieved, owner);
}

#[test]
fn test_ownership_guard_get_token_owner_fails() {
    let env = Env::default();
    let token_id: TokenId = 999;

    let result = clips_nft::ownership_guard::get_token_owner(&env, token_id);
    assert_eq!(result, Err(Error::TokenNotFound));
}

#[test]
fn test_ownership_guard_is_token_owner_true() {
    let env = Env::default();
    let owner = Address::random(&env);
    let token_id: TokenId = 1;

    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id), &owner);

    let result = clips_nft::ownership_guard::is_token_owner(&env, &owner, token_id).unwrap();
    assert!(result);
}

#[test]
fn test_ownership_guard_is_token_owner_false() {
    let env = Env::default();
    let owner = Address::random(&env);
    let not_owner = Address::random(&env);
    let token_id: TokenId = 1;

    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id), &owner);

    let result = clips_nft::ownership_guard::is_token_owner(&env, &not_owner, token_id).unwrap();
    assert!(!result);
}

#[test]
fn test_ownership_guard_is_token_owner_fails_token_not_found() {
    let env = Env::default();
    let address = Address::random(&env);
    let token_id: TokenId = 999;

    let result = clips_nft::ownership_guard::is_token_owner(&env, &address, token_id);
    assert_eq!(result, Err(Error::TokenNotFound));
}

#[test]
fn test_ownership_guard_multiple_tokens() {
    let env = Env::default();
    let owner1 = Address::random(&env);
    let owner2 = Address::random(&env);
    let token1: TokenId = 1;
    let token2: TokenId = 2;

    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token1), &owner1);
    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token2), &owner2);

    // Verify each owner only owns their token
    assert_eq!(
        clips_nft::ownership_guard::is_token_owner(&env, &owner1, token1).unwrap(),
        true
    );
    assert_eq!(
        clips_nft::ownership_guard::is_token_owner(&env, &owner1, token2).unwrap(),
        false
    );
    assert_eq!(
        clips_nft::ownership_guard::is_token_owner(&env, &owner2, token1).unwrap(),
        false
    );
    assert_eq!(
        clips_nft::ownership_guard::is_token_owner(&env, &owner2, token2).unwrap(),
        true
    );
}

// ─── Composed Guard Tests ─────────────────────────────────────────────────────

#[test]
fn test_composed_guard_caller_and_admin_success() {
    let env = Env::default();
    let admin = Address::random(&env);

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    // Both guards should pass
    let result = clips_nft::composed_guard::require_caller_and_admin(&env, &admin);
    assert!(result.is_ok());
}

#[test]
fn test_composed_guard_caller_and_admin_fails_not_initialized() {
    let env = Env::default();
    let caller = Address::random(&env);

    // First admin check should fail with NotInitialized
    let result = clips_nft::composed_guard::require_caller_and_admin(&env, &caller);
    assert_eq!(result, Err(Error::NotInitialized));
}

#[test]
fn test_composed_guard_caller_and_admin_fails_not_admin() {
    let env = Env::default();
    let admin = Address::random(&env);
    let not_admin = Address::random(&env);

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    // Should fail on admin check
    let result = clips_nft::composed_guard::require_caller_and_admin(&env, &not_admin);
    assert_eq!(result, Err(Error::UnauthorizedAdmin));
}

#[test]
fn test_composed_guard_execute_guards_all_pass() {
    let pass: fn() -> Result<(), Error> = || Ok(());
    let guards: &[fn() -> Result<(), Error>] = &[pass, pass, pass];

    let result = clips_nft::composed_guard::execute_guards(guards);
    assert!(result.is_ok());
}

#[test]
fn test_composed_guard_execute_guards_fails_on_first_failure() {
    let pass: fn() -> Result<(), Error> = || Ok(());
    let fail: fn() -> Result<(), Error> = || Err(Error::Unauthorized);

    // Fail on second guard
    let guards: &[fn() -> Result<(), Error>] = &[pass, fail, pass];

    let result = clips_nft::composed_guard::execute_guards(guards);
    assert_eq!(result, Err(Error::Unauthorized));
}

#[test]
fn test_composed_guard_execute_guards_empty() {
    let guards: &[fn() -> Result<(), Error>] = &[];
    let result = clips_nft::composed_guard::execute_guards(guards);
    assert!(result.is_ok());
}

#[test]
fn test_composed_guard_execute_guards_single() {
    let pass: fn() -> Result<(), Error> = || Ok(());
    let guards: &[fn() -> Result<(), Error>] = &[pass];

    let result = clips_nft::composed_guard::execute_guards(guards);
    assert!(result.is_ok());
}

// ─── Integration Tests (Multiple Guards Together) ───────────────────────────────

#[test]
fn test_integration_admin_and_owner_both_required() {
    let env = Env::default();
    let admin = Address::random(&env);
    let token_owner = Address::random(&env);
    let token_id: TokenId = 1;

    // Setup admin and token owner
    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);
    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id), &token_owner);

    // Admin should pass admin check
    assert!(clips_nft::admin_guard::require_admin(&env, &admin).is_ok());

    // Token owner should pass ownership check
    assert!(clips_nft::ownership_guard::require_token_owner(&env, &token_owner, token_id).is_ok());

    // Neither should pass the other's check
    assert_eq!(
        clips_nft::admin_guard::require_admin(&env, &token_owner),
        Err(Error::UnauthorizedAdmin)
    );
    assert_eq!(
        clips_nft::ownership_guard::require_token_owner(&env, &admin, token_id),
        Err(Error::NotTokenOwner)
    );
}

#[test]
fn test_integration_deterministic_guard_order() {
    let env = Env::default();
    let admin = Address::random(&env);

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);

    // Calling with not-initialized should fail fast
    let caller = Address::random(&env);
    let result = clips_nft::composed_guard::require_caller_and_admin(&env, &caller);
    assert_eq!(result, Err(Error::UnauthorizedAdmin));
}

#[test]
fn test_integration_guard_reusability() {
    let env = Env::default();
    let admin = Address::random(&env);
    let token_id1: TokenId = 1;
    let token_id2: TokenId = 2;

    env.storage()
        .instance()
        .set(&clips_nft::DataKey::Admin, &admin);
    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id1), &admin);
    env.storage()
        .persistent()
        .set(&clips_nft::DataKey::Owner(token_id2), &admin);

    // Same admin can be validated for multiple operations
    assert!(clips_nft::admin_guard::require_admin(&env, &admin).is_ok());
    assert!(clips_nft::ownership_guard::require_token_owner(&env, &admin, token_id1).is_ok());
    assert!(clips_nft::ownership_guard::require_token_owner(&env, &admin, token_id2).is_ok());
}
