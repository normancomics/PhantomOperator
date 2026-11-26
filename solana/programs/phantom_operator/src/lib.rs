//! PhantomOperator Solana Program
//!
//! On-chain counterpart to the PhantomOperator Node.js server.
//! Accepts SOL payments for privacy / OPSEC skills and records every
//! invocation in a per-operator registry account.
//!
//! # Instructions
//! - `InitRegistry`  – create and initialise the operator's registry PDA.
//! - `InvokeSkill`   – transfer a SOL payment and record the invocation.
//!
//! # Skill IDs
//! | ID | Slug                 | Min price (lamports) |
//! |----|----------------------|----------------------|
//! |  0 | threat-scan          |          1_000_000   |
//! |  1 | data-removal         |          5_000_000   |
//! |  2 | full-privacy-sweep   |         10_000_000   |
//! |  3 | opsec-score          |          5_000_000   |
//! |  4 | breach-check         |          2_000_000   |
//! |  5 | metadata-audit       |          1_000_000   |

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::instruction as system_instruction;

// ── Entrypoint ────────────────────────────────────────────────────────────────
entrypoint!(process_instruction);

// ── Constants ─────────────────────────────────────────────────────────────────

pub const REGISTRY_SEED: &[u8] = b"phantom_registry";
pub const NUM_SKILLS: usize = 6;

/// Minimum lamport prices per skill (roughly: $0.001–$0.01 in SOL at ~$150/SOL).
/// Mirror the USDCx prices in server.js, converted to lamports.
pub const SKILL_MIN_PRICES: [u64; NUM_SKILLS] = [
    1_000_000,  // 0: threat-scan
    5_000_000,  // 1: data-removal
    10_000_000, // 2: full-privacy-sweep
    5_000_000,  // 3: opsec-score
    2_000_000,  // 4: breach-check
    1_000_000,  // 5: metadata-audit
];

pub const SKILL_NAMES: [&str; NUM_SKILLS] = [
    "threat-scan",
    "data-removal",
    "full-privacy-sweep",
    "opsec-score",
    "breach-check",
    "metadata-audit",
];

// ── Instruction definitions ───────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Clone)]
pub enum PhantomInstruction {
    /// Create and initialise the operator's on-chain registry.
    ///
    /// Required accounts (in order):
    /// 0. `[writable, signer]` – operator / payer wallet
    /// 1. `[writable]`         – registry PDA  (`[REGISTRY_SEED, operator.key]`)
    /// 2. `[]`                 – system program
    InitRegistry,

    /// Record a skill invocation and transfer the payment to the operator wallet.
    ///
    /// Required accounts (in order):
    /// 0. `[writable, signer]` – caller / payer
    /// 1. `[writable]`         – registry PDA
    /// 2. `[writable]`         – operator wallet (receives the SOL payment)
    /// 3. `[]`                 – system program
    /// 4. `[]`                 – clock sysvar
    InvokeSkill {
        /// Skill index (0–5); see `SKILL_NAMES` table above.
        skill_id: u8,
        /// SOL payment in lamports; must be ≥ `SKILL_MIN_PRICES[skill_id]`.
        amount_lamports: u64,
    },
}

// ── State ─────────────────────────────────────────────────────────────────────

/// On-chain state stored in the registry PDA.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RegistryState {
    /// Set to `true` after `InitRegistry` succeeds.
    pub is_initialized: bool,
    /// Operator wallet that owns this registry and receives payments.
    pub owner: Pubkey,
    /// Running count of all skill invocations recorded.
    pub total_invocations: u64,
    /// Running sum of all lamports received.
    pub total_fees_lamports: u64,
}

impl RegistryState {
    /// Byte length of the serialised struct.
    /// bool(1) + Pubkey(32) + u64(8) + u64(8) = 49
    pub const LEN: usize = 1 + 32 + 8 + 8;
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = PhantomInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        PhantomInstruction::InitRegistry => process_init_registry(program_id, accounts),
        PhantomInstruction::InvokeSkill {
            skill_id,
            amount_lamports,
        } => process_invoke_skill(program_id, accounts, skill_id, amount_lamports),
    }
}

// ── Instruction handlers ──────────────────────────────────────────────────────

/// Initialise the on-chain registry for a PhantomOperator deployment.
fn process_init_registry(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let owner_account = next_account_info(accounts_iter)?;
    let registry_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !owner_account.is_signer {
        msg!("InitRegistry: operator must sign the transaction");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive expected PDA and verify it matches the provided account.
    let (registry_pda, bump) = Pubkey::find_program_address(
        &[REGISTRY_SEED, owner_account.key.as_ref()],
        program_id,
    );
    if registry_pda != *registry_account.key {
        msg!("InitRegistry: registry PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    // Allocate the account on-chain.
    let rent = Rent::get()?;
    let required_lamports = rent.minimum_balance(RegistryState::LEN);

    invoke_signed(
        &system_instruction::create_account(
            owner_account.key,
            registry_account.key,
            required_lamports,
            RegistryState::LEN as u64,
            program_id,
        ),
        &[
            owner_account.clone(),
            registry_account.clone(),
            system_program.clone(),
        ],
        &[&[REGISTRY_SEED, owner_account.key.as_ref(), &[bump]]],
    )?;

    // Write initial state.
    let state = RegistryState {
        is_initialized: true,
        owner: *owner_account.key,
        total_invocations: 0,
        total_fees_lamports: 0,
    };
    state.serialize(&mut &mut registry_account.data.borrow_mut()[..])?;

    msg!(
        "PhantomOperator registry initialised for owner {}",
        owner_account.key
    );
    Ok(())
}

/// Record a skill invocation and forward the SOL payment to the operator wallet.
fn process_invoke_skill(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    skill_id: u8,
    amount_lamports: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let caller_account = next_account_info(accounts_iter)?;
    let registry_account = next_account_info(accounts_iter)?;
    let operator_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    let _clock_sysvar = next_account_info(accounts_iter)?;

    if !caller_account.is_signer {
        msg!("InvokeSkill: caller must sign the transaction");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate skill ID.
    if skill_id as usize >= NUM_SKILLS {
        msg!("InvokeSkill: unknown skill_id {}", skill_id);
        return Err(ProgramError::InvalidArgument);
    }

    // Validate payment amount.
    let min_price = SKILL_MIN_PRICES[skill_id as usize];
    if amount_lamports < min_price {
        msg!(
            "InvokeSkill: skill '{}' (id={}) requires >= {} lamports, got {}",
            SKILL_NAMES[skill_id as usize],
            skill_id,
            min_price,
            amount_lamports
        );
        return Err(ProgramError::InsufficientFunds);
    }

    // Load registry state and verify the PDA.
    let owner_pubkey = {
        let data = registry_account.data.borrow();
        let state = RegistryState::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        if !state.is_initialized {
            msg!("InvokeSkill: registry is not initialised");
            return Err(ProgramError::UninitializedAccount);
        }
        state.owner
    };

    let (expected_pda, _) = Pubkey::find_program_address(
        &[REGISTRY_SEED, owner_pubkey.as_ref()],
        program_id,
    );
    if expected_pda != *registry_account.key {
        msg!("InvokeSkill: registry PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify the supplied operator wallet matches the registry owner.
    if *operator_account.key != owner_pubkey {
        msg!("InvokeSkill: operator wallet does not match registry owner");
        return Err(ProgramError::InvalidAccountData);
    }

    // Transfer SOL payment from caller to operator wallet.
    invoke(
        &system_instruction::transfer(
            caller_account.key,
            operator_account.key,
            amount_lamports,
        ),
        &[
            caller_account.clone(),
            operator_account.clone(),
            system_program.clone(),
        ],
    )?;

    // Update registry counters.
    {
        let mut data = registry_account.data.borrow_mut();
        let mut state = RegistryState::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        state.total_invocations = state.total_invocations.saturating_add(1);
        state.total_fees_lamports = state
            .total_fees_lamports
            .saturating_add(amount_lamports);
        state.serialize(&mut &mut data[..])?;
    }

    let clock = Clock::get()?;
    msg!(
        "PhantomOperator: skill '{}' invoked by {} — {} lamports at slot {}",
        SKILL_NAMES[skill_id as usize],
        caller_account.key,
        amount_lamports,
        clock.slot
    );
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_min_prices_length() {
        assert_eq!(SKILL_MIN_PRICES.len(), NUM_SKILLS);
        assert_eq!(SKILL_NAMES.len(), NUM_SKILLS);
    }

    #[test]
    fn registry_state_size() {
        // Serialised size must match the declared constant.
        let state = RegistryState {
            is_initialized: true,
            owner: Pubkey::default(),
            total_invocations: 0,
            total_fees_lamports: 0,
        };
        let serialised = borsh::to_vec(&state).unwrap();
        assert_eq!(serialised.len(), RegistryState::LEN);
    }

    #[test]
    fn instruction_roundtrip() {
        let ix = PhantomInstruction::InvokeSkill {
            skill_id: 2,
            amount_lamports: 10_000_000,
        };
        let encoded = borsh::to_vec(&ix).unwrap();
        let decoded = PhantomInstruction::try_from_slice(&encoded).unwrap();
        assert_eq!(ix, decoded);
    }
}
