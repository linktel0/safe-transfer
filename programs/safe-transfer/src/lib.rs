use anchor_lang::prelude::*;
use anchor_lang::solana_program::entrypoint::ProgramResult;
use anchor_spl::{associated_token::AssociatedToken, token::{CloseAccount, Mint, Token, TokenAccount, Transfer}};

declare_id!("B4VKaDSqRGnyKM8KkSPkTgXbR7WT3ZqAYkyApHQtj5ju");

#[error_code]
pub enum ErrorCode {
    #[msg("Wallet to withdraw from is not owned by owner")]
    WalletToWithdrawFromInvalid,
    #[msg("State index is inconsistent")]
    InvalidStateIdx,
    #[msg("Delegate is not set correctly")]
    DelegateNotSetCorrectly,
    #[msg("Stage is invalid")]
    StageInvalid
}

fn transfer_escrow_out<'info>(
    bump:u8,
    application_idx: u64,
    user_from: AccountInfo<'info>,
    user_to: AccountInfo<'info>,
    mint_token: AccountInfo<'info>,
    escrow: &mut Account<'info, TokenAccount>,
    token_to: AccountInfo<'info>,
    state: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
    amount: u64
) -> ProgramResult {

    let bump_vector = bump.to_le_bytes();
    let mint_token = mint_token.key().clone();
    let application_idx_bytes = application_idx.to_le_bytes();
    let inner = vec![
        b"state".as_ref(),
        user_from.key.as_ref(),
        user_to.key.as_ref(),
        mint_token.as_ref(), 
        application_idx_bytes.as_ref(),
        bump_vector.as_ref(),
    ];

    let outer = vec![inner.as_slice()];

    // Perform the actual transfer
    let transfer_instruction = Transfer{
        from: escrow.to_account_info(),
        to:   token_to,
        authority: state.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );
    anchor_spl::token::transfer(cpi_ctx, amount)?;


    // Use the `reload()` function on an account to reload it's state. Since we performed the
    // transfer, we are expecting the `amount` field to have changed.
    let should_close = {
        escrow.reload()?;
        escrow.amount == 0
    };

    // If token account has no more tokens, 
    // it should be wiped out since it has no other use case.
    if should_close {
        let ca = CloseAccount{
            account: escrow.to_account_info(),
            destination: user_from.to_account_info(),
            authority: state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            token_program.to_account_info(),
            ca,
            outer.as_slice(),
        );
        anchor_spl::token::close_account(cpi_ctx)?;
    }

    Ok(())

}

#[program]
pub mod safe_transfer {
    use super::*;

    pub fn initialize_new_grant(ctx: Context<InitializeNewGrant>, application_idx: u64, amount: u64) -> ProgramResult {
        let state = &mut ctx.accounts.application_state;
        state.idx = application_idx;
        state.user_from = ctx.accounts.user_from.key().clone();
        state.user_to = ctx.accounts.user_to.key().clone();
        state.mint_token = ctx.accounts.mint_token.key().clone();
        state.escrow = ctx.accounts.escrow.key().clone();
        state.amount_tokens = amount;

        msg!("Initialized new Safe Transfer instance for {}", amount);

        let bump = *ctx.bumps.get("state").unwrap();
        let bump_vector = bump.to_le_bytes();
        let mint_token = ctx.accounts.mint_token.key().clone();
        let application_idx_bytes = application_idx.to_le_bytes();
        let inner = vec![
            b"state".as_ref(),
            ctx.accounts.user_from.key.as_ref(),
            ctx.accounts.user_to.key.as_ref(),
            mint_token.as_ref(), 
            application_idx_bytes.as_ref(),
            bump_vector.as_ref(),
        ];
        let outer = vec![inner.as_slice()];

        let transfer_instruction = Transfer{
            from: ctx.accounts.token_from.to_account_info(),
            to: ctx.accounts.escrow.to_account_info(),
            authority: ctx.accounts.user_from.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );

        anchor_spl::token::transfer(cpi_ctx, state.amount_tokens)?;

        state.stage = Stage::FundsDeposited.to_code();
        
        Ok(())
    }

    pub fn complete_grant(ctx: Context<CompleteGrant>, application_idx: u64) -> Result<()> {
        if Stage::from(ctx.accounts.application_state.stage)? != Stage::FundsDeposited {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.application_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let bump = *ctx.bumps.get("state").unwrap();
        transfer_escrow_out(
            bump,
            application_idx,
            ctx.accounts.user_from.to_account_info(),
            ctx.accounts.user_to.to_account_info(),
            ctx.accounts.mint_token.to_account_info(),
            &mut ctx.accounts.escrow,
            ctx.accounts.token_to.to_account_info(),            
            ctx.accounts.application_state.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.application_state.amount_tokens
        )?;

        let state = &mut ctx.accounts.application_state;
        state.stage = Stage::EscrowComplete.to_code();
        Ok(())
    }

    pub fn pull_back(ctx: Context<PullBackInstruction>, application_idx: u64) -> Result<()> {
        let current_stage = Stage::from(ctx.accounts.application_state.stage)?;
        let is_valid_stage = current_stage == Stage::FundsDeposited || current_stage == Stage::PullBackComplete;
        if !is_valid_stage {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.application_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let bump = *ctx.bumps.get("state").unwrap();
        let token_amounts = ctx.accounts.escrow.amount;
        transfer_escrow_out(
            bump,
            application_idx,
            ctx.accounts.user_from.to_account_info(),
            ctx.accounts.user_to.to_account_info(),
            ctx.accounts.mint_token.to_account_info(),
            &mut ctx.accounts.escrow,
            ctx.accounts.token_to.to_account_info(),            
            ctx.accounts.application_state.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            token_amounts,
        )?;
        let state = &mut ctx.accounts.application_state;
        state.stage = Stage::PullBackComplete.to_code();

        Ok(())
    }


}


#[derive(Clone, Copy, PartialEq)]
pub enum Stage {
    // Safe Pay withdrew funds from Alice and deposited them into the escrow wallet
    FundsDeposited,

    // {from FundsDeposited} Bob withdrew the funds from the escrow. We are done.
    EscrowComplete,

    // {from FundsDeposited} Alice pulled back the funds
    PullBackComplete,
}

impl Stage {
    fn to_code(&self) -> u8 {
        match self {
            Stage::FundsDeposited => 1,
            Stage::EscrowComplete => 2,
            Stage::PullBackComplete => 3,
        }
    }

    fn from(val: u8) -> std::result::Result<Stage, Error> {
        match val {
            1 => Ok(Stage::FundsDeposited),
            2 => Ok(Stage::EscrowComplete),
            3 => Ok(Stage::PullBackComplete),
            unknown_value => {
                msg!("Unknown stage: {}", unknown_value);
                Err(ErrorCode::StageInvalid.into())
            }
        }
    }
}


#[account]
#[derive(Default)]
pub struct State {
    idx: u64,
    user_from: Pubkey,
    user_to: Pubkey,
    escrow: Pubkey,
    mint_token: Pubkey,
    amount_tokens: u64,
    stage: u8,
}

impl State {
    pub const MAX_SIZE: usize = 8 + (32 +32 +32 + 32) + 8 + 1;
}

#[derive(Accounts)]
#[instruction(application_idx: u64)]
pub struct InitializeNewGrant<'info>{
    #[account(
        init,
        payer = user_from,
        seeds = [ b"state".as_ref(),user_from.key().as_ref(),user_to.key().as_ref(),
            mint_token.key().as_ref(),application_idx.to_le_bytes().as_ref()],
        bump,
        space = 8 + State::MAX_SIZE
    )]
    application_state: Account<'info, State>,

    #[account(
        init,
        payer = user_from,
        seeds = [ b"wallet".as_ref(),user_from.key().as_ref(),user_to.key().as_ref(),
            mint_token.key().as_ref(),application_idx.to_le_bytes().as_ref()],
        bump,
        token::mint=mint_token,
        token::authority=application_state,
    )]
    escrow: Account<'info, TokenAccount>,

    #[account(mut)]
    user_from: Signer<'info>,   
    /// CHECK: "account is receiver"                  
    user_to: AccountInfo<'info>,              
    mint_token: Account<'info, Mint>,  

    #[account(
        mut,
        constraint=token_from.owner == user_from.key(),
        constraint=token_from.mint  == mint_token.key(),
    )]
    token_from: Account<'info, TokenAccount>,

    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(application_idx: u64)]
pub struct CompleteGrant<'info> {
    #[account(
        mut,
        seeds=[b"state".as_ref(), user_from.key().as_ref(), user_to.key.as_ref(), 
               mint_token.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump,
        has_one = user_from,
        has_one = user_to,
        has_one = mint_token,
    )]
    application_state: Account<'info, State>,

    #[account(
        mut,
        seeds=[b"wallet".as_ref(), user_from.key().as_ref(), user_to.key.as_ref(), 
        mint_token.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump,
    )]
    escrow: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = user_to,
        associated_token::mint = mint_token,
        associated_token::authority = user_to,
    )]
    token_to: Account<'info, TokenAccount>,   

    // Users and accounts in the system
    /// CHECK: "no signature required"
    #[account(mut)]
    user_from: AccountInfo<'info>,                    
    #[account(mut)]
    user_to: Signer<'info>,                        
    mint_token: Account<'info, Mint>,       

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    associated_token_program: Program<'info, AssociatedToken>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(application_idx: u64)]
pub struct PullBackInstruction<'info> {
    #[account(
        mut,
        seeds=[b"state".as_ref(), user_from.key().as_ref(), user_to.key.as_ref(), 
               mint_token.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump,
        has_one = user_from,
        has_one = user_to,
        has_one = mint_token,
    )]
    application_state: Account<'info, State>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), user_from.key().as_ref(), user_to.key.as_ref(), 
               mint_token.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump,
    )]
    escrow: Account<'info, TokenAccount>,    
    // Users and accounts in the system
    #[account(mut)]
    user_from: Signer<'info>,
    /// CHECK: "no signature required"
    user_to: AccountInfo<'info>,
    mint_token: Account<'info, Mint>,

    // escrow deposit to
    #[account(
        mut,
        constraint=token_to.owner == user_from.key(),
        constraint=token_to.mint == mint_token.key()
    )]
    token_to: Account<'info, TokenAccount>,

    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,    
}