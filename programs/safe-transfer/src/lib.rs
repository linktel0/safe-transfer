use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_lang::solana_program::entrypoint::ProgramResult;
use anchor_spl::{token::{CloseAccount, Mint, Token, TokenAccount, Transfer}};

declare_id!("BpCbo5wS53SLmnppnPeZCi271V87s4MkiT9YijMLxC36");

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

#[program]
pub mod safe_transfer {
    use super::*;

    pub fn initialize_sol(ctx: Context<InitializeSol>, transfer_idx: u64, amount: u64) -> ProgramResult {
        
        let transfer_state = &mut ctx.accounts.transfer_state;
        transfer_state.transfer_idx = transfer_idx;
        transfer_state.sender = ctx.accounts.sender.key().clone();
        transfer_state.receiver = ctx.accounts.receiver.key().clone();
        transfer_state.amount = amount;

        msg!("Initialized new Safe Transfer Sol for {}", amount);

        let transfer_instruction = system_program::Transfer{
            from: ctx.accounts.sender.to_account_info(),
            to: transfer_state.to_account_info(),
        };
        
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(), 
            transfer_instruction
        );
        system_program::transfer(cpi_context, amount)?;
        transfer_state.stage = Stage::FundsDeposited.to_code();
        
        Ok(())
    }

    pub fn cancel_sol(ctx: Context<CancelSol>, transfer_idx: u64) -> Result<()> {
        
        let current_stage = Stage::from(ctx.accounts.transfer_state.stage)?;
        let is_valid_stage = current_stage == Stage::FundsDeposited || current_stage == Stage::PullBackComplete;
        if !is_valid_stage {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.transfer_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let amount = ctx.accounts.transfer_state.amount;
        let seed0 = b"state";
        let seed1 = transfer_idx.to_le_bytes(); 
        let seed2 = ctx.accounts.sender.key();
        let seed3 = ctx.accounts.receiver.key();

        let (_transfer_state, _transfer_state_bump) =
            Pubkey::find_program_address(&[
                seed0.as_ref(),
                seed1.as_ref(),
                seed2.as_ref(),
                seed3.as_ref()
            ],    
            ctx.program_id);
   
        if ctx.accounts.transfer_state.key() != _transfer_state {
            panic!("Escrow account is not correct.");
        }

        **ctx.accounts.transfer_state.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.sender.try_borrow_mut_lamports()? += amount;
  
        Ok(())
    }
    
    pub fn transfer_sol(ctx: Context<TransferSol>, transfer_idx: u64) -> Result<()> {
        if Stage::from(ctx.accounts.transfer_state.stage)? != Stage::FundsDeposited {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.transfer_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let amount = ctx.accounts.transfer_state.amount;
        let seed0 = b"state";
        let seed1 = transfer_idx.to_le_bytes(); 
        let seed2 = ctx.accounts.sender.key();
        let seed3 = ctx.accounts.receiver.key();

        let (_transfer_state, _transfer_state_bump) =
            Pubkey::find_program_address(&[
                seed0.as_ref(),
                seed1.as_ref(),
                seed2.as_ref(),
                seed3.as_ref()
            ],    
            ctx.program_id);
   
        if ctx.accounts.transfer_state.key() != _transfer_state {
            panic!("Escrow account is not correct.");
        }

        **ctx.accounts.transfer_state.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.receiver.try_borrow_mut_lamports()? += amount;

        Ok(())
    }

    pub fn initialize_token(ctx: Context<InitializeToken>, transfer_idx: u64, amount: u64) -> ProgramResult {
        
        let state = &mut ctx.accounts.transfer_state;
        state.transfer_idx = transfer_idx;
        state.sender = ctx.accounts.sender.key().clone();
        state.receiver = ctx.accounts.receiver.key().clone();
        state.escrow_wallet = ctx.accounts.escrow_wallet.key().clone();
        state.mint = ctx.accounts.mint.key().clone();
        state.amount = amount;

        msg!("Initialized new Safe Transfer Token for {}", amount);
       
        let transfer_instruction = Transfer{
            from: ctx.accounts.token_withdraw.to_account_info(),
            to: ctx.accounts.escrow_wallet.to_account_info(),
            authority: ctx.accounts.sender.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
        );

        anchor_spl::token::transfer(cpi_ctx, amount)?;
        state.stage = Stage::FundsDeposited.to_code();
        
        Ok(())
    }

    pub fn transfer_token(ctx: Context<TransferToken>, transfer_idx: u64) -> Result<()> {
        if Stage::from(ctx.accounts.transfer_state.stage)? != Stage::FundsDeposited {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.transfer_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let amount = ctx.accounts.transfer_state.amount;
        let bump = *ctx.bumps.get("transfer_state").unwrap();
        let seed0 = b"state";
        let seed1 = transfer_idx.to_le_bytes(); 
        let seed2 = ctx.accounts.sender.key();
        let seed3 = ctx.accounts.receiver.key();
        let seed4 = ctx.accounts.mint.key();
        let seed5 = [bump];
   
        let inner = vec![
            seed0.as_ref(),
            seed1.as_ref(),
            seed2.as_ref(),
            seed3.as_ref(),
            seed4.as_ref(),
            seed5.as_ref(),
        ];
        
        let outer = vec![inner.as_slice()];

        let transfer_instruction = Transfer{
            from: ctx.accounts.escrow_wallet.to_account_info(),
            to:   ctx.accounts.token_deposit.to_account_info(),
            authority: ctx.accounts.transfer_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );
        anchor_spl::token::transfer(cpi_ctx, amount)?;

        let cpi_accounts  = CloseAccount{
            account: ctx.accounts.escrow_wallet.to_account_info(),
            destination: ctx.accounts.sender.to_account_info(),
            authority: ctx.accounts.transfer_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts ,
            outer.as_slice(),
        );
        anchor_spl::token::close_account(cpi_ctx)?;
 
        Ok(())
    }

    pub fn cancel_token(ctx: Context<CancelToken>, transfer_idx: u64) -> Result<()> {
        
        let current_stage = Stage::from(ctx.accounts.transfer_state.stage)?;
        let is_valid_stage = current_stage == Stage::FundsDeposited || current_stage == Stage::PullBackComplete;
        if !is_valid_stage {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.transfer_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let amount = ctx.accounts.transfer_state.amount;
        let bump = *ctx.bumps.get("transfer_state").unwrap();
        let seed0 = b"state";
        let seed1 = transfer_idx.to_le_bytes(); 
        let seed2 = ctx.accounts.sender.key();
        let seed3 = ctx.accounts.receiver.key();
        let seed4 = ctx.accounts.mint.key();
        let seed5 = [bump];
   
        let inner = vec![
            seed0.as_ref(),
            seed1.as_ref(),
            seed2.as_ref(),
            seed3.as_ref(),
            seed4.as_ref(),
            seed5.as_ref(),
        ];
        
        let outer = vec![inner.as_slice()];

        let transfer_instruction = Transfer{
            from: ctx.accounts.escrow_wallet.to_account_info(),
            to:   ctx.accounts.token_deposit.to_account_info(),
            authority: ctx.accounts.transfer_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );
        anchor_spl::token::transfer(cpi_ctx, amount)?;

        let cpi_accounts  = CloseAccount{
            account: ctx.accounts.escrow_wallet.to_account_info(),
            destination: ctx.accounts.sender.to_account_info(),
            authority: ctx.accounts.transfer_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts ,
            outer.as_slice(),
        );
        anchor_spl::token::close_account(cpi_ctx)?;
         
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


#[derive(Accounts)]
#[instruction(transfer_idx: u64,amount: u64)]
pub struct InitializeSol<'info>{
    #[account(mut)]
    sender: Signer<'info>,    
    /// CHECK: This is not dangerous because the program doesn't read or write from this account               
    receiver: AccountInfo<'info>,
    
    #[account(
        init,
        payer = sender,
        seeds = [ b"state".as_ref(),
                  transfer_idx.to_le_bytes().as_ref(),
                  sender.key().as_ref(),
                  receiver.key().as_ref()],
        bump,
        space = TransferState::space(),
    )]
    transfer_state: Account<'info, TransferState>,
  
    system_program: Program<'info, System>,
    //token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
#[instruction(transfer_idx: u64)]
pub struct CancelSol<'info> {
    #[account(mut)]
    sender: Signer<'info>,
    /// CHECK: "no signature required"
    receiver: AccountInfo<'info>,
    #[account(
        mut,
        seeds=[b"state".as_ref(), 
               transfer_idx.to_le_bytes().as_ref(),        
               sender.key().as_ref(), 
               receiver.key.as_ref()], 
        bump,
        has_one = sender,
        has_one = receiver,
        close = sender,
    )]
    transfer_state: Account<'info, TransferState>,
    system_program: Program<'info, System>,
}


#[derive(Accounts)]
#[instruction(transfer_idx: u64)]
pub struct TransferSol<'info> {
    /// CHECK: "no signature required"
    #[account(mut)]
    sender: AccountInfo<'info>,
    #[account(mut)]
    receiver: Signer<'info>,

    #[account(
        mut,
        seeds=[b"state".as_ref(), 
               transfer_idx.to_le_bytes().as_ref(),
               sender.key().as_ref(), 
               receiver.key.as_ref()], 
        bump,
        has_one = sender,
        has_one = receiver,
        close = sender,
    )]
    transfer_state: Account<'info, TransferState>,
    
    system_program: Program<'info, System>,
    //token_program: Program<'info, Token>, 
}


#[derive(Accounts)]
#[instruction(transfer_idx: u64,amount: u64)]
pub struct InitializeToken<'info>{
    #[account(mut)]
    sender: Signer<'info>,    
    /// CHECK: This is not dangerous because the program doesn't read or write from this account               
    receiver: AccountInfo<'info>,              
    mint: Account<'info, Mint>,  
    #[account(
        mut,
        constraint = token_withdraw.amount >= amount,
        constraint = token_withdraw.owner == sender.key(),
        constraint = token_withdraw.mint  == mint.key(),
    )]
    token_withdraw: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = sender,
        seeds = [ b"state".as_ref(),
                  transfer_idx.to_le_bytes().as_ref(),
                  sender.key().as_ref(),
                  receiver.key().as_ref(),
                  mint.key().as_ref()],
        bump,
        space = TransferState::space(),
    )]
    transfer_state: Account<'info, TransferState>,

    #[account(
        init,
        payer = sender,
        seeds = [ b"wallet".as_ref(),
                  transfer_idx.to_le_bytes().as_ref(),
                  sender.key().as_ref(),
                  receiver.key().as_ref(),
                  mint.key().as_ref(),],
        bump,
        token::mint=mint,
        token::authority=transfer_state,
    )]
    escrow_wallet: Account<'info, TokenAccount>,
    
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
#[instruction(transfer_idx: u64)]
pub struct CancelToken<'info> {
    #[account(mut)]
    sender: Signer<'info>,
    /// CHECK: "no signature required"
    receiver: AccountInfo<'info>,
    mint: Account<'info, Mint>,
    // escrow deposit to
    #[account(
        mut,
        constraint=token_deposit.mint == mint.key(),
        constraint=token_deposit.owner == sender.key(),
    )]
    token_deposit: Account<'info, TokenAccount>,
    #[account(
        mut,
        seeds=[b"state".as_ref(), 
               transfer_idx.to_le_bytes().as_ref(),        
               sender.key().as_ref(), 
               receiver.key.as_ref(), 
               mint.key().as_ref() ],
        bump,
        has_one = sender,
        has_one = receiver,
        has_one = mint,
        close = sender,
    )]
    transfer_state: Account<'info, TransferState>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), 
               transfer_idx.to_le_bytes().as_ref(),        
               sender.key().as_ref(), 
               receiver.key.as_ref(), 
               mint.key().as_ref() ],
        bump,
    )]
    escrow_wallet: Account<'info, TokenAccount>,
    token_program: Program<'info, Token>,   
}


#[derive(Accounts)]
#[instruction(transfer_idx: u64)]
pub struct TransferToken<'info> {
    /// CHECK: "no signature required"
    #[account(mut)]
    sender: AccountInfo<'info>,
    #[account(mut)]
    receiver: Signer<'info>,
    mint: Account<'info, Mint>,
    // escrow deposit to
    #[account(
        mut,
        constraint=token_deposit.mint == mint.key(),
        constraint=token_deposit.owner == receiver.key(),
    )]
    token_deposit: Account<'info, TokenAccount>,
    #[account(
        mut,
        seeds=[b"state".as_ref(), 
               transfer_idx.to_le_bytes().as_ref(),
               sender.key().as_ref(), 
               receiver.key.as_ref(), 
               mint.key().as_ref(), ],
        bump,
        has_one = sender,
        has_one = receiver,
        has_one = mint,
        close = sender,
    )]
    transfer_state: Account<'info, TransferState>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), 
               transfer_idx.to_le_bytes().as_ref(),
               sender.key().as_ref(), 
               receiver.key.as_ref(), 
               mint.key().as_ref(), ],
        bump,
    )]
    escrow_wallet: Account<'info, TokenAccount>,    
  
    //system_program: Program<'info, System>,
    token_program: Program<'info, Token>, 
}

#[account]
#[derive(Default)]
pub struct TransferState {
    transfer_idx: u64,
    sender: Pubkey,
    receiver: Pubkey,
    escrow_wallet: Pubkey,
    mint: Pubkey,
    amount: u64,
    stage: u8,
}

impl TransferState {
    pub fn space() -> usize {
        8 + 4*32 + 2*8 + 1
    }
}

