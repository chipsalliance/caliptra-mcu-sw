// Licensed under the Apache-2.0 license
//
// Derived from OpenTitan project with original copyright:
//
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::iter;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use thiserror::Error;

use caliptra_hw_model::lcc::{LcCtrlReg, LcCtrlStatus, LcCtrlTransitionCmd};
use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagTap, OpenOcdJtagTap};
use mcu_rom_common::{Lifecycle, LifecycleControllerState};
use poll_common::poll_until;

/// Errors related to the LCC operations below.
#[derive(Error, Debug)]
pub enum LccUtilError {
    #[error("LCC is not initialized; STATUS: {0}")]
    NotInitialized(u32),
    #[error("LCC transition mutex is already claimed.")]
    MutexAlreadyClaimed,
    #[error("Failed to claim the LCC transition mutex (value = 0x{0:x}).")]
    FailedToClaimMutex(u32),
    #[error("Bad post transition state (state = {0}).")]
    BadPostTransitionState(String),
    #[error("Functionality unimplemented.")]
    Unimplemented,
}

pub fn lc_token_to_words(bytes: &[u8; 16]) -> [u32; 4] {
    let mut out_words = [0u32; 4];
    bytes
        .chunks_exact(std::mem::size_of::<u32>())
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .zip(&mut out_words)
        .for_each(|(word, out)| *out = word);
    out_words
}

/// Read the LC state.
pub fn read_lc_state(tap: &mut OpenOcdJtagTap) -> Result<LifecycleControllerState> {
    // Check the LCC is initialized and ready.
    let lcc_status = tap.read_lc_ctrl_reg(&LcCtrlReg::Status)?;
    if LcCtrlStatus::from_bits_truncate(lcc_status)
        != LcCtrlStatus::INITIALIZED | LcCtrlStatus::READY
    {
        bail!(LccUtilError::NotInitialized(lcc_status));
    }

    // Read the state register.
    let lc_state = LifecycleControllerState::from(tap.read_lc_ctrl_reg(&LcCtrlReg::LcState)?);

    Ok(lc_state)
}

/// Perform an LC transition.
pub fn lc_transition(
    tap: &mut OpenOcdJtagTap,
    target_lc_state: LifecycleControllerState,
    token: Option<[u32; 4]>,
) -> Result<LifecycleControllerState> {
    // Check the LCC is initialized and ready.
    let lcc_status = tap.read_lc_ctrl_reg(&LcCtrlReg::Status)?;
    if LcCtrlStatus::from_bits_truncate(lcc_status)
        != LcCtrlStatus::INITIALIZED | LcCtrlStatus::READY
    {
        bail!(LccUtilError::NotInitialized(lcc_status));
    }

    // Attempt to claim the LC transition mutex if it has not been claimed yet.
    const MULTI_TRUE: u32 = 0x96;
    if tap.read_lc_ctrl_reg(&LcCtrlReg::ClaimTransitionIf)? == MULTI_TRUE {
        bail!(LccUtilError::MutexAlreadyClaimed);
    }
    tap.write_lc_ctrl_reg(&LcCtrlReg::ClaimTransitionIf, MULTI_TRUE)?;
    let mutex_val = tap.read_lc_ctrl_reg(&LcCtrlReg::ClaimTransitionIf)?;
    if mutex_val != MULTI_TRUE {
        bail!(LccUtilError::FailedToClaimMutex(mutex_val));
    }

    // Program the target LC state.
    tap.write_lc_ctrl_reg(
        &LcCtrlReg::TransitionTarget,
        Lifecycle::calc_lc_state_mnemonic(target_lc_state),
    )?;

    // If the transition requires a token, write it to the multi-register.
    if let Some(token_words) = token {
        let token_regs = [
            &LcCtrlReg::TransitionToken0,
            &LcCtrlReg::TransitionToken1,
            &LcCtrlReg::TransitionToken2,
            &LcCtrlReg::TransitionToken3,
        ];

        for (reg, value) in iter::zip(token_regs, token_words) {
            tap.write_lc_ctrl_reg(reg, value)?;
        }
    }

    // Start the LC transition and wait for completion.
    tap.write_lc_ctrl_reg(&LcCtrlReg::TransitionCmd, LcCtrlTransitionCmd::START.bits())?;
    wait_for_status(
        tap,
        Duration::from_secs(3),
        LcCtrlStatus::TRANSITION_SUCCESSFUL,
    )
    .context("failed waiting for TRANSITION_SUCCESSFUL status.")?;

    // Check we have entered the post transition state.
    let post_transition_lc_state =
        LifecycleControllerState::from(tap.read_lc_ctrl_reg(&LcCtrlReg::LcState)?);
    if post_transition_lc_state != LifecycleControllerState::PostTransition {
        bail!(LccUtilError::BadPostTransitionState(
            post_transition_lc_state.to_string()
        ));
    }
    Ok(post_transition_lc_state)
}

fn wait_for_status(
    tap: &mut OpenOcdJtagTap,
    timeout: Duration,
    status: LcCtrlStatus,
) -> Result<()> {
    // Wait for LC controller to be ready.
    poll_until(timeout, Duration::from_millis(50), || {
        let polled_status = match tap.tap() {
            JtagTap::LccTap => tap.read_lc_ctrl_reg(&LcCtrlReg::Status).unwrap(),
            JtagTap::CaliptraCoreTap => bail!(LccUtilError::Unimplemented),
            JtagTap::CaliptraMcuTap => bail!(LccUtilError::Unimplemented),
            JtagTap::NoTap => bail!(LccUtilError::Unimplemented),
        };

        let polled_status =
            LcCtrlStatus::from_bits(polled_status).context("status has invalid bits set")?;

        // Check for any error bits set - however, we exclude the status that
        // we are looking for in this comparison, since otherwise this
        // function would just bail.
        if polled_status.intersects(LcCtrlStatus::ERRORS & !status) {
            bail!("status {polled_status:#b} has error bits set");
        }

        Ok(polled_status.contains(status))
    })
}
