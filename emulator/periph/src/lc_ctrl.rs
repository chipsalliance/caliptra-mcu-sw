/*++

Licensed under the Apache-2.0 license.

File Name:

    lc_ctrl.rs

Abstract:

    OpenTitan Lifecycle controller emulated device.
    Supports lifecycle state reads, transitions with token verification,
    and OTP fuse updates on successful transitions.

--*/

use std::cell::RefCell;
use std::rc::Rc;

use caliptra_emu_bus::ReadWriteRegister;
use emulator_registers_generated::lc::LcGenerated;
use registers_generated::lc_ctrl;
use tock_registers::interfaces::Readable;

#[cfg(test)]
use crate::otp_scramble;
use crate::otp_unscramble;

// OTP partition offsets (from registers_generated::fuses).
const SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET: usize =
    registers_generated::fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET;
const LIFE_CYCLE_BYTE_OFFSET: usize = registers_generated::fuses::LIFE_CYCLE_BYTE_OFFSET;

// OTP scramble key for the LC tokens partition (OTP_SCRAMBLE_KEYS[6]).
// Source: caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson
const LC_TOKENS_SCRAMBLE_KEY: u128 = 0xB7474D640F8A7F5D60822E1FAEC5C72;

// Hardcoded raw unlock token matching the caliptra-ss RTL netlist constant.
// Source: caliptra-ss/src/lc_ctrl/rtl/lc_ctrl_pkg.sv (RndCnstRawUnlockToken)
const RAW_UNLOCK_TOKEN: [u8; 16] = [
    0xca, 0xa0, 0x32, 0xb5, 0x87, 0x96, 0xce, 0x74, 0x9a, 0xef, 0xec, 0xa2, 0x65, 0xbe, 0x41, 0x61,
];

const MUTEX_TRUE: u32 = 0x96;
const MUTEX_FALSE: u32 = 0x69;
const MAX_TRANSITION_COUNT: u32 = 24;

// Status register bits.
const STATUS_INITIALIZED: u32 = 1 << 0;
const STATUS_READY: u32 = 1 << 1;
const STATUS_TRANSITION_SUCCESSFUL: u32 = 1 << 3;
const STATUS_TRANSITION_COUNT_ERROR: u32 = 1 << 4;
const STATUS_TRANSITION_ERROR: u32 = 1 << 5;
const STATUS_TOKEN_ERROR: u32 = 1 << 6;
const STATUS_OTP_ERROR: u32 = 1 << 8;

// Lifecycle state indices from the shared otp-lifecycle crate.
use mcu_otp_lifecycle::LifecycleControllerState as LcState;
const RAW: u32 = LcState::Raw as u32;
const TEST_UNLOCKED0: u32 = LcState::TestUnlocked0 as u32;
const TEST_LOCKED0: u32 = LcState::TestLocked0 as u32;
const TEST_UNLOCKED7: u32 = LcState::TestUnlocked7 as u32;
const DEV: u32 = LcState::Dev as u32;
const PROD: u32 = LcState::Prod as u32;
const PROD_END: u32 = LcState::ProdEnd as u32;
const RMA: u32 = LcState::Rma as u32;
const SCRAP: u32 = LcState::Scrap as u32;
const POST_TRANSITION: u32 = LcState::PostTransition as u32;

/// Compute the 30-bit LC state mnemonic from a 5-bit state index
/// by replicating it 6 times across the 30-bit field.
fn calc_lc_state_mnemonic(state_5bit: u32) -> u32 {
    let s = state_5bit & 0x1F;
    (s << 25) | (s << 20) | (s << 15) | (s << 10) | (s << 5) | s
}

/// Decode a 30-bit mnemonic back to a 5-bit state index.
/// Returns None if the mnemonic is not a valid 6x-replicated value.
fn decode_lc_state_mnemonic(mnemonic: u32) -> Option<u32> {
    let s = mnemonic & 0x1F;
    if calc_lc_state_mnemonic(s) == mnemonic {
        Some(s)
    } else {
        None
    }
}

use mcu_otp_lifecycle::hash_lc_token;

/// What token (if any) a valid transition requires.
enum TokenRequirement {
    /// No token needed (unconditional transition).
    None,
    /// Raw unlock token (netlist constant, not from OTP).
    RawUnlock,
    /// Token at the given index in the OTP LC tokens partition.
    OtpToken(usize),
}

/// Check whether (from_state, to_state) is a legal transition and
/// return the token requirement. Returns `None` for illegal transitions.
fn validate_transition(from: u32, to: u32) -> Option<TokenRequirement> {
    // TestUnlocked(N) states have odd indices 1,3,5,...,15
    // TestLocked(N) states have even indices 2,4,6,...,14
    let is_test_unlocked = |s: u32| (TEST_UNLOCKED0..=TEST_UNLOCKED7).contains(&s) && s % 2 == 1;
    let is_test_locked = |s: u32| (TEST_LOCKED0..=14).contains(&s) && s % 2 == 0;

    match (from, to) {
        // Raw -> TestUnlocked0: hardcoded raw unlock token
        (RAW, TEST_UNLOCKED0) => Some(TokenRequirement::RawUnlock),
        // Raw -> Scrap: unconditional
        (RAW, SCRAP) => Some(TokenRequirement::None),
        // TestUnlocked(N) -> TestLocked(N): unconditional (N=0..6)
        (f, t) if is_test_unlocked(f) && t == f + 1 && is_test_locked(t) => {
            Some(TokenRequirement::None)
        }
        // TestLocked(N) -> TestUnlocked(N+1): test_unlock token
        // TestLocked0(2) -> TestUnlocked1(3): test_unlock[0]
        // TestLocked6(14) -> TestUnlocked7(15): test_unlock[6]
        (f, t) if is_test_locked(f) && t == f + 1 && is_test_unlocked(t) => {
            let token_idx = (f - TEST_LOCKED0) / 2;
            Some(TokenRequirement::OtpToken(token_idx as usize))
        }
        // TestUnlocked7 -> Dev: manuf token (index 7)
        (TEST_UNLOCKED7, DEV) => Some(TokenRequirement::OtpToken(7)),
        // Dev -> Prod: manuf_to_prod token (index 8)
        (DEV, PROD) => Some(TokenRequirement::OtpToken(8)),
        // Dev -> Rma: rma token (index 10)
        (DEV, RMA) => Some(TokenRequirement::OtpToken(10)),
        // Prod -> ProdEnd: prod_to_prod_end token (index 9)
        (PROD, PROD_END) => Some(TokenRequirement::OtpToken(9)),
        // Prod -> Rma: rma token (index 10)
        (PROD, RMA) => Some(TokenRequirement::OtpToken(10)),
        // Any non-terminal state -> Scrap: unconditional
        (f, SCRAP) if is_test_unlocked(f) || is_test_locked(f) => Some(TokenRequirement::None),
        (DEV, SCRAP) | (PROD, SCRAP) | (PROD_END, SCRAP) | (RMA, SCRAP) => {
            Some(TokenRequirement::None)
        }
        _ => Option::None,
    }
}

pub struct LcCtrl {
    status: ReadWriteRegister<u32, lc_ctrl::bits::Status::Register>,
    /// Current lifecycle state index (5-bit, 0-21).
    lc_state_index: u32,
    /// Lifecycle transition count.
    lc_transition_cnt: u32,
    generated: LcGenerated,

    // Transition protocol state.
    mutex_claimed: bool,
    transition_target: u32,
    token: [u32; 4],

    /// Shared reference to OTP partition data for token reads and state writes.
    otp_partitions: Option<Rc<RefCell<Vec<u8>>>>,
}

impl Default for LcCtrl {
    fn default() -> Self {
        Self::with_state(0, 0)
    }
}

impl LcCtrl {
    /// Create an LC controller with shared OTP partition access for transitions.
    pub fn new(
        lc_state_index: u32,
        lc_transition_cnt: u32,
        otp_partitions: Rc<RefCell<Vec<u8>>>,
    ) -> Self {
        let mut ctrl = Self::with_state(lc_state_index, lc_transition_cnt);
        ctrl.otp_partitions = Some(otp_partitions);
        ctrl
    }

    /// Create an LC controller without OTP access (read-only, no transitions).
    pub fn with_state(lc_state_index: u32, lc_transition_cnt: u32) -> Self {
        Self {
            status: (STATUS_INITIALIZED | STATUS_READY).into(),
            lc_state_index,
            lc_transition_cnt,
            generated: LcGenerated::default(),
            mutex_claimed: false,
            transition_target: 0,
            token: [0; 4],
            otp_partitions: None,
        }
    }

    /// Provide OTP partition access after construction.
    pub fn set_otp_partitions(&mut self, otp: Rc<RefCell<Vec<u8>>>) {
        self.otp_partitions = Some(otp);
    }

    /// Re-read lifecycle state from OTP and reset transient state.
    /// Called on warm/cold reset so the new LC state takes effect.
    fn reload_from_otp(&mut self) {
        if let Some(otp) = &self.otp_partitions {
            let otp = otp.borrow();
            let start = LIFE_CYCLE_BYTE_OFFSET;
            let end = start + mcu_otp_lifecycle::LIFECYCLE_MEM_SIZE;
            if end <= otp.len() && otp[start..end].iter().any(|&b| b != 0) {
                let mut mem = [0u8; mcu_otp_lifecycle::LIFECYCLE_MEM_SIZE];
                mem.copy_from_slice(&otp[start..end]);
                if let Ok((state_idx, count)) = mcu_otp_lifecycle::lc_decode_memory(&mem) {
                    self.lc_state_index = state_idx as u32;
                    self.lc_transition_cnt = count as u32;
                }
            }
        }
        self.status = (STATUS_INITIALIZED | STATUS_READY).into();
        self.mutex_claimed = false;
        self.transition_target = 0;
        self.token = [0; 4];
    }

    fn token_as_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for (i, word) in self.token.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Read a 16-byte hashed token from the OTP LC tokens partition,
    /// descrambling it in the process.
    fn read_otp_token(&self, token_index: usize) -> Option<[u8; 16]> {
        let otp = self.otp_partitions.as_ref()?;
        let otp = otp.borrow();
        let base = SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET + token_index * 16;
        if base + 16 > otp.len() {
            return None;
        }
        let mut token_data = [0u8; 16];
        token_data.copy_from_slice(&otp[base..base + 16]);
        // Descramble: tokens are stored scrambled in 8-byte blocks.
        for chunk in token_data.chunks_exact_mut(8) {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            let unscrambled = otp_unscramble(val, LC_TOKENS_SCRAMBLE_KEY);
            chunk.copy_from_slice(&unscrambled.to_le_bytes());
        }
        Some(token_data)
    }

    /// Write the new lifecycle state and transition count to OTP.
    fn write_mcu_otp_lifecycle(&self, state_index: u8, transition_count: u8) {
        let Some(otp) = &self.otp_partitions else {
            return;
        };
        let Ok(mem) = mcu_otp_lifecycle::lc_generate_memory(state_index, transition_count) else {
            return;
        };
        let mut otp = otp.borrow_mut();
        let start = LIFE_CYCLE_BYTE_OFFSET;
        let end = start + mem.len();
        if end <= otp.len() {
            otp[start..end].copy_from_slice(&mem);
        }
    }

    /// Execute the transition. Called when the ROM writes 1 to transition_cmd.
    fn execute_transition(&mut self) {
        let target_mnemonic = self.transition_target & 0x3FFF_FFFF;
        let target_index = match decode_lc_state_mnemonic(target_mnemonic) {
            Some(idx) if idx <= POST_TRANSITION => idx,
            _ => {
                self.transition_error(STATUS_TRANSITION_ERROR);
                return;
            }
        };

        if self.lc_transition_cnt >= MAX_TRANSITION_COUNT {
            self.transition_error(STATUS_TRANSITION_COUNT_ERROR);
            return;
        }

        // Increment counter before token check (hardware does this to prevent
        // brute-force attempts even on failed transitions).
        self.lc_transition_cnt += 1;

        let token_req = match validate_transition(self.lc_state_index, target_index) {
            Some(req) => req,
            None => {
                self.transition_error(STATUS_TRANSITION_ERROR);
                return;
            }
        };

        match token_req {
            TokenRequirement::None => {}
            TokenRequirement::RawUnlock => {
                if self.token_as_bytes() != RAW_UNLOCK_TOKEN {
                    self.transition_error(STATUS_TOKEN_ERROR);
                    return;
                }
            }
            TokenRequirement::OtpToken(index) => {
                let supplied_hash = hash_lc_token(&self.token_as_bytes());
                let expected_hash = match self.read_otp_token(index) {
                    Some(h) => h,
                    None => {
                        self.transition_error(STATUS_OTP_ERROR);
                        return;
                    }
                };
                if supplied_hash != expected_hash {
                    self.transition_error(STATUS_TOKEN_ERROR);
                    return;
                }
            }
        }

        // Success: update OTP, enter PostTransition.
        self.write_mcu_otp_lifecycle(target_index as u8, self.lc_transition_cnt as u8);

        self.lc_state_index = POST_TRANSITION;
        self.status = (STATUS_INITIALIZED | STATUS_READY | STATUS_TRANSITION_SUCCESSFUL).into();
    }

    fn transition_error(&mut self, error_bit: u32) {
        self.lc_state_index = POST_TRANSITION;
        self.status = (STATUS_INITIALIZED | error_bit).into();
    }
}

impl emulator_registers_generated::lc::LcPeripheral for LcCtrl {
    fn generated(&mut self) -> Option<&mut LcGenerated> {
        Some(&mut self.generated)
    }

    fn warm_reset(&mut self) {
        self.reload_from_otp();
    }

    fn read_status(&mut self) -> ReadWriteRegister<u32, lc_ctrl::bits::Status::Register> {
        ReadWriteRegister::new(self.status.reg.get())
    }

    fn read_lc_state(&mut self) -> ReadWriteRegister<u32, lc_ctrl::bits::LcState::Register> {
        ReadWriteRegister::new(calc_lc_state_mnemonic(self.lc_state_index))
    }

    fn read_lc_transition_cnt(
        &mut self,
    ) -> ReadWriteRegister<u32, lc_ctrl::bits::LcTransitionCnt::Register> {
        ReadWriteRegister::new(self.lc_transition_cnt)
    }

    fn read_claim_transition_if(
        &mut self,
    ) -> ReadWriteRegister<u32, lc_ctrl::bits::ClaimTransitionIf::Register> {
        let val = if self.mutex_claimed {
            MUTEX_TRUE
        } else {
            MUTEX_FALSE
        };
        ReadWriteRegister::new(val)
    }

    fn write_claim_transition_if(
        &mut self,
        val: ReadWriteRegister<u32, lc_ctrl::bits::ClaimTransitionIf::Register>,
    ) {
        let v = val.reg.get() & 0xFF;
        if v == MUTEX_TRUE {
            self.mutex_claimed = true;
        } else {
            self.mutex_claimed = false;
            self.transition_target = 0;
            self.token = [0; 4];
        }
    }

    fn write_transition_target(
        &mut self,
        val: ReadWriteRegister<u32, lc_ctrl::bits::TransitionTarget::Register>,
    ) {
        if self.mutex_claimed {
            self.transition_target = val.reg.get();
        }
    }

    fn write_transition_token_0(&mut self, val: caliptra_emu_types::RvData) {
        if self.mutex_claimed {
            self.token[0] = val;
        }
    }

    fn write_transition_token_1(&mut self, val: caliptra_emu_types::RvData) {
        if self.mutex_claimed {
            self.token[1] = val;
        }
    }

    fn write_transition_token_2(&mut self, val: caliptra_emu_types::RvData) {
        if self.mutex_claimed {
            self.token[2] = val;
        }
    }

    fn write_transition_token_3(&mut self, val: caliptra_emu_types::RvData) {
        if self.mutex_claimed {
            self.token[3] = val;
        }
    }

    fn write_transition_cmd(
        &mut self,
        val: ReadWriteRegister<u32, lc_ctrl::bits::TransitionCmd::Register>,
    ) {
        if self.mutex_claimed && (val.reg.get() & 1) != 0 {
            self.execute_transition();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mcu_otp_lifecycle::LIFECYCLE_MEM_SIZE;

    /// Build OTP partition data with provisioned tokens and a given LC state.
    fn make_otp_data(state_index: u8, transition_count: u8, raw_token: &[u8; 16]) -> Vec<u8> {
        // Need enough space for the lifecycle partition (offset 0xc80 + 0x58).
        let size = LIFE_CYCLE_BYTE_OFFSET + LIFECYCLE_MEM_SIZE;
        let mut data = vec![0u8; size];

        // Provision LC tokens at SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET.
        // 11 tokens * 16 bytes = 176 bytes of token data (+ 8 byte digest = 184 total).
        let hashed = hash_lc_token(raw_token);
        for i in 0..11 {
            let mut token_copy = hashed;
            // Scramble each 8-byte block before storing.
            for chunk in token_copy.chunks_exact_mut(8) {
                let val = u64::from_le_bytes(chunk.try_into().unwrap());
                let scrambled = otp_scramble(val, LC_TOKENS_SCRAMBLE_KEY);
                chunk.copy_from_slice(&scrambled.to_le_bytes());
            }
            let offset = SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET + i * 16;
            data[offset..offset + 16].copy_from_slice(&token_copy);
        }

        // Provision LC state.
        let lc_mem = mcu_otp_lifecycle::lc_generate_memory(state_index, transition_count).unwrap();
        data[LIFE_CYCLE_BYTE_OFFSET..LIFE_CYCLE_BYTE_OFFSET + LIFECYCLE_MEM_SIZE]
            .copy_from_slice(&lc_mem);

        data
    }

    fn make_lc_ctrl(state_index: u32, count: u32, raw_token: &[u8; 16]) -> LcCtrl {
        let otp = Rc::new(RefCell::new(make_otp_data(
            state_index as u8,
            count as u8,
            raw_token,
        )));
        LcCtrl::new(state_index, count, otp)
    }

    /// Helper: perform a full transition protocol on an LcCtrl.
    fn do_transition(lc: &mut LcCtrl, target_state: u32, token_words: [u32; 4]) -> u32 {
        use emulator_registers_generated::lc::LcPeripheral;

        // Claim mutex
        lc.write_claim_transition_if(ReadWriteRegister::new(MUTEX_TRUE));
        assert_eq!(lc.read_claim_transition_if().reg.get(), MUTEX_TRUE);

        // Set target
        let mnemonic = calc_lc_state_mnemonic(target_state);
        lc.write_transition_target(ReadWriteRegister::new(mnemonic));

        // Set token
        lc.write_transition_token_0(token_words[0]);
        lc.write_transition_token_1(token_words[1]);
        lc.write_transition_token_2(token_words[2]);
        lc.write_transition_token_3(token_words[3]);

        // Trigger
        lc.write_transition_cmd(ReadWriteRegister::new(1));

        lc.read_status().reg.get()
    }

    fn token_to_words(token: &[u8; 16]) -> [u32; 4] {
        let mut words = [0u32; 4];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes(token[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        words
    }

    const TEST_RAW_TOKEN: [u8; 16] = [
        0x57, 0x5e, 0xd6, 0xcf, 0x32, 0x17, 0x18, 0xde, 0x30, 0xc8, 0xfc, 0x08, 0xc6, 0xb8, 0xed,
        0x05,
    ];

    #[test]
    fn test_mnemonic_roundtrip() {
        for i in 0..=21 {
            let m = calc_lc_state_mnemonic(i);
            assert_eq!(decode_lc_state_mnemonic(m), Some(i));
        }
        assert_eq!(decode_lc_state_mnemonic(0x12345678), None);
    }

    #[test]
    fn test_raw_to_test_unlocked0() {
        let mut lc = make_lc_ctrl(RAW, 0, &TEST_RAW_TOKEN);
        let token_words = token_to_words(&RAW_UNLOCK_TOKEN);
        let status = do_transition(&mut lc, TEST_UNLOCKED0, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);
        assert_eq!(lc.lc_state_index, POST_TRANSITION);
        assert_eq!(lc.lc_transition_cnt, 1);
    }

    #[test]
    fn test_raw_to_test_unlocked0_wrong_token() {
        let mut lc = make_lc_ctrl(RAW, 0, &TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, TEST_UNLOCKED0, [0xdead, 0xbeef, 0xcafe, 0xbabe]);
        assert_ne!(status & STATUS_TOKEN_ERROR, 0);
    }

    #[test]
    fn test_unconditional_transition() {
        // TestUnlocked0 -> TestLocked0: no token needed.
        let mut lc = make_lc_ctrl(TEST_UNLOCKED0, 1, &TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, TEST_LOCKED0, [0; 4]);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);
        assert_eq!(lc.lc_transition_cnt, 2);
    }

    #[test]
    fn test_locked_to_unlocked_with_token() {
        // TestLocked0 -> TestUnlocked1: needs test_unlock[0] token.
        let mut lc = make_lc_ctrl(TEST_LOCKED0, 2, &TEST_RAW_TOKEN);
        let token_words = token_to_words(&TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, TEST_UNLOCKED0 + 2, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);
    }

    #[test]
    fn test_dev_to_prod() {
        let mut lc = make_lc_ctrl(DEV, 9, &TEST_RAW_TOKEN);
        let token_words = token_to_words(&TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, PROD, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);
    }

    #[test]
    fn test_prod_to_rma() {
        let mut lc = make_lc_ctrl(PROD, 10, &TEST_RAW_TOKEN);
        let token_words = token_to_words(&TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, RMA, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);
    }

    #[test]
    fn test_invalid_transition() {
        // Prod -> TestUnlocked0: not a valid transition.
        let mut lc = make_lc_ctrl(PROD, 10, &TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, TEST_UNLOCKED0, [0; 4]);
        assert_ne!(status & STATUS_TRANSITION_ERROR, 0);
    }

    #[test]
    fn test_scrap_no_transitions() {
        let mut lc = make_lc_ctrl(SCRAP, 20, &TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, RAW, [0; 4]);
        assert_ne!(status & STATUS_TRANSITION_ERROR, 0);
    }

    #[test]
    fn test_max_transition_count() {
        let mut lc = make_lc_ctrl(TEST_UNLOCKED0, MAX_TRANSITION_COUNT, &TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, TEST_LOCKED0, [0; 4]);
        assert_ne!(status & STATUS_TRANSITION_COUNT_ERROR, 0);
    }

    #[test]
    fn test_otp_updated_on_success() {
        let otp_data = make_otp_data(DEV as u8, 9, &TEST_RAW_TOKEN);
        let otp = Rc::new(RefCell::new(otp_data));
        let mut lc = LcCtrl::new(DEV, 9, otp.clone());

        let token_words = token_to_words(&TEST_RAW_TOKEN);
        let status = do_transition(&mut lc, PROD, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);

        // Decode the OTP lifecycle partition to verify it was updated.
        let otp_ref = otp.borrow();
        let lc_bytes: [u8; LIFECYCLE_MEM_SIZE] = otp_ref
            [LIFE_CYCLE_BYTE_OFFSET..LIFE_CYCLE_BYTE_OFFSET + LIFECYCLE_MEM_SIZE]
            .try_into()
            .unwrap();
        let (state_idx, count) = mcu_otp_lifecycle::lc_decode_memory(&lc_bytes).unwrap();
        assert_eq!(state_idx, PROD as u8);
        assert_eq!(count, 10);
    }

    #[test]
    fn test_mutex_required() {
        use emulator_registers_generated::lc::LcPeripheral;

        let mut lc = make_lc_ctrl(TEST_UNLOCKED0, 1, &TEST_RAW_TOKEN);

        // Write target without claiming mutex -- should be ignored.
        let mnemonic = calc_lc_state_mnemonic(TEST_LOCKED0);
        lc.write_transition_target(ReadWriteRegister::new(mnemonic));
        lc.write_transition_cmd(ReadWriteRegister::new(1));
        // Status should still be ready (no transition attempted).
        let status = lc.read_status().reg.get();
        assert_eq!(status, STATUS_INITIALIZED | STATUS_READY);
    }

    #[test]
    fn test_full_walkthrough() {
        // Walk through: TestUnlocked0 -> TestLocked0 -> TestUnlocked1 -> ... -> Dev -> Prod
        let token_words = token_to_words(&TEST_RAW_TOKEN);

        // State sequence: 1,2,3,4,...,15,16,17
        let states: Vec<u32> = (TEST_UNLOCKED0..=PROD).collect();

        let otp_data = make_otp_data(TEST_UNLOCKED0 as u8, 1, &TEST_RAW_TOKEN);
        let otp = Rc::new(RefCell::new(otp_data));

        for window in states.windows(2) {
            let from = window[0];
            let to = window[1];

            // Read current state from OTP for a fresh controller (simulating cold reset).
            let otp_ref = otp.borrow();
            let lc_bytes: [u8; LIFECYCLE_MEM_SIZE] = otp_ref
                [LIFE_CYCLE_BYTE_OFFSET..LIFE_CYCLE_BYTE_OFFSET + LIFECYCLE_MEM_SIZE]
                .try_into()
                .unwrap();
            let (state_idx, count) = mcu_otp_lifecycle::lc_decode_memory(&lc_bytes).unwrap();
            drop(otp_ref);

            assert_eq!(
                state_idx as u32, from,
                "expected state {from} before transition to {to}"
            );

            let mut lc = LcCtrl::new(state_idx as u32, count as u32, otp.clone());

            // Determine if token is needed.
            let needs_token = matches!(
                validate_transition(from, to),
                Some(TokenRequirement::OtpToken(_))
            );
            let tok = if needs_token { token_words } else { [0; 4] };

            let status = do_transition(&mut lc, to, tok);
            assert_ne!(
                status & STATUS_TRANSITION_SUCCESSFUL,
                0,
                "transition {from} -> {to} failed with status 0x{status:x}"
            );
        }

        // Verify final state is Prod.
        let otp_ref = otp.borrow();
        let lc_bytes: [u8; LIFECYCLE_MEM_SIZE] = otp_ref
            [LIFE_CYCLE_BYTE_OFFSET..LIFE_CYCLE_BYTE_OFFSET + LIFECYCLE_MEM_SIZE]
            .try_into()
            .unwrap();
        let (state_idx, _count) = mcu_otp_lifecycle::lc_decode_memory(&lc_bytes).unwrap();
        assert_eq!(state_idx, PROD as u8);
    }

    #[test]
    fn test_warm_reset_loads_new_state() {
        use emulator_registers_generated::lc::LcPeripheral;

        let mut lc = make_lc_ctrl(RAW, 1, &TEST_RAW_TOKEN);

        // Transition Raw -> TestUnlocked0.
        let token_words = token_to_words(&RAW_UNLOCK_TOKEN);
        let status = do_transition(&mut lc, TEST_UNLOCKED0, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);

        // Before warm_reset, state should be PostTransition.
        assert_eq!(lc.lc_state_index, POST_TRANSITION);

        // After warm_reset, state should be the target (TestUnlocked0).
        lc.warm_reset();
        assert_eq!(lc.lc_state_index, TEST_UNLOCKED0);
        assert_eq!(lc.lc_transition_cnt, 2);

        // Status should be reset to initialized + ready.
        let status = lc.read_status().reg.get();
        assert_ne!(status & STATUS_INITIALIZED, 0);
        assert_ne!(status & STATUS_READY, 0);
        assert_eq!(status & STATUS_TRANSITION_SUCCESSFUL, 0);
    }

    #[test]
    fn test_warm_reset_clears_mutex_and_token() {
        use emulator_registers_generated::lc::LcPeripheral;

        let mut lc = make_lc_ctrl(RAW, 1, &TEST_RAW_TOKEN);

        // Claim mutex and write a token.
        lc.write_claim_transition_if(ReadWriteRegister::new(MUTEX_TRUE));
        lc.write_transition_token_0(0xDEAD);
        assert!(lc.mutex_claimed);

        // warm_reset should clear everything.
        lc.warm_reset();
        assert!(!lc.mutex_claimed);
        assert_eq!(lc.token, [0; 4]);
        assert_eq!(lc.transition_target, 0);
    }

    #[test]
    fn test_transition_then_reset_then_transition() {
        use emulator_registers_generated::lc::LcPeripheral;

        let raw_token = TEST_RAW_TOKEN;
        let token_words = token_to_words(&raw_token);

        // Start at TestLocked0 with provisioned tokens.
        let mut lc = make_lc_ctrl(TEST_LOCKED0, 1, &raw_token);

        // Transition TestLocked0 -> TestUnlocked1 (needs OTP token).
        let status = do_transition(&mut lc, TEST_UNLOCKED0 + 2, token_words);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);

        // Warm reset to apply the new state.
        lc.warm_reset();
        assert_eq!(lc.lc_state_index, TEST_UNLOCKED0 + 2); // TestUnlocked1

        // Now transition TestUnlocked1 -> TestLocked1 (unconditional).
        let status = do_transition(&mut lc, TEST_LOCKED0 + 2, [0; 4]);
        assert_ne!(status & STATUS_TRANSITION_SUCCESSFUL, 0);

        lc.warm_reset();
        assert_eq!(lc.lc_state_index, TEST_LOCKED0 + 2); // TestLocked1
    }
}
