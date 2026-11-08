//! Hunt battery leg 3/5: executor guests — trap-or-finish, never panic (SP1-02A/B/D).
//!
//! Drives `MinimalExecutor` on hand-built guests that poke the SP1-02 panic sites
//! end to end: unknown ecall numbers, empty hint stream, misaligned precompile
//! pointers, invalid curve points. Only public API is used
//! (`MinimalExecutorEnum`, `Program`, `Instruction`, `Opcode`).
//!
//! Outcome model per case: Panicked(site) | Trapped | Finished. Each case asserts
//! the FIXED behavior (trap, or finish where legal). Pre-fix the case FAILS and
//! the failure log carries the exact panic site — the failure IS the PoC, no
//! test changes needed after a fix. Green controls prove the harness is sound
//! (a failing control = inconclusive leg, never a finding).
//!
//! Run: cargo test -p sp1-core-executor --test hunt_guests
use sp1_core_executor::{Instruction, MinimalExecutorEnum, Opcode, Program};
use std::sync::Arc;

const ED_DECOMPRESS_CODE: u64 = 0x00_00_01_08;
const ED_ADD_CODE: u64 = 0x00_01_01_07;
const HINT_READ_CODE: u64 = 0x00_00_00_F1;
const HINT_LEN_CODE: u64 = 0x00_00_00_F0;

fn addi(rd: u8, imm: u64) -> Instruction {
    Instruction::new(Opcode::ADDI, rd, 0, imm, false, true)
}
fn lui(rd: u8, imm20: u64) -> Instruction {
    Instruction::new(Opcode::LUI, rd, 0, imm20, false, true)
}
fn ecall() -> Instruction {
    Instruction::new(Opcode::ECALL, 0, 0, 0, false, false)
}

#[derive(Debug)]
enum Outcome {
    Panicked(String),
    Trapped(String),
    Finished([u64; 32]),
}

fn panic_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Drive a hand-built guest to completion-ish. Caps steps; never hangs the leg.
fn run_guest(instrs: Vec<Instruction>) -> Outcome {
    let prog = Program::new(instrs, 0, 0);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ex = MinimalExecutorEnum::new(Arc::new(prog), false, None);
        let mut steps = 0u32;
        loop {
            // NOTE (native-backend port): the x86_64 MinimalExecutor exposes only
            // `execute_chunk`, which panics (via expect) on ExecutionError traps.
            // Trap-vs-panic is recovered from the panic payload: expect() prefixes
            // trap payloads with "execute chunk"; genuine host panics (from_u32,
            // curve expects, slice indexing) never carry that marker.
            let finished_or_err: Result<Option<[u64; 32]>, String> = match &mut ex {
                MinimalExecutorEnum::Supervisor(inner) => {
                    if inner.is_done() {
                        Ok(Some(inner.registers()))
                    } else {
                        inner.execute_chunk();
                        Ok(None)
                    }
                }
                MinimalExecutorEnum::User(inner) => {
                    if inner.is_done() {
                        Ok(Some(inner.registers()))
                    } else {
                        inner.execute_chunk();
                        Ok(None)
                    }
                }
            };
            match finished_or_err {
                Ok(Some(regs)) => return Outcome::Finished(regs),
                Ok(None) => {}
                Err(e) => return Outcome::Trapped(e),
            }
            steps += 1;
            if steps > 20_000 {
                return Outcome::Trapped("step-cap 20000 (no halt, no trap)".to_string());
            }
        }
    }));
    match r {
        Err(p) => {
            let s = panic_string(p);
            if s.contains("execute chunk") {
                Outcome::Trapped(s)
            } else {
                Outcome::Panicked(s)
            }
        }
        Ok(o) => o,
    }
}

#[test]
fn control_halt_is_clean() {
    // Green control: bare ECALL with x5 == 0 halts cleanly (proves drive loop).
    match run_guest(vec![ecall()]) {
        Outcome::Finished(_) => {}
        other => panic!("GREEN-CONTROL FAILED: bare halt guest gave {other:?}"),
    }
}

#[test]
fn control_hint_len_empty_is_clean() {
    // Green control: HINT_LEN on an empty stream returns u64::MAX, no panic.
    // (Falls off the end afterwards => trap is a legal outcome; panic is not.)
    match run_guest(vec![addi(5, HINT_LEN_CODE), ecall()]) {
        Outcome::Panicked(site) => {
            panic!("GREEN-CONTROL FAILED: hint_len panicked: {site}")
        }
        Outcome::Trapped(_) | Outcome::Finished(_) => {}
    }
}

#[test]
fn control_lui_setup() {
    // Proves the LUI+ADDI encoding used by later cases: x6 must equal 0x10107,
    // then x5 = 0 halts. If this fails, later LUI cases are INCONCLUSIVE.
    // Build x6 = 0x10107 via LUI+ADDI, then x5 = 0 halts; read back x6.
    match run_guest(vec![
        lui(6, 0x101),
        Instruction::new(Opcode::ADDI, 6, 6, 0x107, false, true),
        addi(5, 0),
        ecall(),
    ]) {
        Outcome::Finished(regs) => assert_eq!(
            regs[6], 0x10107,
            "SETUP BROKEN: LUI+ADDI did not produce 0x10107 in x6 (got {:#x}) — later LUI cases inconclusive",
            regs[6]
        ),
        other => panic!("GREEN-CONTROL FAILED: setup guest gave {other:?}"),
    }
}

#[test]
fn unknown_ecall_traps() {
    // SP1-02A: x5 = 1 is not a known code. Fixed behavior: trap.
    // Today this FAILS with the host panic site — that failure IS the PoC.
    match run_guest(vec![addi(5, 1), ecall()]) {
        Outcome::Panicked(site) => panic!(
            "BUG-CONFIRMED (SP1-02A): host panics instead of trapping: {site}"
        ),
        Outcome::Trapped(_) => {}
        Outcome::Finished(_) => {
            panic!("unexpected clean finish on unknown ecall — investigate")
        }
    }
}

#[test]
fn hint_read_empty_traps() {
    // SP1-02B: HINT_READ with an empty input stream. Fixed: trap.
    match run_guest(vec![addi(5, HINT_READ_CODE), ecall()]) {
        Outcome::Panicked(site) => panic!(
            "BUG-CONFIRMED (SP1-02B): host panics instead of trapping: {site}"
        ),
        Outcome::Trapped(_) => {}
        Outcome::Finished(_) => {
            panic!("unexpected clean finish on empty hint_read — investigate")
        }
    }
}

#[test]
fn misaligned_ed_decompress_traps() {
    // SP1-02D executor half: slice_ptr = 1 (not 8-aligned). Fixed: trap.
    match run_guest(vec![addi(5, ED_DECOMPRESS_CODE), addi(10, 1), ecall()]) {
        Outcome::Panicked(site) => panic!(
            "BUG-CONFIRMED (SP1-02D): host panics instead of trapping: {site}"
        ),
        Outcome::Trapped(_) => {}
        Outcome::Finished(_) => {
            panic!("unexpected clean finish on misaligned ed_decompress — investigate")
        }
    }
}

#[test]
fn misaligned_ed_add_traps() {
    // SP1-01#3 via guest: p_ptr = 1. Needs full 32-bit code => LUI+ADDI.
    // (control_lui_setup must be green or this case is inconclusive.)
    match run_guest(vec![
        lui(5, 0x101),
        Instruction::new(Opcode::ADDI, 5, 5, 0x107, false, true),
        addi(10, 1),
        ecall(),
    ]) {
        Outcome::Panicked(site) => panic!(
            "BUG-CONFIRMED (SP1-01#3): host panics instead of trapping: {site}"
        ),
        Outcome::Trapped(_) => {}
        Outcome::Finished(_) => {
            panic!("unexpected clean finish on misaligned ed_add — investigate")
        }
    }
}

#[test]
fn zero_point_ed_add_executor_path() {
    // SP1-01#1 via guest: aligned ptr into zero memory = invalid (0,0),(0,0).
    // Executor performs NO validity check, so today this either panics in curve
    // code (bug confirmed) or finishes (premise confirmed for the machine leg).
    // A trap here means the setup address is unmapped — actionable, not a find.
    match run_guest(vec![
        lui(5, 0x101),
        Instruction::new(Opcode::ADDI, 5, 5, 0x107, false, true),
        addi(10, 0x100),
        addi(11, 0),
        ecall(),
    ]) {
        Outcome::Panicked(site) => println!("executor panicked (bug-consistent): {site}"),
        Outcome::Finished(_) => {
            println!("executor finished on invalid point: validity unchecked (feeds machine leg)")
        }
        Outcome::Trapped(e) => panic!("SETUP: zero-memory read trapped ({e}) — remap setup address"),
    }
}
