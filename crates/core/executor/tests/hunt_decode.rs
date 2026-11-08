//! Hunt battery leg 1/5: syscall decode totality (SP1-02A).
//!
//! Invariant under test: `SyscallCode::from_u32` is total over guest-reachable
//! inputs. A RISC-V guest controls x5 fully, so an unknown ecall number must
//! trap, never panic the host (`crates/core/executor/src/vm.rs:448` ->
//! `crates/core/executor/src/syscall_code.rs:249`).
//!
//! Doctrine: RED = bug confirmed (the panicking value is the PoC trigger).
//! GREEN = fixed. Run: cargo test -p sp1-core-executor --test hunt_decode
use sp1_core_executor::SyscallCode;
use std::collections::HashSet;

/// All known codes on main @ 749b0c6 (extracted from syscall_code.rs match arms).
const KNOWN: [(u32, &str); 48] = [
    (0x00_00_00_00, "HALT"), (0x00_00_00_02, "WRITE"),
    (0x00_00_00_03, "ENTER_UNCONSTRAINED"), (0x00_00_00_04, "EXIT_UNCONSTRAINED"),
    (0x00_30_01_05, "SHA_EXTEND"), (0x00_01_01_06, "SHA_COMPRESS"),
    (0x00_01_01_07, "ED_ADD"), (0x00_00_01_08, "ED_DECOMPRESS"),
    (0x00_01_01_09, "KECCAK_PERMUTE"), (0x00_01_01_0A, "SECP256K1_ADD"),
    (0x00_00_01_0B, "SECP256K1_DOUBLE"), (0x00_00_01_0C, "SECP256K1_DECOMPRESS"),
    (0x00_01_01_0E, "BN254_ADD"), (0x00_00_01_0F, "BN254_DOUBLE"),
    (0x00_01_01_1E, "BLS12381_ADD"), (0x00_00_01_1F, "BLS12381_DOUBLE"),
    (0x00_00_00_10, "COMMIT"), (0x00_00_00_1A, "COMMIT_DEFERRED_PROOFS"),
    (0x00_00_00_1B, "VERIFY_SP1_PROOF"), (0x00_00_00_F0, "HINT_LEN"),
    (0x00_00_00_F1, "HINT_READ"), (0x00_01_01_1D, "UINT256_MUL"),
    (0x00_01_01_2F, "U256XU2048_MUL"), (0x00_01_01_20, "BLS12381_FP_ADD"),
    (0x00_01_01_21, "BLS12381_FP_SUB"), (0x00_01_01_22, "BLS12381_FP_MUL"),
    (0x00_01_01_23, "BLS12381_FP2_ADD"), (0x00_01_01_24, "BLS12381_FP2_SUB"),
    (0x00_01_01_25, "BLS12381_FP2_MUL"), (0x00_01_01_26, "BN254_FP_ADD"),
    (0x00_01_01_27, "BN254_FP_SUB"), (0x00_01_01_28, "BN254_FP_MUL"),
    (0x00_01_01_29, "BN254_FP2_ADD"), (0x00_01_01_2A, "BN254_FP2_SUB"),
    (0x00_01_01_2B, "BN254_FP2_MUL"), (0x00_00_01_1C, "BLS12381_DECOMPRESS"),
    (0x00_01_01_2C, "SECP256R1_ADD"), (0x00_00_01_2D, "SECP256R1_DOUBLE"),
    (0x00_00_01_2E, "SECP256R1_DECOMPRESS"), (0x00_01_01_30, "UINT256_ADD_CARRY"),
    (0x00_01_01_31, "UINT256_MUL_CARRY"), (0x00_00_01_32, "MPROTECT"),
    (0x00_00_01_33, "POSEIDON2"), (0x00_00_01_34, "SIG_RETURN"),
    (0x00_00_00_35, "HINT_MPROTECT_FLUSH"), (0x00_00_00_40, "DUMP_ELF"),
    (0x00_00_00_41, "INSERT_PROFILER_SYMBOLS"),
    (0x00_00_00_42, "DELETE_PROFILER_SYMBOLS"),
];

/// Decode without dying: Some(code) or None (panicked).
fn decode_no_panic(v: u32) -> Option<SyscallCode> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SyscallCode::from_u32(v)
    })) {
        Ok(c) => Some(c),
        Err(_) => None,
    }
}

/// Deterministic PRNG (mulberry32) — reproducible sweeps, no deps.
fn rng_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x6D2B79F5);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[test]
fn known_codes_decode() {
    // Green control: the documented table must keep decoding (guards enum drift).
    for (v, name) in KNOWN {
        assert!(
            decode_no_panic(v).is_some(),
            "GREEN-CONTROL FAILED: known code {name} (0x{v:08X}) panicked — harness/enum drift, not a finding"
        );
    }
}

#[test]
fn unknown_codes_must_not_panic() {
    // Hand-picked guest-plausible unknowns: tiny immediates a guest can emit with
    // one ADDI, off-by-ones of real codes, and hostile extremes.
    let mut cands = vec![
        0x01, 0x05, 0x0D, 0x11, 0x12, 0xF2, 0x36, 0x3F, 0x43, 0x100, 0x101,
        0xDEAD, 0xBEEF, 0xDEAD_BEEF, 0xFFFF_FFFF, 0x8000_0000, 0x00_01_01_00,
        0x00_01_01_01, 0x00_00_01_00,
    ];
    let known: HashSet<u32> = KNOWN.iter().map(|(v, _)| *v).collect();
    cands.retain(|v| !known.contains(v));
    // Plus 30k deterministic pseudo-random u32s (skip knowns).
    let mut st = 0x1234_5678u64;
    for _ in 0..30_000 {
        let v = (rng_next(&mut st) & 0xFFFF_FFFF) as u32;
        if !known.contains(&v) {
            cands.push(v);
        }
    }
    let panics: Vec<u32> = cands
        .into_iter()
        .filter(|v| decode_no_panic(*v).is_none())
        .take(11)
        .collect();
    let show: Vec<String> = panics.iter().map(|v| format!("0x{v:08X}")).collect();
    assert!(
        panics.is_empty(),
        "BUG-CONFIRMED (SP1-02A): host panics on guest-reachable ecall numbers, first: {show:?}. Expected: trap, not panic."
    );
}

#[test]
fn decode_exhaustive_low16() {
    // Every 12-bit guest immediate (what one ADDI can put in x5) outside the known
    // set must decode-or-trap, never panic. 65k calls, milliseconds.
    let known: HashSet<u32> = KNOWN.iter().map(|(v, _)| *v).collect();
    let mut panics = vec![];
    for v in 0..0x10000u32 {
        if known.contains(&v) {
            continue;
        }
        if decode_no_panic(v).is_none() {
            panics.push(v);
            if panics.len() >= 10 {
                break;
            }
        }
    }
    let show: Vec<String> = panics.iter().map(|v| format!("0x{v:08X}")).collect();
    assert!(
        panics.is_empty(),
        "BUG-CONFIRMED (SP1-02A): host panics on 12-bit ecall numbers, first: {show:?}"
    );
}
