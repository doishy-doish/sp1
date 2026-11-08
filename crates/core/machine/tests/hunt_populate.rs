//! Hunt battery leg 5/5: trace-gen populate totality (SP1-02D).
//!
//! Invariant under test: `EdDecompressCols::populate` is total over canonical
//! guest-controlled `y_bytes`. The executor emits `EdDecompressEvent`s with raw
//! guest bytes and performs NO curve-validity check
//! (`crates/core/executor/src/vm/syscall/precompiles/edwards/decompress.rs`),
//! so trace generation must not panic on any canonical input —
//! `ed25519_sqrt(v).expect("curve25519 expected field element to be a square")`
//! (`crates/core/machine/src/syscall/precompiles/edwards/ed_decompress.rs:174`)
//! fires on canonical-but-invalid y, crashing the prover on a program that
//! executed without any trap.
//!
//! Note on construction: column structs carry no `Default`, so cols are built
//! the same way the chip itself does — a zeroed `repr(C)` buffer reinterpreted
//! (BabyBear is plain u32 data, no invalid bit patterns; `populate` only writes
//! col state before reading it, and the panicking path depends solely on the
//! event bytes, so garbage-sensitivity cannot mask the finding).
//!
//! Doctrine: RED = bug confirmed (the panicking y is the trigger).
//! GREEN = fixed. Run: cargo test -p sp1-core-machine --test hunt_populate
use sp1_core_executor::{events::EdDecompressEvent, ExecutionRecord};
use sp1_core_machine::{
    syscall::precompiles::edwards::EdDecompressCols, SupervisorMode,
};
use sp1_curves::edwards::ed25519::{Ed25519, Ed25519BaseField};
use slop_algebra::BabyBear;
use std::mem::size_of;

fn populate_no_panic(y_bytes: [u8; 32]) -> Option<String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let n = size_of::<EdDecompressCols<BabyBear, SupervisorMode>>();
        let mut buf = vec![0u8; n];
        // SAFETY: EdDecompressCols<BabyBear, _> is #[repr(C)] plain data; the
        // buffer is exactly one struct long. populate() writes every field it
        // touches before reading it.
        let cols: &mut EdDecompressCols<BabyBear, SupervisorMode> =
            unsafe { &mut *(buf.as_mut_ptr() as *mut _) };
        let mut record = ExecutionRecord::default();
        let event = EdDecompressEvent {
            y_bytes,
            ..Default::default()
        };
        cols.populate::<Ed25519BaseField, Ed25519>(event, &mut record, true);
    })) {
        Ok(()) => None,
        Err(p) => Some(if let Some(s) = p.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        }),
    }
}

#[test]
fn populate_sweep_canonical_y() {
    // Every small canonical y (all < p): the prover must never crash, whether
    // the point is valid (constraints decide) or not (proof fails cleanly).
    // ~2000 iterations, milliseconds each.
    let mut bad: Vec<(u64, String)> = vec![];
    for y in 2u64..2000 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&y.to_le_bytes());
        if let Some(site) = populate_no_panic(bytes) {
            bad.push((y, site));
            if bad.len() >= 5 {
                break;
            }
        }
    }
    assert!(
        bad.is_empty(),
        "BUG-CONFIRMED (SP1-02D): trace-gen populate panics on canonical y: {bad:?}"
    );
}

#[test]
fn populate_valid_point_is_quiet() {
    // Green control: y = 1 populates without panic, proving the sweep above
    // exercises real witness filling rather than erroring on everything.
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    assert!(
        populate_no_panic(bytes).is_none(),
        "GREEN-CONTROL FAILED: populate panics even on y=1"
    );
}
