//! Hunt battery leg 2/5: default-hook input totality (SP1-02C).
//!
//! Invariant under test: every hook in `HookRegistry::default()` is a total
//! function over guest-written byte slices. Guests invoke hooks with arbitrary
//! bytes via hint-write, so any `assert!`/`unwrap!`/`unimplemented!`/short-slice
//! on `buf` is a host crash on untrusted input
//! (`crates/core/executor/src/hook.rs`).
//!
//! Doctrine: RED = bug confirmed. GREEN = fixed.
//! Run: cargo test -p sp1-core-executor --test hunt_hooks
use sp1_core_executor::{
    bls::{hook_bls12_381_inverse, hook_bls12_381_sqrt},
    fp_ops::{hook_fp_inverse, hook_fp_sqrt},
    hook_ecrecover, hook_ed_decompress, hook_rsa_mul_mod, Hook, HookEnv, HookRegistry,
    FD_BLS12_381_INVERSE, FD_BLS12_381_SQRT, FD_ECRECOVER_HOOK, FD_EDDECOMPRESS,
    FD_FP_INV, FD_FP_SQRT, FD_RSA_MUL_MOD,
};

/// Run a hook body without dying. Ok(output) or Err(panic-site hint).
fn hook_no_panic(f: impl FnOnce() -> Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(out) => Ok(out),
        Err(payload) => Err(if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else {
            "<non-string panic payload>".to_string()
        }),
    }
}

/// Assert totality over a named input matrix. Panics (test failure) iff any case
/// panics — each failure line is file:line-anchored by the hook under test.
fn assert_total(name: &str, cases: Vec<(&str, Vec<u8>)>, run: impl Fn(&[u8]) -> Vec<Vec<u8>>) {
    let mut panics = vec![];
    for (label, buf) in &cases {
        if let Err(site) = hook_no_panic(|| run(buf)) {
            panics.push(format!("{label} => {site}"));
        }
    }
    assert!(
        panics.is_empty(),
        "BUG-CONFIRMED ({name}): hook panics on guest-written input:\n  {}",
        panics.join("\n  ")
    );
}

fn n_zeros(n: usize) -> Vec<u8> {
    vec![0u8; n]
}
fn n_ff(n: usize) -> Vec<u8> {
    vec![0xFFu8; n]
}

#[test]
fn ecrecover_total() {
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short-10", vec![1u8; 10]),
        ("len-64", vec![1u8; 64]),
        ("len-66", vec![1u8; 66]),
        ("bad-curve-0", vec![0u8; 65]),
        ("bad-curve-3", {
            let mut b = vec![0u8; 65];
            b[0] = 3;
            b
        }),
        ("bad-curve-255", vec![0xFFu8; 65]),
        ("curve1-zero-alpha", {
            let mut b = vec![0u8; 65];
            b[0] = 1;
            b
        }),
        ("curve1-ff", {
            let mut b = vec![0xFFu8; 65];
            b[0] = 1;
            b
        }),
        ("curve2-zero-alpha", {
            let mut b = vec![0u8; 65];
            b[0] = 2;
            b
        }),
    ];
    // r = 0 scalar path (release-build invert failure): r field element zero with
    // nonzero alpha. k256/p256 from_bytes accept zero; invert must not panic.
    cases.push(("curve1-rzero-anonzero", {
        let mut b = vec![0u8; 65];
        b[0] = 1;
        b[33] = 1; // alpha != 0
        b
    }));
    assert_total("hook_ecrecover", cases, |buf| {
        hook_ecrecover(HookEnv {}, buf)
    });
}

#[test]
fn ecrecover_reachable_via_default_registry() {
    // Proves the guest-reachability premise: the hook is registered by default and
    // a guest-written buffer with curve_id=3 crashes through the registry path.
    let table = HookRegistry::default();
    let mut hook = table
        .get(FD_ECRECOVER_HOOK)
        .expect("GREEN-CONTROL FAILED: FD_ECRECOVER_HOOK not in default table");
    let r = hook_no_panic(|| hook.invoke_hook(HookEnv {}, &[3u8; 65]));
    assert!(
        r.is_ok(),
        "BUG-CONFIRMED (SP1-02C reachability): default-registered ecrecover hook panics: {}",
        r.err().unwrap()
    );
}

#[test]
fn ed_decompress_total() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short-16", vec![0u8; 16]),
        ("short-31", vec![0u8; 31]),
        ("y0-no-v", vec![0u8; 32]),
        ("y1-zero-v", {
            let mut b = vec![0u8; 64];
            b[0] = 1;
            b
        }),
        ("y-ff", vec![0xFFu8; 64]),
        ("y-p-plus-1", {
            // p = 2^255-19, so p+1 = 2^255-18: non-canonical, must not panic.
            let mut b = vec![0u8; 64];
            b[0] = 0xEF;
            b[31] = 0x80; // 2^255 bit range shape
            b
        }),
        ("v-huge", {
            let mut b = vec![0u8; 64];
            b[32..].copy_from_slice(&[0xFFu8; 32]);
            b
        }),
    ];
    assert_total("hook_ed_decompress", cases, |buf| {
        hook_ed_decompress(HookEnv {}, buf)
    });
}

#[test]
fn fp_inverse_total() {
    // buf = [len:u32be || element(len) || modulus(len)]
    let good_len = |l: usize| 4 + 2 * l;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short-3", vec![0u8; 3]),
        ("len0", 0u32.to_be_bytes().to_vec()),
        ("len1-zero", {
            let mut b = 1u32.to_be_bytes().to_vec();
            b.extend_from_slice(&[0u8; 2]);
            b
        }),
        ("len32-zero-elem", n_zeros(good_len(32))),
        ("len32-ff", n_ff(good_len(32))),
        ("truncated", n_zeros(10)),
    ];
    assert_total("hook_fp_inverse", cases, |buf| {
        hook_fp_inverse(HookEnv {}, buf)
    });
}

#[test]
fn fp_sqrt_total() {
    // buf = [len:u32be || element || modulus || nqr]
    let good_len = |l: usize| 4 + 3 * l;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short-3", vec![0u8; 3]),
        ("len32-zeros", n_zeros(good_len(32))),
        ("len32-ff", n_ff(good_len(32))),
        ("truncated", n_zeros(20)),
        ("elem-zero-prime-modulus", {
            // element = 0 with p = 2^255-19 (3 mod 4 path OK) — must not panic.
            let mut b = 32u32.to_be_bytes().to_vec();
            b.extend_from_slice(&[0u8; 32]); // element = 0
            let mut p = vec![0u8; 32];
            p[0] = 0xED;
            p[31] = 0x7F; // 2^255-19 LE? (bytes placed BE here; canonical-check may trip — totality only)
            b.extend_from_slice(&p);
            b.extend_from_slice(&[3u8; 32]); // nqr = 3
            b
        }),
        ("even-composite-modulus", {
            // modulus = 100 (even, non-prime): Tonelli/Legendre paths must not panic.
            let mut b = 1u32.to_be_bytes().to_vec();
            b.push(2); // element
            b.push(100); // modulus
            b.push(3); // nqr
            b
        }),
    ];
    assert_total("hook_fp_sqrt", cases, |buf| {
        hook_fp_sqrt(HookEnv {}, buf)
    });
}

#[test]
fn bls_total() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short-47", vec![1u8; 47]),
        ("zero-48", n_zeros(48)),
        ("ff-48", n_ff(48)),
        ("one-48", {
            let mut b = vec![0u8; 48];
            b[47] = 1;
            b
        }),
    ];
    assert_total("hook_bls12_381_sqrt", cases.clone(), |buf| {
        hook_bls12_381_sqrt(HookEnv {}, buf)
    });
    assert_total("hook_bls12_381_inverse", cases, |buf| {
        hook_bls12_381_inverse(HookEnv {}, buf)
    });
}

#[test]
fn rsa_mul_mod_total() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short-100", vec![1u8; 100]),
        ("len-767", vec![1u8; 767]),
        ("len-769", vec![1u8; 769]),
        ("zeros-768", n_zeros(768)),
        ("zeros-1152", n_zeros(1152)),
        ("zeros-1536", n_zeros(1536)),
        ("ones-768", vec![1u8; 768]),
        ("modulus-zero-rest-one", {
            // Valid length, zero modulus => div_rem by zero must not panic host.
            let mut b = vec![1u8; 768];
            for x in b.iter_mut().take(768).skip(512) {
                *x = 0;
            }
            b
        }),
    ];
    assert_total("hook_rsa_mul_mod", cases, |buf| {
        hook_rsa_mul_mod(HookEnv {}, buf)
    });
}

#[test]
fn default_table_sanity() {
    // Green control: all 7 documented hook fds registered by default.
    let table = HookRegistry::default();
    for fd in [
        FD_ECRECOVER_HOOK,
        FD_EDDECOMPRESS,
        FD_RSA_MUL_MOD,
        FD_BLS12_381_SQRT,
        FD_BLS12_381_INVERSE,
        FD_FP_SQRT,
        FD_FP_INV,
    ] {
        assert!(
            table.get(fd).is_some(),
            "GREEN-CONTROL FAILED: fd {fd} missing from default HookRegistry"
        );
    }
}
