//! Hunt battery leg 4/5: curve arithmetic totality + differentials (SP1-01 family).
//!
//! Invariants under test:
//! (a) `&p + &q` (=> `ec_add`) and scalar `Mul` never panic, on valid OR invalid
//!     points (SP1-01#1/#2: `affine_to_dalek().decompress().expect(..)` +
//!     `scalar_mul` zero-`expect`). Fixed behavior: graceful biguint path /
//!     identity-or-error, never host panic.
//! (b) Weierstrass edge totality: equal-x add (= double case), opposite-point add
//!     (= infinity case) must not panic — same family, unknown status (WATCH).
//! (c) k256 differential (green control + fix-guard): `sw_scalar_mul` agrees with
//!     the independent k256 crate on random scalars.
//!
//! Doctrine: RED = bug confirmed. GREEN = fixed/agreement.
//! Run: cargo test -p sp1-curves --test hunt_curves
use sp1_curves::{
    weierstrass::secp256k1::Secp256k1, AffinePoint, BigUint, EllipticCurve,
};
use sp1_curves::edwards::ed25519::Ed25519;

/// Bad point from the repo's own `test_biguint_ed_add_accepts_invalid_points`.
fn invalid_ed_point() -> AffinePoint<Ed25519> {
    AffinePoint::<Ed25519>::new(
        "90393249858788985237231628593243673548167146579814271945474941877372611"
            .parse()
            .unwrap(),
        "33321104029277100578831462130550309254424125212570121538923759338004303"
            .parse()
            .unwrap(),
    )
}

fn no_panic<T>(label: &str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(p) => {
            let s = if let Some(x) = p.downcast_ref::<String>() {
                x.clone()
            } else {
                "<non-string>".to_string()
            };
            println!("{label} panicked: {s}");
            None
        }
    }
}

/// Deterministic PRNG (mulberry32).
fn rng_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x6D2B79F5);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[test]
fn ed_add_invalid_must_not_panic() {
    // SP1-01#1: invalid point + generator. Today: "edwards point must be valid".
    let p = invalid_ed_point();
    let q = Ed25519::ec_generator();
    assert!(
        no_panic("ed_add(invalid)", || &p + &q).is_some(),
        "BUG-CONFIRMED (SP1-01#1): ec_add panics on invalid point"
    );
}

#[test]
fn ed_add_random_pairs_must_not_panic() {
    // Totality sweep: random (x,y) pairs are ~all off-curve; none may panic.
    let g = Ed25519::ec_generator();
    let mut st = 0xABCDEFu64;
    let mut panics = 0u32;
    for _ in 0..200 {
        let x = BigUint::from(rng_next(&mut st) >> 1); // < 2^63, canonical
        let y = BigUint::from(rng_next(&mut st) >> 1);
        let p = AffinePoint::<Ed25519>::new(x, y);
        if no_panic("ed_add(random)", || &p + &g).is_none() {
            panics += 1;
            if panics >= 3 {
                break;
            }
        }
    }
    assert_eq!(
        panics, 0,
        "BUG-CONFIRMED (SP1-01#1 class): ec_add panics on random points"
    );
}

#[test]
fn scalar_mul_zero_must_not_panic() {
    // SP1-01#2: scalar 0 leaves result None => expect panics (public Mul API).
    let g = Ed25519::ec_generator();
    assert!(
        no_panic("scalar_mul(0)", || &g * BigUint::from(0u32)).is_some(),
        "BUG-CONFIRMED (SP1-01#2): scalar_mul panics on zero scalar"
    );
}

#[test]
fn scalar_mul_edges_must_not_panic() {
    let g = Ed25519::ec_generator();
    let order = Ed25519::prime_group_order();
    let cands = vec![
        BigUint::from(1u32),
        &order - BigUint::from(1u32),
        order.clone(),
        &order + BigUint::from(1u32),
        (BigUint::from(1u32) << 256usize) - BigUint::from(1u32),
    ];
    for s in cands {
        assert!(
            no_panic("scalar_mul(edge)", || &g * s.clone()).is_some(),
            "scalar_mul panics on edge scalar {s}"
        );
    }
}

#[test]
fn ed_valid_consistency() {
    // Green control: generator arithmetic is internally consistent on the fixed
    // behavior (g+g == 2*g, (a+b)*g == a*g + b*g for small scalars).
    let g = Ed25519::ec_generator();
    let two_g = &g + &g;
    let s1 = BigUint::from(12345u32);
    let s2 = BigUint::from(67890u32);
    let lhs = &(&g * s1.clone()) + &(&g * s2.clone());
    let rhs = &g * (s1 + s2);
    assert_eq!(lhs, rhs, "GREEN-CONTROL FAILED: scalar-mul/add inconsistent");
    assert_eq!(
        &g * BigUint::from(2u32),
        two_g,
        "GREEN-CONTROL FAILED: 2*g mismatch"
    );
}

#[test]
fn sw_equal_x_add_must_not_panic() {
    // WATCH (unknown status, SP1-01 family): ec_add with x1 == x2 is the double
    // case through the add path; naive slope (y2-y1)/(x2-x1) divides by zero.
    let g = Secp256k1::ec_generator();
    match no_panic("sw ec_add(g,g)", || Secp256k1::ec_add(&g, &g)) {
        Some(a) => {
            let d = no_panic("sw ec_double(g)", || Secp256k1::ec_double(&g))
                .expect("sw ec_double panicked — new finding, file it");
            assert_eq!(a, d, "add(g,g) != double(g) — miscompile, investigate");
        }
        None => panic!(
            "BUG-CONFIRMED (new, SP1-01 family): sw ec_add panics on equal-x input"
        ),
    }
}

#[test]
fn sw_opposite_add_must_not_panic() {
    // WATCH (unknown status, SP1-01 family): ec_add(p, -p) is the point at
    // infinity, which AffinePoint may not represent — must not panic the host.
    let g = Secp256k1::ec_generator();
    let neg = Secp256k1::ec_neg(&g);
    if no_panic("sw ec_add(g,-g)", || Secp256k1::ec_add(&g, &neg)).is_none() {
        panic!(
            "BUG-CONFIRMED (new, SP1-01 family): sw ec_add panics on opposite points"
        );
    }
}

#[test]
fn sw_scalar_mul_agrees_with_k256() {
    // Green control + fix-guard: independent-oracle differential. k256 is a
    // separate implementation; agreement on 20 random scalars proves the harness
    // compares real math, so the totality cases above are meaningful.
    use sp1_curves::k256::{
        elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar as KScalar,
    };
    let mut st = 0x99AAu64;
    for _ in 0..20 {
        let s = (rng_next(&mut st) % 1_000_000) + 1;
        let mine = Secp256k1::ec_generator().sw_scalar_mul(&BigUint::from(s));
        let theirs =
            (ProjectivePoint::GENERATOR * KScalar::from(s as u64)).to_affine();
        let enc = theirs.to_encoded_point(false);
        let x = BigUint::from_bytes_be(enc.x().unwrap().as_slice());
        let y = BigUint::from_bytes_be(enc.y().unwrap().as_slice());
        assert_eq!(mine.x, x, "GREEN-CONTROL FAILED: k256 x mismatch at s={s}");
        assert_eq!(mine.y, y, "GREEN-CONTROL FAILED: k256 y mismatch at s={s}");
    }
}
