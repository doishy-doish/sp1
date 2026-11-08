# sp1-hunt battery (branch `hunt/*` of the doishy-doish/sp1 public fork)

Upstream: succinctlabs/sp1, battery written against
`749b0c63f226063c471a6238a94101f930c14a13` (main, 2026-11-05).
Re-pin: merge upstream main into this branch, re-run. Moved HEAD = fresh scope.

## Doctrine (read before interpreting CI)

- Tests assert FIXED behavior (trap / graceful error / agreement, never host panic).
- **RED = BUG-CONFIRMED.** A failing leg is the PoC: the log's `panicked at` lines
  are the file:line evidence, the failing input is the trigger.
- **GREEN = FIXED.** Same tests pass unmodified after the fix. No test changes needed.
- **INCONCLUSIVE = compile/setup error.** Never a finding. Fix the harness, rerun.
- Green controls ship in every leg (halt, hint_len, LUI-setup proof, valid-point
  agreement). If a control fails, the leg is inconclusive, not a finding.

## Legs (each = one `cargo test -p <crate> --test hunt_<leg>`)

| leg | file (in fork) | invariant | today |
|---|---|---|---|
| decode | crates/core/executor/tests/hunt_decode.rs | `from_u32` total over guest-reachable u32s (SP1-02A) | RED |
| hooks | crates/core/executor/tests/hunt_hooks.rs | all 7 default hooks total on byte slices (SP1-02C) | RED |
| guests | crates/core/executor/tests/hunt_guests.rs | MinimalExecutor: trap-or-finish, never panic (SP1-02A/B/D) | RED |
| curves | crates/curves/tests/hunt_curves.rs | curve ops total + k256 differential (SP1-01, weierstrass edges) | RED (SP1-01) + watch sw-edges |
| populate | crates/core/machine/tests/hunt_populate.rs | `populate_field_ops` total over canonical y (SP1-02D) | RED |

## Creative extensions queued (add as legs 6+)

- hint-stream accounting fuzz: random write/read interleavings vs model (reads ≤
  writes, else trap). Needs no prover.
- weierstrass differential vs k256 full-range (leg 4 has the harness point).
- Hostile-guest prove: build tiny RISC-V guests (unknown ecall / empty hint_read /
  invalid ed_decompress) under examples/, run `execute` then `prove` in CI;
  classify trap-vs-panic-vs-proof-fail. Heavy leg, shard separately.
- NQR-hook modulus fuzz: hook_fp_sqrt/hook_rsa_mul_mod over adversarial moduli
  (composite, even, tiny) — totality under hostile modulus.
- Weekly-schedule diff: summary JSON diffed week-over-week; any RED→GREEN or
  GREEN→RED flip pages the lane.

## Fallbacks (if upstream moved and a path broke)

- Machine chip path: `sp1_core_machine::syscall::precompiles::edwards::ed_decompress::EdDecompressCols`
  (all-`pub` chain verified 2026-11-08). If renamed, `git ls-files '*ed_decompress*'`.
- BabyBear path: `slop_algebra::BabyBear`. If moved, any `PrimeField32` impl in
  sp1-core-machine's deps works.
- `EdDecompressCols::default()`: column structs derive Default; if removed,
  construct via the chip's own test helper.
- `MinimalExecutor` drives via enum match so no private type names are needed.
- LUI/ADDI encoding is self-proving: control_lui_setup goes INCONCLUSIVE (not red)
  if the encoding assumption breaks.
