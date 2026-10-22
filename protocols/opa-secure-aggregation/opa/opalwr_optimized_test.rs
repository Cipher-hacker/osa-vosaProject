use opalwr::paper_benchmark_params;
use opalwr_fixed_q::{
    optimized_lwr_round_for_test, optimized_mod_add_for_test, optimized_mod_mul_for_test,
    optimized_paper_benchmark_params,
};

#[test]
fn optimized_params_match_reference_paper_params() {
    let reference = paper_benchmark_params(10_000);
    let optimized = optimized_paper_benchmark_params(10_000);
    assert_eq!(optimized.vector_len, reference.vector_len);
    assert_eq!(optimized.seed_dim, reference.seed_dim);
    assert_eq!(optimized.packed_secret_dim, reference.packed_secret_dim);
    assert_eq!(optimized.committee_size, reference.committee_size);
    assert_eq!(optimized.threshold_r, reference.threshold_r);
    assert_eq!(optimized.p, reference.p);
    assert_eq!(optimized.q, reference.q);
    assert_eq!(optimized.q.bit_length(), 128);
    assert!(is_probable_prime_128(optimized.q));
}

#[test]
fn optimized_field_arithmetic_matches_reference_samples() {
    let params = paper_benchmark_params(10_000);
    let samples = [
        (0_u128, 0_u128),
        (1, 1),
        (params.q - 1, 1),
        (params.q - 2, params.q - 3),
        (123_456_789, 987_654_321),
        (u128::MAX - 7, u128::MAX - 11),
        (params.q / 2, params.q / 3),
    ];

    for (a, b) in samples {
        assert_eq!(
            optimized_mod_add_for_test(a % params.q, b % params.q),
            opalwr_reference_mod_add(a % params.q, b % params.q, params.q)
        );
        assert_eq!(
            optimized_mod_mul_for_test(a % params.q, b % params.q),
            opalwr_reference_mod_mul(a % params.q, b % params.q, params.q)
        );
        assert_eq!(
            optimized_lwr_round_for_test(a % params.q),
            opalwr_reference_lwr_round(a % params.q, params.p, params.q)
        );
    }

    let mut state = 0x9e37_79b9_7f4a_7c15_d1b5_4a32_d192_ed03_u128;
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let a = state % params.q;
        state = state.rotate_left(47).wrapping_add(0xa076_1d64_78bd_642f_u128);
        let b = state % params.q;
        assert_eq!(
            optimized_mod_add_for_test(a, b),
            opalwr_reference_mod_add(a, b, params.q)
        );
        assert_eq!(
            optimized_mod_mul_for_test(a, b),
            opalwr_reference_mod_mul(a, b, params.q)
        );
    }
}

fn opalwr_reference_mod_add(a: u128, b: u128, modulus: u128) -> u128 {
    use crypto_bigint::{U256, Wrapping};
    let sum = (Wrapping(U256::from(a)) + Wrapping(U256::from(b))).0;
    let reduced = sum % U256::from(modulus);
    let bytes = reduced.to_be_bytes();
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(lower)
}

fn opalwr_reference_mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
    use crypto_bigint::{U256, Wrapping};
    let product = (Wrapping(U256::from(a)) * Wrapping(U256::from(b))).0;
    let reduced = product % U256::from(modulus);
    let bytes = reduced.to_be_bytes();
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(lower)
}

fn opalwr_reference_lwr_round(value: u128, p: u128, q: u128) -> u128 {
    use crypto_bigint::{U256, Wrapping};
    let numerator = (Wrapping(U256::from(value)) * Wrapping(U256::from(p))).0;
    let rounded = numerator / U256::from(q);
    let bytes = rounded.to_be_bytes();
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(lower) % p
}

trait BitLength {
    fn bit_length(self) -> u32;
}

impl BitLength for u128 {
    fn bit_length(self) -> u32 {
        128 - self.leading_zeros()
    }
}

fn is_probable_prime_128(n: u128) -> bool {
    let small_primes = [2_u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for p in small_primes {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }

    let mut d = n - 1;
    let mut s = 0;
    while d % 2 == 0 {
        s += 1;
        d /= 2;
    }

    let bases = [
        2_u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113,
    ];
    for base in bases {
        let a = base % (n - 3) + 2;
        let mut x = mod_pow_u128(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        let mut witness_passed = false;
        for _ in 1..s {
            x = opalwr_reference_mod_mul(x, x, n);
            if x == n - 1 {
                witness_passed = true;
                break;
            }
        }
        if !witness_passed {
            return false;
        }
    }
    true
}

fn mod_pow_u128(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1_u128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = opalwr_reference_mod_mul(result, base, modulus);
        }
        base = opalwr_reference_mod_mul(base, base, modulus);
        exp >>= 1;
    }
    result
}
