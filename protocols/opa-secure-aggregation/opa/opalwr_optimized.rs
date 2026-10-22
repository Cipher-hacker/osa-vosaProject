use crypto_bigint::{U256, Wrapping};

const PAPER_Q: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297;
const PAPER_P: u128 = 1_u128 << 53;
const PAPER_SEED_DIM: usize = 2048;
const PAPER_PACKED_SECRET_DIM: usize = 16;
const PAPER_COMMITTEE_SIZE: usize = 50;
const PAPER_THRESHOLD_R: usize = 34;
const PAPER_STAT_SEC_BITS: u32 = 40;
const PAPER_Q_COMPLEMENT: u128 = 159;

#[derive(Clone, Debug)]
pub struct OpaParameters {
    pub vector_len: usize,
    pub seed_dim: usize,
    pub packed_secret_dim: usize,
    pub committee_size: usize,
    pub threshold_r: usize,
    pub q: u128,
    pub p: u128,
    pub stat_sec_bits: u32,
}

pub fn optimized_paper_benchmark_params(vector_len: usize) -> OpaParameters {
    OpaParameters {
        vector_len,
        seed_dim: PAPER_SEED_DIM,
        packed_secret_dim: PAPER_PACKED_SECRET_DIM,
        committee_size: PAPER_COMMITTEE_SIZE,
        threshold_r: PAPER_THRESHOLD_R,
        q: PAPER_Q,
        p: PAPER_P,
        stat_sec_bits: PAPER_STAT_SEC_BITS,
    }
}

pub fn optimized_mod_add_for_test(a: u128, b: u128) -> u128 {
    mod_add_q(a, b)
}

pub fn optimized_mod_mul_for_test(a: u128, b: u128) -> u128 {
    mod_mul_q(a, b)
}

pub fn optimized_lwr_round_for_test(value: u128) -> u128 {
    lwr_round(value, PAPER_P, PAPER_Q)
}

fn mod_add_q(a: u128, b: u128) -> u128 {
    let (sum, carry) = a.overflowing_add(b);
    let mut reduced = if carry {
        add_small_mod_q(sum, PAPER_Q_COMPLEMENT)
    } else {
        sum
    };
    if reduced >= PAPER_Q {
        reduced -= PAPER_Q;
    }
    reduced
}

fn add_small_mod_q(value: u128, small: u128) -> u128 {
    let (sum, carry) = value.overflowing_add(small);
    let mut reduced = if carry {
        sum.wrapping_add(PAPER_Q_COMPLEMENT)
    } else {
        sum
    };
    if reduced >= PAPER_Q {
        reduced -= PAPER_Q;
    }
    reduced
}

fn mod_mul_q(a: u128, b: u128) -> u128 {
    let limbs = mul_u128_to_u64_limbs(a, b);
    let lo = (limbs[0] as u128) | ((limbs[1] as u128) << 64);
    let hi = (limbs[2] as u128) | ((limbs[3] as u128) << 64);
    fold_hi_times_complement(lo, hi)
}

fn fold_hi_times_complement(lo: u128, hi: u128) -> u128 {
    let h0 = hi as u64 as u128;
    let h1 = hi >> 64;

    let p0 = h0 * PAPER_Q_COMPLEMENT;
    let p1 = h1 * PAPER_Q_COMPLEMENT;

    let mid_low = (p0 >> 64) + (p1 & u64::MAX as u128);
    let folded_low = (p0 & u64::MAX as u128) | ((mid_low & u64::MAX as u128) << 64);
    let folded_high = (p1 >> 64) + (mid_low >> 64);

    let (sum, carry) = lo.overflowing_add(folded_low);
    let high = folded_high + u128::from(carry);
    let high_fold = high * PAPER_Q_COMPLEMENT;
    add_small_mod_q(sum, high_fold)
}

fn mul_u128_to_u64_limbs(a: u128, b: u128) -> [u64; 4] {
    let mask = u64::MAX as u128;
    let a0 = a & mask;
    let a1 = a >> 64;
    let b0 = b & mask;
    let b1 = b >> 64;

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let limb0 = p00 as u64;
    let carry0 = p00 >> 64;
    let middle = carry0 + (p01 & mask) + (p10 & mask);
    let limb1 = middle as u64;
    let carry1 = middle >> 64;
    let high = p11 + (p01 >> 64) + (p10 >> 64) + carry1;
    let limb2 = high as u64;
    let limb3 = (high >> 64) as u64;
    [limb0, limb1, limb2, limb3]
}

fn lwr_round(value: u128, p: u128, q: u128) -> u128 {
    let numerator = (Wrapping(U256::from(value)) * Wrapping(U256::from(p))).0;
    u128_from_u256(numerator / U256::from(q)) % p
}

fn u128_from_u256(value: U256) -> u128 {
    let bytes = value.to_be_bytes();
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(lower)
}
