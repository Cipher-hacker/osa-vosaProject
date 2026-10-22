use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::rand::Rng;
use ark_std::UniformRand;

pub mod crs;
pub mod decryption;
pub mod encryption;
use crate::bte::crs::CRS;

#[derive(Clone, Debug)]
pub struct PRF<E: Pairing> {
    pub key: E::ScalarField,
}

impl<E: Pairing> PRF<E> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let key = E::ScalarField::rand(rng);
        Self { key }
    }

    pub fn from_key(key: E::ScalarField) -> Self {
        Self { key }
    }

    pub fn eval(&self, input: usize, crs: &CRS<E>) -> PairingOutput<E> {
        assert!(input < crs.batch_size, "input must be smaller than batch_size");
        crs.gt_powers[input] * self.key
    }

    pub fn puncture(&self, point: usize, crs: &CRS<E>) -> PPRF<E> {
        if point >= crs.batch_size {
            panic!("puncture point must be smaller than batch_size");
        } else {
            return PPRF {
                key: crs.powers_of_g[point] * self.key,
                point,
            };
        }
    }
}

#[derive(Clone, Debug)]
pub struct PPRF<E: Pairing> {
    pub key: E::G1,
    pub point: usize,
}

impl<E: Pairing> PPRF<E> {
    pub fn eval(&self, input: usize, crs: &CRS<E>) -> PairingOutput<E> {
        if input == crs.batch_size + 1 || input == self.point {
            panic!(
                "invalid input to puncture PRF: {}, punctured at {}",
                input, self.point
            );
        } else {
            return E::pairing(
                self.key,
                crs.powers_of_h[crs.batch_size + 1 + input - self.point],
            );
        }
    }
}

/// Returns the sum of PPRF evaluations at `input` across all PPRFs via a multi-pairing.
pub fn batch_eval<E: Pairing>(
    pprfs: &[PPRF<E>],
    input: usize,
    crs: &CRS<E>,
) -> PairingOutput<E> {
    let lhs = pprfs.iter().map(|pprf| pprf.key).collect::<Vec<_>>();
    let rhs = pprfs
        .iter()
        .map(|pprf| crs.powers_of_h[crs.batch_size + 1 + input - pprf.point])
        .collect::<Vec<_>>();
    E::multi_pairing(lhs, rhs)
}

/// Same as batch_eval but using individual pairings (for comparison/benchmarking).
pub fn naive_batch_eval<E: Pairing>(
    pprfs: &[PPRF<E>],
    input: usize,
    crs: &CRS<E>,
) -> PairingOutput<E> {
    let mut res = PairingOutput::<E>::zero();
    for pprf in pprfs.iter() {
        res += E::pairing(
            pprf.key,
            crs.powers_of_h[crs.batch_size + 1 + input - pprf.point],
        );
    }
    res
}

/// Computes all `batch_size` masks simultaneously using an FFT-based circular cross-correlation.
///
/// Replaces the O(B²) loop:
///   for i in 0..B { mask[i] = k_agg.eval(i) - batch_eval(&pprfs, i) }
///
/// With O(B log B) using arkworks' generic EvaluationDomain:
///   1. A_vec[j] = pprfs[j].key  (G1, padded to N ≈ 2B)
///   2. FFT(A_vec) — domain.fft_in_place over E::G1 (DomainCoeff<ScalarField>)
///   3. C_hat[k] = e(A_hat[k], fft_h[k])  — N pointwise pairings
///   4. iFFT(C_hat) — domain.ifft_in_place over PairingOutput<E> (DomainCoeff<ScalarField>)
///   5. z[i] = k_agg.eval(i) - C[i]
///
/// `crs.fft_h` holds FFT(B_vec) where B_vec is arranged for circular cross-correlation,
/// precomputed once at CRS setup using the same arkworks generic FFT.
pub fn fft_batch_eval<E: Pairing>(
    k_agg: &PRF<E>,
    pprfs: &[PPRF<E>],
    crs: &CRS<E>,
) -> Vec<PairingOutput<E>> {
    let b = crs.batch_size;
    let n = crs.fft_size;
    assert_eq!(pprfs.len(), b, "pprfs length must equal batch_size");

    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)
        .expect("fft_size exceeds field 2-adicity");

    // Step 1: Build A_vec (G1, length N, zero-padded)
    let mut a_vec: Vec<E::G1> = pprfs.iter().map(|p| p.key).collect();
    a_vec.resize(n, E::G1::zero());

    // Step 2: FFT(A_vec) in G1 via arkworks' generic domain.fft_in_place
    // Works because E::G1 implements DomainCoeff<ScalarField>.
    domain.fft_in_place(&mut a_vec);

    // Convert to affine in one batch — uses Montgomery's batch inversion trick
    // (1 field inversion + 3N multiplications) vs N individual inversions.
    let a_hat_affine = E::G1::normalize_batch(&a_vec);

    // Step 3: Pointwise pairing — C_hat[k] = e(A_hat[k], fft_h[k])
    // N ≈ 2B individual pairings vs B multi-pairings of B elements in the naive approach.
    // Zero G1 points (from zero-padding) yield GT identity; pairing is still well-defined.
    let mut c_hat: Vec<PairingOutput<E>> = a_hat_affine
        .iter()
        .zip(crs.fft_h.iter())
        .map(|(&a, &b)| E::pairing(a, b))
        .collect();

    // Step 4: iFFT(C_hat) in GT via arkworks' generic domain.ifft_in_place
    // Works because PairingOutput<E> implements DomainCoeff<ScalarField>.
    // After iFFT: C[i] = batch_eval(&pprfs, i) for all i (by the circular B_vec layout).
    domain.ifft_in_place(&mut c_hat);

    // Step 5: z[i] = k_agg.eval(i) - C[i]
    (0..b)
        .map(|i| k_agg.eval(i, crs) - c_hat[i])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_puncture() {
        let mut rng = test_rng();
        let batch_size = 10;
        let crs = CRS::<Bls12_381>::new(batch_size, &mut rng);
        let prf = PRF::<Bls12_381>::new(&mut rng);

        let point = 3;
        let pprf = prf.puncture(point, &crs);

        let input = 5;
        let output = prf.eval(input, &crs);
        let punctured_output = pprf.eval(input, &crs);

        assert_eq!(output, punctured_output);
    }

    #[test]
    fn test_homomorphism() {
        let mut rng = test_rng();
        let batch_size = 10;
        let crs = CRS::<Bls12_381>::new(batch_size, &mut rng);

        let prf1 = PRF::<Bls12_381>::new(&mut rng);
        let prf2 = PRF::<Bls12_381>::new(&mut rng);

        let input = 7;
        let output = prf1.eval(input, &crs) + prf2.eval(input, &crs);

        let agg_key = prf1.key + prf2.key;
        let agg_prf = PRF::<Bls12_381>::from_key(agg_key);

        let agg_output = agg_prf.eval(input, &crs);
        assert_eq!(output, agg_output);

        let point1 = 3;
        let point2 = 5;
        let pprf1 = prf1.puncture(point1, &crs);
        let pprf2 = prf2.puncture(point2, &crs);

        let output = batch_eval(&vec![pprf1, pprf2], input, &crs);

        assert_eq!(output, agg_output);
    }

    /// Verifies fft_batch_eval matches the reference k_agg.eval(i) - batch_eval(&pprfs, i) for all i.
    #[test]
    fn test_fft_batch_eval_correctness() {
        let mut rng = test_rng();
        let batch_size = 8;
        let crs = CRS::<Bls12_381>::new(batch_size, &mut rng);

        let prfs: Vec<PRF<Bls12_381>> = (0..batch_size)
            .map(|_| PRF::<Bls12_381>::new(&mut rng))
            .collect();
        let pprfs: Vec<PPRF<Bls12_381>> = prfs
            .iter()
            .enumerate()
            .map(|(i, p)| p.puncture(i, &crs))
            .collect();

        let k_agg_scalar = prfs.iter().map(|p| p.key).fold(
            <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField::zero(),
            |acc, k| acc + k,
        );
        let k_agg = PRF::<Bls12_381>::from_key(k_agg_scalar);

        let expected: Vec<_> = (0..batch_size)
            .map(|i| k_agg.eval(i, &crs) - batch_eval(&pprfs, i, &crs))
            .collect();

        let got = fft_batch_eval(&k_agg, &pprfs, &crs);

        assert_eq!(got.len(), batch_size);
        for i in 0..batch_size {
            assert_eq!(got[i], expected[i], "fft_batch_eval mismatch at position {i}");
        }
    }
}
