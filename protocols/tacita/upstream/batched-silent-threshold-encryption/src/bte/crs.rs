use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, PrimeGroup, ScalarMul};
use ark_ff::{One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::rand::Rng;
use ark_std::UniformRand;

#[derive(Clone, Debug)]
pub struct CRS<E: Pairing> {
    // contains g^{x^i} at positions i = 0, 1, ...,batch_size, batch_size+2, ..., 2*batch_size
    // at position i = batch_size+1, contains g^0
    pub powers_of_g: Vec<E::G1>,
    pub powers_of_h: Vec<E::G2>,
    pub gt_nplus1: PairingOutput<E>,
    pub batch_size: usize,
    /// FFT size N = next_power_of_two(2 * batch_size). Used for the convolution in fft_batch_eval.
    pub fft_size: usize,
    /// Precomputed FFT of the circular B-vector, stored in affine form for efficient pairing.
    ///
    /// batch_eval(i) = Σ_j e(pprfs[j].key, powers_of_h[B+1+i-j])
    ///              = Σ_j e(A[j], B_vec[(i-j) mod N])   (circular cross-correlation)
    ///
    /// B_vec layout (length N ≥ 2B):
    ///   B_vec[k]   = powers_of_h[B+1+k]  for k = 0..B-1   (positive lags)
    ///   B_vec[N-j] = powers_of_h[B+1-j]  for j = 1..B-1   (negative lags, wrapped)
    ///   remainder  = G2::zero()                              (dead-zone, prevents aliasing)
    ///
    /// B_vec[0] = powers_of_h[B+1] = [0] → self-evaluation (i==j) contributes zero ✓
    pub fft_h: Vec<E::G2Affine>,
    /// Precomputed `e(g,h)^{τ^{B+1+i}}` for `i = 0..B-1`.
    /// Lets `PRF::eval` use a GT scalar mul instead of a full pairing.
    pub gt_powers: Vec<PairingOutput<E>>,
}

impl<E: Pairing> CRS<E> {
    pub fn new(batch_size: usize, rng: &mut impl Rng) -> Self {
        let x = E::ScalarField::rand(rng);
        let mut powers_of_x = vec![E::ScalarField::one()];

        let mut cur = x;
        for _ in 0..=2 * batch_size {
            powers_of_x.push(cur);
            cur *= &x;
        }
        // at position i = batch_size+1, contains 0
        powers_of_x[batch_size + 1] = E::ScalarField::zero();

        let powers_of_g_affine = E::G1::generator().batch_mul(&powers_of_x[0..=2 * batch_size]);
        let powers_of_g = powers_of_g_affine
            .iter()
            .map(|g| g.into_group())
            .collect::<Vec<_>>();

        let powers_of_h_affine = E::G2::generator().batch_mul(&powers_of_x[0..=2 * batch_size]);
        let powers_of_h = powers_of_h_affine
            .iter()
            .map(|h| h.into_group())
            .collect::<Vec<_>>();

        let gt_nplus1 = E::pairing(powers_of_g[batch_size], powers_of_h[1]);

        // gt_powers[i] = e(g, h)^{τ^{B+1+i}} — precomputed so PRF::eval avoids pairings.
        // i=0: powers_of_g[B+1] is zeroed, so use e(g^{τ^B}, h^τ) = gt_nplus1.
        // i>0: powers_of_g[B+1+i] has the real value.
        let mut gt_powers = Vec::with_capacity(batch_size);
        gt_powers.push(gt_nplus1);
        for i in 1..batch_size {
            gt_powers.push(E::pairing(
                powers_of_g_affine[batch_size + 1 + i],
                powers_of_h_affine[0],
            ));
        }

        // --- FFT precomputation for fft_batch_eval ---
        //
        // Build circular B_vec of length N, then take its FFT using arkworks'
        // generic EvaluationDomain::fft_in_place which works over any DomainCoeff<F> —
        // including E::G2 (projective group elements implement the required trait bounds).
        let fft_size = (2 * batch_size).next_power_of_two();
        assert!(fft_size >= 2 * batch_size);

        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(fft_size)
            .expect("fft_size must be a power of two within the field's 2-adicity");

        let mut b_vec: Vec<E::G2> = vec![E::G2::zero(); fft_size];

        // Positive lags: b_vec[k] = powers_of_h[B+1+k]  for k = 0..B-1
        for k in 0..batch_size {
            b_vec[k] = powers_of_h[batch_size + 1 + k];
        }
        // Negative lags: b_vec[N-j] = powers_of_h[B+1-j]  for j = 1..B-1
        // (j=1: h^{τ^B}, j=2: h^{τ^{B-1}}, ..., j=B-1: h^{τ^2})
        for j in 1..batch_size {
            b_vec[fft_size - j] = powers_of_h[batch_size + 1 - j];
        }

        // Use arkworks' generic FFT — works because E::G2 implements DomainCoeff<ScalarField>.
        domain.fft_in_place(&mut b_vec);

        let fft_h: Vec<E::G2Affine> = b_vec.iter().map(|h| (*h).into()).collect();

        Self {
            powers_of_g,
            powers_of_h,
            gt_nplus1,
            batch_size,
            fft_size,
            fft_h,
            gt_powers,
        }
    }
}
