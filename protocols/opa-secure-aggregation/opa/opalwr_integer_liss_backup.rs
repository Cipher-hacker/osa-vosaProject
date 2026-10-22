// NOTE: The original field-Shamir prototype has been preserved in
// `opalwr_field_shamir_backup.rs`. This file now follows the paper's
// integer-secret-sharing style more closely by replacing F_q Shamir sharing
// with secret sharing over Z using the Delta = m! scaling factor.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::{Rng, RngCore};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpaError {
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("invalid aux payload")]
    InvalidAuxPayload,
    #[error("context mismatch")]
    ContextMismatch,
    #[error("not enough committee responses")]
    NotEnoughCommitteeResponses,
    #[error("not enough shares to reconstruct")]
    NotEnoughShares,
    #[error("integer-sharing arithmetic overflow")]
    ArithmeticOverflow,
    #[error("non-integral interpolation coefficient")]
    NonIntegralCoefficient,
    #[error("non-integral reconstruction result")]
    NonIntegralReconstruction,
    #[error("negative reconstructed secret")]
    NegativeReconstructedSecret,
}

#[derive(Clone, Debug)]
pub struct OpaParameters {
    pub vector_len: usize,
    pub log_n: usize,
    pub seed_dim: usize,
    pub committee_size: usize,
    pub threshold_t: usize,
    pub threshold_r: usize,
    pub q: u64,
    pub p: u64,
    pub stat_sec_bits: u32,
}

impl OpaParameters {
    pub fn validate(&self) -> Result<(), OpaError> {
        if self.vector_len == 0 {
            return Err(OpaError::InvalidParameter("vector_len must be positive"));
        }
        if self.log_n == 0 {
            return Err(OpaError::InvalidParameter("log_n must be positive"));
        }
        if self.seed_dim == 0 {
            return Err(OpaError::InvalidParameter("seed_dim must be positive"));
        }
        if self.committee_size == 0 {
            return Err(OpaError::InvalidParameter("committee_size must be positive"));
        }
        if self.threshold_r == 0 || self.threshold_r > self.committee_size {
            return Err(OpaError::InvalidParameter("threshold_r must be in 1..=committee_size"));
        }
        if self.threshold_t >= self.threshold_r {
            return Err(OpaError::InvalidParameter("threshold_t must be smaller than threshold_r"));
        }
        if self.q <= self.p {
            return Err(OpaError::InvalidParameter("q must be strictly greater than p"));
        }
        factorial_i128(self.committee_size)?;
        Ok(())
    }

    fn delta(&self, num_active_clients: usize) -> u64 {
        (num_active_clients as u64) << self.stat_sec_bits
    }

    fn ring_degree(&self) -> usize {
        1 << self.log_n
    }

    fn num_polynomials(&self) -> usize {
        self.vector_len.div_ceil(self.ring_degree())
    }

    fn padded_len(&self) -> usize {
        self.num_polynomials() * self.ring_degree()
    }

    fn share_secret_bits(&self) -> u32 {
        64 - self.q.saturating_sub(1).leading_zeros()
    }

    fn integer_share_random_bits(&self) -> u32 {
        let log_m = ceil_log2_u64(self.committee_size as u64 + 1);
        let log_t = ceil_log2_u64(self.threshold_t as u64 + 1);
        let log_r = ceil_log2_u64(self.threshold_r as u64 + 1);
        (self.share_secret_bits() + self.stat_sec_bits + log_m + log_t + log_r).min(120)
    }
}

#[derive(Clone, Debug)]
pub struct PackedRingVector {
    pub ring_degree: usize,
    pub polynomials: Vec<Vec<u64>>,
}

impl PackedRingVector {
    fn from_flat(values: &[u64], ring_degree: usize) -> Result<Self, OpaError> {
        if ring_degree == 0 || values.len() % ring_degree != 0 {
            return Err(OpaError::InvalidParameter("values length must be a multiple of ring_degree"));
        }
        let polynomials = values.chunks(ring_degree).map(|chunk| chunk.to_vec()).collect();
        Ok(Self { ring_degree, polynomials })
    }

    fn zero(num_polynomials: usize, ring_degree: usize) -> Self {
        Self { ring_degree, polynomials: vec![vec![0_u64; ring_degree]; num_polynomials] }
    }

    fn flatten(&self) -> Vec<u64> {
        self.polynomials.iter().flat_map(|poly| poly.iter().copied()).collect()
    }

    pub fn coeff_count(&self) -> usize {
        self.polynomials.len() * self.ring_degree
    }
}

#[derive(Clone, Debug)]
pub struct LwrShprg {
    params: OpaParameters,
    matrix: Vec<Vec<u64>>,
}

impl LwrShprg {
    pub fn new(params: OpaParameters, rng: &mut StdRng) -> Result<Self, OpaError> {
        params.validate()?;
        let mut matrix = Vec::with_capacity(params.padded_len());
        for _ in 0..params.padded_len() {
            let mut row = Vec::with_capacity(params.seed_dim);
            for _ in 0..params.seed_dim {
                row.push(random_mod_q(params.q, rng));
            }
            matrix.push(row);
        }
        Ok(Self { params, matrix })
    }

    pub fn params(&self) -> &OpaParameters {
        &self.params
    }

    pub fn sample_seed(&self, rng: &mut StdRng) -> Vec<u64> {
        (0..self.params.seed_dim).map(|_| random_mod_q(self.params.q, rng)).collect()
    }

    pub fn expand(&self, seed: &[u64]) -> Result<Vec<u64>, OpaError> {
        if seed.len() != self.params.seed_dim {
            return Err(OpaError::InvalidParameter("seed length mismatch"));
        }
        let mut out = Vec::with_capacity(self.params.padded_len());
        for row in &self.matrix {
            let mut acc = 0_u64;
            for (&a, &s) in row.iter().zip(seed.iter()) {
                acc = mod_add(acc, mod_mul(a, s, self.params.q), self.params.q);
            }
            let rounded = ((acc as u128 * self.params.p as u128) / self.params.q as u128) as u64;
            out.push(rounded % self.params.p);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug)]
pub struct CommitteeKeyPair {
    secret: Scalar,
    public: RistrettoPoint,
}

impl CommitteeKeyPair {
    pub fn generate(rng: &mut StdRng) -> Self {
        let secret = random_scalar(rng);
        let public = secret * RISTRETTO_BASEPOINT_POINT;
        Self { secret, public }
    }

    pub fn public(&self) -> RistrettoPoint {
        self.public
    }
}

#[derive(Clone, Debug)]
pub struct CommitteeCiphertext {
    pub ephemeral_public: [u8; 32],
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AuxShare {
    iteration: u64,
    client_id: u64,
    seed_share: Vec<i128>,
    digest_share: i128,
}

impl AuxShare {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + self.seed_share.len() * 16);
        out.extend_from_slice(&self.iteration.to_le_bytes());
        out.extend_from_slice(&self.client_id.to_le_bytes());
        out.extend_from_slice(&(self.seed_share.len() as u64).to_le_bytes());
        for &value in &self.seed_share {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&self.digest_share.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, OpaError> {
        if bytes.len() < 40 {
            return Err(OpaError::InvalidAuxPayload);
        }
        let iteration = read_u64(bytes, 0)?;
        let client_id = read_u64(bytes, 8)?;
        let seed_len = read_u64(bytes, 16)? as usize;
        let expected = 40 + seed_len * 16;
        if bytes.len() != expected {
            return Err(OpaError::InvalidAuxPayload);
        }
        let mut seed_share = Vec::with_capacity(seed_len);
        let mut offset = 24;
        for _ in 0..seed_len {
            seed_share.push(read_i128(bytes, offset)?);
            offset += 16;
        }
        let digest_share = read_i128(bytes, offset)?;
        Ok(Self { iteration, client_id, seed_share, digest_share })
    }
}

#[derive(Clone, Debug)]
pub struct ClientUpload {
    pub client_id: usize,
    pub ciphertext: PackedRingVector,
    pub encrypted_aux_shares: Vec<CommitteeCiphertext>,
}

#[derive(Clone, Debug)]
pub struct CommitteeAggregate {
    pub committee_member_id: usize,
    pub summed_seed_share: Vec<i128>,
    pub digest_shares: BTreeMap<usize, i128>,
}

#[derive(Clone, Debug)]
pub struct OpaClient {
    pub client_id: usize,
}

impl OpaClient {
    pub fn encrypt(
        &self,
        iteration: u64,
        values: &[u64],
        shprg: &LwrShprg,
        committee_public_keys: &[RistrettoPoint],
        num_active_clients: usize,
        rng: &mut StdRng,
    ) -> Result<ClientUpload, OpaError> {
        let params = shprg.params();
        if values.len() != params.vector_len {
            return Err(OpaError::InvalidParameter("input vector length mismatch"));
        }
        if committee_public_keys.len() != params.committee_size {
            return Err(OpaError::InvalidParameter("committee public key length mismatch"));
        }

        let seed = shprg.sample_seed(rng);
        let digest = random_mod_q(params.q, rng);
        let mask = shprg.expand(&seed)?;
        let hash_mask = hash_mask_vector(digest, params.padded_len(), params.p);
        let encoded = encode(values, params.padded_len(), params.delta(num_active_clients), params.p, rng);
        let ciphertext = PackedRingVector::from_flat(
            &add_vectors_mod_p(&add_vectors_mod_p(&encoded, &mask, params.p), &hash_mask, params.p),
            params.ring_degree(),
        )?;

        let seed_shares = integer_share_vector(&seed, params, rng)?;
        let digest_shares = integer_share_scalar(digest, params, rng)?;

        let mut encrypted_aux_shares = Vec::with_capacity(params.committee_size);
        for committee_index in 0..params.committee_size {
            let aux = AuxShare {
                iteration,
                client_id: self.client_id as u64,
                seed_share: seed_shares[committee_index].1.clone(),
                digest_share: digest_shares[committee_index].1,
            };
            let aad = aad(iteration, self.client_id, committee_index + 1);
            encrypted_aux_shares.push(encrypt_aux(
                committee_public_keys[committee_index],
                &aad,
                &aux.encode(),
                rng,
            ));
        }

        Ok(ClientUpload { client_id: self.client_id, ciphertext, encrypted_aux_shares })
    }
}

#[derive(Clone, Debug)]
pub struct OpaCommitteeMember {
    pub committee_member_id: usize,
    pub key_pair: CommitteeKeyPair,
}

impl OpaCommitteeMember {
    pub fn new(committee_member_id: usize, rng: &mut StdRng) -> Self {
        Self { committee_member_id, key_pair: CommitteeKeyPair::generate(rng) }
    }

    pub fn process(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        uploads: &[ClientUpload],
        params: &OpaParameters,
    ) -> Result<CommitteeAggregate, OpaError> {
        let mut summed_seed_share = vec![0_i128; params.seed_dim];
        let mut digest_shares = BTreeMap::new();

        for upload in uploads {
            if !active_clients.contains(&upload.client_id) {
                return Err(OpaError::ContextMismatch);
            }
            let aad = aad(iteration, upload.client_id, self.committee_member_id);
            let plaintext = decrypt_aux(
                &self.key_pair,
                &aad,
                &upload.encrypted_aux_shares[self.committee_member_id - 1],
            )?;
            let aux = AuxShare::decode(&plaintext)?;
            if aux.iteration != iteration || aux.client_id != upload.client_id as u64 {
                return Err(OpaError::ContextMismatch);
            }
            for (dst, value) in summed_seed_share.iter_mut().zip(aux.seed_share.iter()) {
                *dst = checked_add_i128(*dst, *value)?;
            }
            digest_shares.insert(upload.client_id, aux.digest_share);
        }

        Ok(CommitteeAggregate {
            committee_member_id: self.committee_member_id,
            summed_seed_share,
            digest_shares,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OpaServer {
    pub shprg: LwrShprg,
}

impl OpaServer {
    pub fn new(shprg: LwrShprg) -> Self {
        Self { shprg }
    }

    pub fn aggregate(
        &self,
        iteration: u64,
        uploads: &[ClientUpload],
        committee_outputs: &[CommitteeAggregate],
    ) -> Result<Vec<u64>, OpaError> {
        let params = self.shprg.params();
        if committee_outputs.len() < params.threshold_r {
            return Err(OpaError::NotEnoughCommitteeResponses);
        }

        let active_clients: BTreeSet<usize> = uploads.iter().map(|upload| upload.client_id).collect();
        let selected_outputs = &committee_outputs[..params.threshold_r];

        let seed_points: Vec<(u64, Vec<i128>)> = selected_outputs
            .iter()
            .map(|output| (output.committee_member_id as u64, output.summed_seed_share.clone()))
            .collect();
        let reconstructed_seed_sum = integer_reconstruct_vector(&seed_points, params)?;
        let aux_mask = self.shprg.expand(&reconstructed_seed_sum)?;

        let mut digest_masks_sum = vec![0_u64; params.padded_len()];
        for client_id in &active_clients {
            let shares: Result<Vec<(u64, i128)>, OpaError> = selected_outputs
                .iter()
                .map(|output| {
                    output
                        .digest_shares
                        .get(client_id)
                        .copied()
                        .map(|share| (output.committee_member_id as u64, share))
                        .ok_or(OpaError::NotEnoughShares)
                })
                .collect();
            let digest = integer_reconstruct_scalar(&shares?, params)?;
            let mask = hash_mask_vector(digest, params.padded_len(), params.p);
            digest_masks_sum = add_vectors_mod_p(&digest_masks_sum, &mask, params.p);
        }

        let summed_ciphertexts = uploads.iter().fold(
            PackedRingVector::zero(params.num_polynomials(), params.ring_degree()),
            |acc, upload| add_packed_ring_vectors(&acc, &upload.ciphertext, params.p),
        );
        let summed_ciphertexts = summed_ciphertexts.flatten();
        let unmasked_once = sub_vectors_mod_p(&summed_ciphertexts, &aux_mask, params.p);
        let unmasked = sub_vectors_mod_p(&unmasked_once, &digest_masks_sum, params.p);

        Ok(decode(
            &unmasked,
            params.vector_len,
            params.delta(active_clients.len()),
            iteration,
            params.p,
        ))
    }
}

fn aad(iteration: u64, client_id: usize, committee_member_id: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&iteration.to_le_bytes());
    out.extend_from_slice(&(client_id as u64).to_le_bytes());
    out.extend_from_slice(&(committee_member_id as u64).to_le_bytes());
    out
}

fn encrypt_aux(
    public_key: RistrettoPoint,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut StdRng,
) -> CommitteeCiphertext {
    let ephemeral_secret = random_scalar(rng);
    let ephemeral_public = (ephemeral_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let shared = (ephemeral_secret * public_key).compress().to_bytes();
    let keystream = derive_keystream(&shared, aad, plaintext.len());
    let body = plaintext
        .iter()
        .zip(keystream.iter())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .collect();
    CommitteeCiphertext { ephemeral_public, body }
}

fn decrypt_aux(
    key_pair: &CommitteeKeyPair,
    aad: &[u8],
    ciphertext: &CommitteeCiphertext,
) -> Result<Vec<u8>, OpaError> {
    let eph = CompressedRistretto(ciphertext.ephemeral_public)
        .decompress()
        .ok_or(OpaError::InvalidCiphertext)?;
    let shared = (key_pair.secret * eph).compress().to_bytes();
    let keystream = derive_keystream(&shared, aad, ciphertext.body.len());
    Ok(ciphertext
        .body
        .iter()
        .zip(keystream.iter())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .collect())
}

fn derive_keystream(shared_secret: &[u8; 32], aad: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u64;
    while out.len() < len {
        let mut hash = Sha3_256::new();
        hash.update(shared_secret);
        hash.update(aad);
        hash.update(counter.to_le_bytes());
        out.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn hash_mask_vector(digest: u64, len: usize, p: u64) -> Vec<u64> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u64;
    while out.len() < len {
        let mut hash = Sha3_256::new();
        hash.update(b"opa-digest-mask");
        hash.update(digest.to_le_bytes());
        hash.update(counter.to_le_bytes());
        let block = hash.finalize();
        for chunk in block.chunks_exact(8) {
            let mut arr = [0_u8; 8];
            arr.copy_from_slice(chunk);
            out.push(u64::from_le_bytes(arr) % p);
            if out.len() == len {
                break;
            }
        }
        counter += 1;
    }
    out
}

fn encode(values: &[u64], padded_len: usize, delta: u64, p: u64, rng: &mut StdRng) -> Vec<u64> {
    let mut out: Vec<u64> = values
        .iter()
        .map(|&value| {
            let randomizer = rng.gen_range(0..(1_u64 << 8));
            (value * delta + randomizer + 1) % p
        })
        .collect();
    out.resize(padded_len, 0_u64);
    out
}

fn decode(values: &[u64], output_len: usize, delta: u64, _iteration: u64, _p: u64) -> Vec<u64> {
    values
        .iter()
        .take(output_len)
        .map(|&value| value.div_ceil(delta).saturating_sub(1))
        .collect()
}

fn integer_share_scalar(
    secret: u64,
    params: &OpaParameters,
    rng: &mut StdRng,
) -> Result<Vec<(u64, i128)>, OpaError> {
    let delta = factorial_i128(params.committee_size)?;
    let mut coeffs = Vec::with_capacity(params.threshold_r);
    coeffs.push(checked_mul_i128(secret as i128, delta)?);
    let random_bits = params.integer_share_random_bits();
    for _ in 1..params.threshold_r {
        coeffs.push(random_nonnegative_i128(random_bits, rng)?);
    }

    let mut shares = Vec::with_capacity(params.committee_size);
    for x in 1..=params.committee_size {
        let x_i = x as i128;
        let mut y = 0_i128;
        let mut x_power = 1_i128;
        for &coeff in &coeffs {
            y = checked_add_i128(y, checked_mul_i128(coeff, x_power)?)?;
            x_power = checked_mul_i128(x_power, x_i)?;
        }
        shares.push((x as u64, y));
    }
    Ok(shares)
}

fn integer_share_vector(
    secret: &[u64],
    params: &OpaParameters,
    rng: &mut StdRng,
) -> Result<Vec<(u64, Vec<i128>)>, OpaError> {
    let mut shares: Vec<(u64, Vec<i128>)> = (1..=params.committee_size)
        .map(|x| (x as u64, vec![0_i128; secret.len()]))
        .collect();
    for (coord, value) in secret.iter().enumerate() {
        let scalar_shares = integer_share_scalar(*value, params, rng)?;
        for (index, (_, share)) in scalar_shares.into_iter().enumerate() {
            shares[index].1[coord] = share;
        }
    }
    Ok(shares)
}

fn integer_reconstruct_scalar(points: &[(u64, i128)], params: &OpaParameters) -> Result<u64, OpaError> {
    if points.len() < params.threshold_r {
        return Err(OpaError::NotEnoughShares);
    }
    let used = &points[..params.threshold_r];
    let coeffs = integer_reconstruction_coefficients(
        &used.iter().map(|(x, _)| *x).collect::<Vec<_>>(),
        params.committee_size,
    )?;
    let mut recovered_scaled = 0_i128;
    for ((_, share), coeff) in used.iter().zip(coeffs.iter()) {
        recovered_scaled = checked_add_i128(recovered_scaled, checked_mul_i128(*share, *coeff)?)?;
    }

    let delta = factorial_i128(params.committee_size)?;
    let scale = checked_mul_i128(delta, delta)?;
    if recovered_scaled % scale != 0 {
        return Err(OpaError::NonIntegralReconstruction);
    }
    let secret = recovered_scaled / scale;
    if secret < 0 {
        return Err(OpaError::NegativeReconstructedSecret);
    }
    Ok(normalize_mod_q(secret, params.q))
}

fn integer_reconstruct_vector(
    points: &[(u64, Vec<i128>)],
    params: &OpaParameters,
) -> Result<Vec<u64>, OpaError> {
    if points.len() < params.threshold_r {
        return Err(OpaError::NotEnoughShares);
    }
    let coords = points[0].1.len();
    let mut out = vec![0_u64; coords];
    for coord in 0..coords {
        let scalar_points: Vec<(u64, i128)> = points
            .iter()
            .take(params.threshold_r)
            .map(|(x, y)| (*x, y[coord]))
            .collect();
        out[coord] = integer_reconstruct_scalar(&scalar_points, params)?;
    }
    Ok(out)
}

fn integer_reconstruction_coefficients(indices: &[u64], committee_size: usize) -> Result<Vec<i128>, OpaError> {
    let delta = factorial_i128(committee_size)?;
    let mut coeffs = Vec::with_capacity(indices.len());
    for (i, &x_i) in indices.iter().enumerate() {
        let mut numerator = delta;
        let mut denominator = 1_i128;
        for (j, &x_j) in indices.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = checked_mul_i128(numerator, x_j as i128)?;
            denominator = checked_mul_i128(denominator, x_j as i128 - x_i as i128)?;
        }
        if denominator == 0 || numerator % denominator != 0 {
            return Err(OpaError::NonIntegralCoefficient);
        }
        coeffs.push(numerator / denominator);
    }
    Ok(coeffs)
}

fn add_vectors_mod_p(lhs: &[u64], rhs: &[u64], p: u64) -> Vec<u64> {
    lhs.iter().zip(rhs.iter()).map(|(&a, &b)| mod_add(a, b, p)).collect()
}

fn add_packed_ring_vectors(lhs: &PackedRingVector, rhs: &PackedRingVector, modulus: u64) -> PackedRingVector {
    PackedRingVector {
        ring_degree: lhs.ring_degree,
        polynomials: lhs
            .polynomials
            .iter()
            .zip(rhs.polynomials.iter())
            .map(|(left, right)| add_vectors_mod_p(left, right, modulus))
            .collect(),
    }
}

fn sub_vectors_mod_p(lhs: &[u64], rhs: &[u64], p: u64) -> Vec<u64> {
    lhs.iter().zip(rhs.iter()).map(|(&a, &b)| mod_sub(a, b, p)).collect()
}

fn mod_add(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 + b as u128) % modulus as u128) as u64
}

fn mod_sub(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 + modulus as u128 - b as u128) % modulus as u128) as u64
}

fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

fn checked_add_i128(lhs: i128, rhs: i128) -> Result<i128, OpaError> {
    lhs.checked_add(rhs).ok_or(OpaError::ArithmeticOverflow)
}

fn checked_mul_i128(lhs: i128, rhs: i128) -> Result<i128, OpaError> {
    lhs.checked_mul(rhs).ok_or(OpaError::ArithmeticOverflow)
}

fn factorial_i128(n: usize) -> Result<i128, OpaError> {
    let mut acc = 1_i128;
    for value in 2..=n {
        acc = checked_mul_i128(acc, value as i128)?;
    }
    Ok(acc)
}

fn random_nonnegative_i128(bits: u32, rng: &mut StdRng) -> Result<i128, OpaError> {
    if bits > 120 {
        return Err(OpaError::InvalidParameter(
            "integer-share randomness is too wide for the i128 prototype",
        ));
    }
    if bits == 0 {
        return Ok(0);
    }
    let raw: u128 = rng.gen();
    let mask = if bits == 128 { u128::MAX } else { (1_u128 << bits) - 1 };
    i128::try_from(raw & mask).map_err(|_| OpaError::ArithmeticOverflow)
}

fn normalize_mod_q(value: i128, q: u64) -> u64 {
    value.rem_euclid(q as i128) as u64
}

fn ceil_log2_u64(value: u64) -> u32 {
    if value <= 1 {
        0
    } else {
        64 - (value - 1).leading_zeros()
    }
}

fn random_mod_q(q: u64, rng: &mut StdRng) -> u64 {
    rng.next_u64() % q
}

fn random_scalar(rng: &mut StdRng) -> Scalar {
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, OpaError> {
    let end = offset + 8;
    let slice = bytes.get(offset..end).ok_or(OpaError::InvalidAuxPayload)?;
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}

fn read_i128(bytes: &[u8], offset: usize) -> Result<i128, OpaError> {
    let end = offset + 16;
    let slice = bytes.get(offset..end).ok_or(OpaError::InvalidAuxPayload)?;
    let mut buf = [0_u8; 16];
    buf.copy_from_slice(slice);
    Ok(i128::from_le_bytes(buf))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::SeedableRng;

    fn test_params() -> OpaParameters {
        OpaParameters {
            vector_len: 10,
            log_n: 2,
            seed_dim: 4,
            committee_size: 5,
            threshold_t: 1,
            threshold_r: 3,
            q: 2_305_843_009_213_693_951,
            p: 2_147_483_647,
            stat_sec_bits: 8,
        }
    }

    #[test]
    fn integer_round_trip_vector() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(7);
        let secret = vec![7, 11, 13, 17];
        let shares = integer_share_vector(&secret, &params, &mut rng).unwrap();
        let recovered = integer_reconstruct_vector(&shares[..params.threshold_r], &params).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn integer_round_trip_scalar_wraps_mod_q() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(8);
        let secret = params.q + 9;
        let shares = integer_share_scalar(secret, &params, &mut rng).unwrap();
        let recovered = integer_reconstruct_scalar(&shares[..params.threshold_r], &params).unwrap();
        assert_eq!(9, recovered);
    }

    #[test]
    fn opalwr_end_to_end_with_client_and_committee_dropouts() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(42);
        let shprg = LwrShprg::new(params.clone(), &mut rng).unwrap();
        let server = OpaServer::new(shprg.clone());

        let committees: Vec<OpaCommitteeMember> = (1..=params.committee_size)
            .map(|id| OpaCommitteeMember::new(id, &mut rng))
            .collect();
        let committee_public_keys: Vec<RistrettoPoint> =
            committees.iter().map(|member| member.key_pair.public()).collect();

        let raw_inputs = [
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            vec![2, 4, 6, 8, 10, 12, 14, 16, 18, 20],
            vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        ];
        let active_mask = [true, false, true, true];

        let uploads: Vec<ClientUpload> = raw_inputs
            .iter()
            .enumerate()
            .filter_map(|(index, values)| {
                active_mask[index].then(|| {
                    OpaClient { client_id: index + 1 }
                        .encrypt(9, values, &shprg, &committee_public_keys, raw_inputs.len() - 1, &mut rng)
                        .unwrap()
                })
            })
            .collect();

        let active_clients = uploads.iter().map(|upload| upload.client_id).collect::<BTreeSet<_>>();
        let available_committees = [&committees[0], &committees[2], &committees[4]];
        let committee_outputs: Vec<CommitteeAggregate> = available_committees
            .iter()
            .map(|member| member.process(9, &active_clients, &uploads, &params).unwrap())
            .collect();

        let expected: Vec<u64> = raw_inputs
            .iter()
            .enumerate()
            .filter(|(index, _)| active_mask[*index])
            .fold(vec![0_u64; params.vector_len], |mut acc, (_, values)| {
                for (dst, value) in acc.iter_mut().zip(values.iter()) {
                    *dst += *value;
                }
                acc
            });

        let aggregate = server.aggregate(9, &uploads, &committee_outputs).unwrap();
        assert_eq!(expected, aggregate);
        assert_eq!(active_uploads_len(&uploads), 3);
        assert_eq!(uploads[0].ciphertext.polynomials.len(), params.num_polynomials());
        assert_eq!(uploads[0].ciphertext.ring_degree, params.ring_degree());
    }

    #[test]
    fn committee_rejects_wrong_context() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(3);
        let shprg = LwrShprg::new(params.clone(), &mut rng).unwrap();
        let committee = OpaCommitteeMember::new(1, &mut rng);
        let committee_public_keys = vec![committee.key_pair.public(); params.committee_size];
        let upload = OpaClient { client_id: 1 }
            .encrypt(5, &[3, 3, 3, 3, 3, 3, 3, 3, 3, 3], &shprg, &committee_public_keys, 1, &mut rng)
            .unwrap();
        let err = committee
            .process(6, &BTreeSet::from([1]), &[upload], &params)
            .unwrap_err();
        assert!(matches!(err, OpaError::ContextMismatch | OpaError::InvalidAuxPayload));
    }

    fn active_uploads_len(uploads: &[ClientUpload]) -> usize {
        uploads.len()
    }
}


