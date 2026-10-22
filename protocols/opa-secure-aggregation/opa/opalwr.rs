use crypto_bigint::{U256, Wrapping};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::{Rng, RngCore};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

// The paper specifies q as a 128-bit prime. The text available in this
// workspace does not expose a unique literal, so we use a fixed prime close to
// 2^128: 2^128 - 159.
const PAPER_Q: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_297;
const PAPER_P: u128 = 1_u128 << 53;
const PAPER_FL_P: u128 = 1_u128 << 85;
const PAPER_SEED_DIM: usize = 2048;
const PAPER_PACKED_SECRET_DIM: usize = 16;
const PAPER_COMMITTEE_SIZE: usize = 50;
const PAPER_THRESHOLD_R: usize = 34;
const PAPER_STAT_SEC_BITS: u32 = 40;
#[cfg(opa_fixed_q_optimized)]
const PAPER_Q_COMPLEMENT: u128 = 159;

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
}

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

impl OpaParameters {
    pub fn validate(&self) -> Result<(), OpaError> {
        if self.vector_len == 0 {
            return Err(OpaError::InvalidParameter("vector_len must be positive"));
        }
        if self.seed_dim == 0 {
            return Err(OpaError::InvalidParameter("seed_dim must be positive"));
        }
        if self.packed_secret_dim == 0 {
            return Err(OpaError::InvalidParameter("packed_secret_dim must be positive"));
        }
        if self.committee_size == 0 {
            return Err(OpaError::InvalidParameter("committee_size must be positive"));
        }
        if self.threshold_r == 0 || self.threshold_r > self.committee_size {
            return Err(OpaError::InvalidParameter("threshold_r must be in 1..=committee_size"));
        }
        if self.packed_secret_dim >= self.threshold_r {
            return Err(OpaError::InvalidParameter(
                "packed_secret_dim must be smaller than threshold_r",
            ));
        }
        if self.seed_dim % self.packed_secret_dim != 0 {
            return Err(OpaError::InvalidParameter(
                "seed_dim must be divisible by packed_secret_dim",
            ));
        }
        if self.q <= self.p {
            return Err(OpaError::InvalidParameter("q must be strictly greater than p"));
        }
        Ok(())
    }

    pub fn encoding_delta(&self, client_bound: usize) -> Result<u128, OpaError> {
        let delta = (client_bound as u128)
            .checked_shl(self.stat_sec_bits)
            .ok_or(OpaError::InvalidParameter("encoding delta overflow"))?;
        if delta == 0 || delta >= self.p {
            return Err(OpaError::InvalidParameter("encoding delta must be in 1..p"));
        }
        Ok(delta)
    }

    pub fn max_safe_aggregate_coordinate(&self, client_bound: usize) -> Result<u128, OpaError> {
        let delta = self.encoding_delta(client_bound)?;
        Ok((self.p - delta - 1) / delta)
    }

    fn packed_share_count(&self) -> usize {
        self.seed_dim / self.packed_secret_dim
    }
}

pub fn paper_benchmark_params(vector_len: usize) -> OpaParameters {
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

/// Paper-compatible parameters with the wider plaintext modulus required by
/// bounded fixed-point federated updates. The q, LWR seed dimension, packed
/// sharing dimensions, committee, threshold, and statistical security
/// parameter are identical to the main optimized benchmark target.
pub fn paper_fl_benchmark_params(vector_len: usize) -> OpaParameters {
    let mut params = paper_benchmark_params(vector_len);
    params.p = PAPER_FL_P;
    params
}

pub fn packed_share_count_for_committee(params: &OpaParameters) -> usize {
    params.packed_share_count()
}

#[derive(Clone, Debug)]
pub struct LwrShprg {
    params: OpaParameters,
    matrix: Vec<u128>,
}

impl LwrShprg {
    pub fn new(params: OpaParameters, rng: &mut StdRng) -> Result<Self, OpaError> {
        params.validate()?;
        let entry_count = params
            .vector_len
            .checked_mul(params.seed_dim)
            .ok_or(OpaError::InvalidParameter("matrix dimensions overflow"))?;
        let matrix = (0..entry_count)
            .map(|_| random_mod_q(params.q, rng))
            .collect::<Vec<_>>();
        Ok(Self { params, matrix })
    }

    pub fn params(&self) -> &OpaParameters {
        &self.params
    }

    pub fn sample_seed(&self, rng: &mut StdRng) -> Vec<u128> {
        (0..self.params.seed_dim)
            .map(|_| random_mod_q(self.params.q, rng))
            .collect()
    }

    pub fn expand(&self, seed: &[u128]) -> Result<Vec<u128>, OpaError> {
        if seed.len() != self.params.seed_dim {
            return Err(OpaError::InvalidParameter("seed length mismatch"));
        }
        let mut out = Vec::with_capacity(self.params.vector_len);
        for row in self.matrix.chunks_exact(self.params.seed_dim) {
            let mut acc = 0_u128;
            for (&a, &s) in row.iter().zip(seed.iter()) {
                acc = mod_add(acc, mod_mul(a, s, self.params.q), self.params.q);
            }
            out.push(lwr_round(acc, self.params.p, self.params.q));
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
    seed_share: Vec<u128>,
    digest_share: u128,
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
            seed_share.push(read_u128(bytes, offset)?);
            offset += 16;
        }
        let digest_share = read_u128(bytes, offset)?;
        Ok(Self {
            iteration,
            client_id,
            seed_share,
            digest_share,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ClientUpload {
    pub client_id: usize,
    pub iteration: u64,
    pub encoding_client_bound: usize,
    pub ciphertext: Vec<u128>,
    pub encrypted_aux_shares: Vec<CommitteeCiphertext>,
}

#[derive(Clone, Debug)]
pub struct CommitteeAggregate {
    pub committee_member_id: usize,
    pub summed_seed_share: Vec<u128>,
    pub digest_shares: BTreeMap<usize, u128>,
}

#[derive(Clone, Debug)]
pub struct RoutedAuxShare {
    pub client_id: usize,
    pub ciphertext: CommitteeCiphertext,
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
            return Err(OpaError::InvalidParameter(
                "committee public key length mismatch",
            ));
        }

        let seed = shprg.sample_seed(rng);
        let digest = random_mod_q(params.q, rng);
        let mask = shprg.expand(&seed)?;
        let hash_mask = hash_mask_vector(digest, params.vector_len, params.p);
        let delta = params.encoding_delta(num_active_clients)?;
        let max_safe_coordinate = params.max_safe_aggregate_coordinate(num_active_clients)?;
        if values.iter().any(|&value| value as u128 > max_safe_coordinate) {
            return Err(OpaError::InvalidParameter("input exceeds OPA encoding correctness bound"));
        }
        let encoded = encode(
            values,
            delta,
            params.p,
            params.stat_sec_bits,
            rng,
        );
        let ciphertext =
            add_vectors_mod_p(&add_vectors_mod_p(&encoded, &mask, params.p), &hash_mask, params.p);

        let seed_shares = packed_share_secret(
            &seed,
            params.packed_secret_dim,
            params.threshold_r,
            params.committee_size,
            params.q,
            rng,
        )?;
        let digest_shares = shamir_share_scalar(
            digest,
            params.threshold_r - 1,
            params.committee_size,
            params.q,
            rng,
        )?;

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

        Ok(ClientUpload {
            client_id: self.client_id,
            iteration,
            encoding_client_bound: num_active_clients,
            ciphertext,
            encrypted_aux_shares,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OpaCommitteeMember {
    pub committee_member_id: usize,
    pub key_pair: CommitteeKeyPair,
}

impl OpaCommitteeMember {
    pub fn new(committee_member_id: usize, rng: &mut StdRng) -> Self {
        Self {
            committee_member_id,
            key_pair: CommitteeKeyPair::generate(rng),
        }
    }

    pub fn process(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        uploads: &[ClientUpload],
        params: &OpaParameters,
    ) -> Result<CommitteeAggregate, OpaError> {
        let routed = uploads
            .iter()
            .map(|upload| RoutedAuxShare {
                client_id: upload.client_id,
                ciphertext: upload.encrypted_aux_shares[self.committee_member_id - 1].clone(),
            })
            .collect::<Vec<_>>();
        self.process_routed(iteration, active_clients, &routed, params)
    }

    pub fn process_routed(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        routed: &[RoutedAuxShare],
        params: &OpaParameters,
    ) -> Result<CommitteeAggregate, OpaError> {
        let routed_clients = routed.iter().map(|share| share.client_id).collect::<BTreeSet<_>>();
        if routed.len() != active_clients.len() || &routed_clients != active_clients {
            return Err(OpaError::ContextMismatch);
        }
        let mut summed_seed_share = vec![0_u128; params.packed_share_count()];
        let mut digest_shares = BTreeMap::new();

        for share in routed {
            let aad = aad(iteration, share.client_id, self.committee_member_id);
            let plaintext = decrypt_aux(
                &self.key_pair,
                &aad,
                &share.ciphertext,
            )?;
            let aux = AuxShare::decode(&plaintext)?;
            if aux.iteration != iteration || aux.client_id != share.client_id as u64 {
                return Err(OpaError::ContextMismatch);
            }
            for (dst, value) in summed_seed_share.iter_mut().zip(aux.seed_share.iter()) {
                *dst = mod_add(*dst, *value, params.q);
            }
            digest_shares.insert(share.client_id, aux.digest_share);
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
        if uploads.is_empty() {
            return Err(OpaError::InvalidParameter("upload set must be non-empty"));
        }
        let encoding_client_bound = uploads[0].encoding_client_bound;
        if uploads.iter().any(|upload| {
            upload.iteration != iteration
                || upload.encoding_client_bound != encoding_client_bound
                || upload.ciphertext.len() != params.vector_len
        }) {
            return Err(OpaError::ContextMismatch);
        }

        let active_clients: BTreeSet<usize> =
            uploads.iter().map(|upload| upload.client_id).collect();
        if active_clients.len() != uploads.len() {
            return Err(OpaError::ContextMismatch);
        }
        let selected_outputs = &committee_outputs[..params.threshold_r];

        let seed_points = selected_outputs
            .iter()
            .map(|output| (output.committee_member_id as u64, output.summed_seed_share.clone()))
            .collect::<Vec<_>>();
        let reconstructed_seed_sum = packed_reconstruct_secret(
            &seed_points,
            params.seed_dim,
            params.packed_secret_dim,
            params.threshold_r,
            params.q,
        )?;
        let aux_mask = self.shprg.expand(&reconstructed_seed_sum)?;

        let interpolation = invert_vandermonde(
            &selected_outputs
                .iter()
                .map(|output| output.committee_member_id as u128)
                .collect::<Vec<_>>(),
            params.q,
        )?;
        let mut digest_masks_sum = vec![0_u128; params.vector_len];
        for client_id in &active_clients {
            let shares = selected_outputs
                .iter()
                .map(|output| {
                    output
                        .digest_shares
                        .get(client_id)
                        .copied()
                        .map(|share| (output.committee_member_id as u64, share))
                        .ok_or(OpaError::NotEnoughShares)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let digest = reconstruct_scalar_with_inverse(&shares, &interpolation, params.q)?;
            let mask = hash_mask_vector(digest, params.vector_len, params.p);
            digest_masks_sum = add_vectors_mod_p(&digest_masks_sum, &mask, params.p);
        }

        let summed_ciphertexts = uploads.iter().fold(vec![0_u128; params.vector_len], |acc, upload| {
            add_vectors_mod_p(&acc, &upload.ciphertext, params.p)
        });
        let unmasked_once = sub_vectors_mod_p(&summed_ciphertexts, &aux_mask, params.p);
        let unmasked = sub_vectors_mod_p(&unmasked_once, &digest_masks_sum, params.p);

        Ok(decode(
            &unmasked,
            params.vector_len,
            params.encoding_delta(encoding_client_bound)?,
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
    let ephemeral_public = (ephemeral_secret * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    let shared = (ephemeral_secret * public_key).compress().to_bytes();
    let keystream = derive_keystream(&shared, aad, plaintext.len());
    let body = plaintext
        .iter()
        .zip(keystream.iter())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .collect();
    CommitteeCiphertext {
        ephemeral_public,
        body,
    }
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

fn hash_mask_vector(digest: u128, len: usize, p: u128) -> Vec<u128> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u64;
    while out.len() < len {
        let mut hash = Sha3_256::new();
        hash.update(b"opa-digest-mask");
        hash.update(digest.to_le_bytes());
        hash.update(counter.to_le_bytes());
        let block = hash.finalize();
        for chunk in block.chunks_exact(16) {
            let mut arr = [0_u8; 16];
            arr.copy_from_slice(chunk);
            out.push(u128::from_le_bytes(arr) % p);
            if out.len() == len {
                break;
            }
        }
        counter += 1;
    }
    out
}

fn encode(
    values: &[u64],
    delta: u128,
    p: u128,
    stat_sec_bits: u32,
    rng: &mut StdRng,
) -> Vec<u128> {
    let random_mask = if stat_sec_bits >= 128 {
        u128::MAX
    } else {
        (1_u128 << stat_sec_bits) - 1
    };
    values
        .iter()
        .map(|&value| {
            let randomizer = (rng.gen::<u64>() as u128) & random_mask;
            (((value as u128) * delta) + randomizer + 1) % p
        })
        .collect()
}

fn decode(values: &[u128], output_len: usize, delta: u128) -> Vec<u64> {
    values
        .iter()
        .take(output_len)
        .map(|&value| value.div_ceil(delta).saturating_sub(1) as u64)
        .collect()
}

fn shamir_share_scalar(
    secret: u128,
    threshold_t: usize,
    committee_size: usize,
    q: u128,
    rng: &mut StdRng,
) -> Result<Vec<(u64, u128)>, OpaError> {
    if threshold_t >= committee_size {
        return Err(OpaError::InvalidParameter(
            "threshold_t must be smaller than committee_size",
        ));
    }
    let mut coeffs = Vec::with_capacity(threshold_t + 1);
    coeffs.push(secret % q);
    for _ in 0..threshold_t {
        coeffs.push(random_mod_q(q, rng));
    }
    let mut shares = Vec::with_capacity(committee_size);
    for x in 1..=committee_size {
        let mut y = 0_u128;
        let mut x_power = 1_u128;
        for &coeff in &coeffs {
            y = mod_add(y, mod_mul(coeff, x_power, q), q);
            x_power = mod_mul(x_power, x as u128, q);
        }
        shares.push((x as u64, y));
    }
    Ok(shares)
}

fn packed_share_secret(
    secret: &[u128],
    packed_secret_dim: usize,
    threshold_r: usize,
    committee_size: usize,
    q: u128,
    rng: &mut StdRng,
) -> Result<Vec<(u64, Vec<u128>)>, OpaError> {
    if packed_secret_dim == 0 || packed_secret_dim >= threshold_r {
        return Err(OpaError::InvalidParameter(
            "packed_secret_dim must be in 1..threshold_r",
        ));
    }
    let block_count = secret.len().div_ceil(packed_secret_dim);
    let mut shares = (1..=committee_size)
        .map(|x| (x as u64, Vec::with_capacity(block_count.max(1))))
        .collect::<Vec<_>>();
    for block in secret.chunks(packed_secret_dim) {
        let mut coeffs = vec![0_u128; threshold_r];
        coeffs[..block.len()].copy_from_slice(block);
        for coeff in coeffs.iter_mut().skip(packed_secret_dim) {
            *coeff = random_mod_q(q, rng);
        }
        for (committee_id, values) in shares.iter_mut() {
            let mut y = 0_u128;
            let mut x_power = 1_u128;
            for &coeff in &coeffs {
                y = mod_add(y, mod_mul(coeff, x_power, q), q);
                x_power = mod_mul(x_power, *committee_id as u128, q);
            }
            values.push(y);
        }
    }
    Ok(shares)
}

fn packed_reconstruct_secret(
    shares: &[(u64, Vec<u128>)],
    total_len: usize,
    packed_secret_dim: usize,
    threshold_r: usize,
    q: u128,
) -> Result<Vec<u128>, OpaError> {
    if shares.len() < threshold_r {
        return Err(OpaError::NotEnoughShares);
    }
    let block_count = total_len.div_ceil(packed_secret_dim);
    let used = &shares[..threshold_r];
    if used.iter().any(|(_, values)| values.len() != block_count) {
        return Err(OpaError::InvalidParameter("packed share block count mismatch"));
    }
    let interpolation = invert_vandermonde(
        &used.iter().map(|(x, _)| *x as u128).collect::<Vec<_>>(),
        q,
    )?;
    let mut secret = Vec::with_capacity(block_count * packed_secret_dim);
    for block_idx in 0..block_count {
        let evaluations = used.iter().map(|(_, values)| values[block_idx]).collect::<Vec<_>>();
        for row in interpolation.iter().take(packed_secret_dim) {
            secret.push(dot_product_mod(row, &evaluations, q));
        }
    }
    secret.truncate(total_len);
    Ok(secret)
}

fn reconstruct_scalar_with_inverse(
    shares: &[(u64, u128)],
    interpolation: &[Vec<u128>],
    q: u128,
) -> Result<u128, OpaError> {
    if shares.len() < interpolation.len() || interpolation.is_empty() {
        return Err(OpaError::NotEnoughShares);
    }
    let evaluations = shares
        .iter()
        .take(interpolation.len())
        .map(|(_, value)| *value)
        .collect::<Vec<_>>();
    Ok(dot_product_mod(&interpolation[0], &evaluations, q))
}

fn invert_vandermonde(
    x_coordinates: &[u128],
    modulus: u128,
) -> Result<Vec<Vec<u128>>, OpaError> {
    if x_coordinates.is_empty() {
        return Err(OpaError::NotEnoughShares);
    }
    let n = x_coordinates.len();
    let mut matrix = vec![vec![0_u128; 2 * n]; n];
    for (row, &x) in x_coordinates.iter().enumerate() {
        let mut power = 1_u128;
        for col in 0..n {
            matrix[row][col] = power;
            power = mod_mul(power, x, modulus);
        }
        matrix[row][n + row] = 1;
    }
    for col in 0..n {
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or(OpaError::InvalidParameter("singular interpolation matrix"))?;
        matrix.swap(col, pivot);
        let inv = mod_inv(matrix[col][col], modulus);
        for j in 0..2 * n {
            matrix[col][j] = mod_mul(matrix[col][j], inv, modulus);
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for j in 0..2 * n {
                let sub = mod_mul(factor, matrix[col][j], modulus);
                matrix[row][j] = mod_sub(matrix[row][j], sub, modulus);
            }
        }
    }
    let mut inverse = vec![vec![0_u128; n]; n];
    for row in 0..n {
        inverse[row].copy_from_slice(&matrix[row][n..]);
    }
    Ok(inverse)
}

fn dot_product_mod(weights: &[u128], values: &[u128], modulus: u128) -> u128 {
    weights
        .iter()
        .zip(values.iter())
        .fold(0_u128, |acc, (&weight, &value)| {
            mod_add(acc, mod_mul(weight, value, modulus), modulus)
        })
}

fn add_vectors_mod_p(lhs: &[u128], rhs: &[u128], p: u128) -> Vec<u128> {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(&a, &b)| mod_add(a, b, p))
        .collect()
}

fn sub_vectors_mod_p(lhs: &[u128], rhs: &[u128], p: u128) -> Vec<u128> {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(&a, &b)| mod_sub(a, b, p))
        .collect()
}

fn mod_add(a: u128, b: u128, modulus: u128) -> u128 {
    #[cfg(opa_fixed_q_optimized)]
    if modulus == PAPER_Q {
        return mod_add_paper_q(a, b);
    }
    u128_from_u256(
        (Wrapping(u256_from_u128(a)) + Wrapping(u256_from_u128(b))).0
            % u256_from_u128(modulus),
    )
}

fn mod_sub(a: u128, b: u128, modulus: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        modulus - (b - a)
    }
}

fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
    #[cfg(opa_fixed_q_optimized)]
    if modulus == PAPER_Q {
        return mod_mul_paper_q(a, b);
    }
    let product = (Wrapping(u256_from_u128(a)) * Wrapping(u256_from_u128(b))).0;
    u128_from_u256(product % u256_from_u128(modulus))
}

fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut result = 1_u128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exp >>= 1;
    }
    result
}

fn mod_inv(value: u128, modulus: u128) -> u128 {
    mod_pow(value, modulus - 2, modulus)
}

fn random_mod_q(q: u128, rng: &mut StdRng) -> u128 {
    rng.gen::<u128>() % q
}

fn random_scalar(rng: &mut StdRng) -> Scalar {
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn lwr_round(value: u128, p: u128, q: u128) -> u128 {
    let numerator = (Wrapping(u256_from_u128(value)) * Wrapping(u256_from_u128(p))).0;
    u128_from_u256(numerator / u256_from_u128(q)) % p
}

#[cfg(opa_fixed_q_optimized)]
fn mod_add_paper_q(a: u128, b: u128) -> u128 {
    let (sum, carry) = a.overflowing_add(b);
    let mut reduced = if carry {
        add_small_mod_paper_q(sum, PAPER_Q_COMPLEMENT)
    } else {
        sum
    };
    if reduced >= PAPER_Q {
        reduced -= PAPER_Q;
    }
    reduced
}

#[cfg(opa_fixed_q_optimized)]
fn add_small_mod_paper_q(value: u128, small: u128) -> u128 {
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

#[cfg(opa_fixed_q_optimized)]
fn mod_mul_paper_q(a: u128, b: u128) -> u128 {
    let limbs = mul_u128_to_u64_limbs(a, b);
    let lo = (limbs[0] as u128) | ((limbs[1] as u128) << 64);
    let hi = (limbs[2] as u128) | ((limbs[3] as u128) << 64);
    fold_paper_q_high_half(lo, hi)
}

#[cfg(opa_fixed_q_optimized)]
fn fold_paper_q_high_half(lo: u128, hi: u128) -> u128 {
    let h0 = hi as u64 as u128;
    let h1 = hi >> 64;

    let p0 = h0 * PAPER_Q_COMPLEMENT;
    let p1 = h1 * PAPER_Q_COMPLEMENT;

    let mid_low = (p0 >> 64) + (p1 & u64::MAX as u128);
    let folded_low = (p0 & u64::MAX as u128) | ((mid_low & u64::MAX as u128) << 64);
    let folded_high = (p1 >> 64) + (mid_low >> 64);

    let (sum, carry) = lo.overflowing_add(folded_low);
    let high = folded_high + u128::from(carry);
    add_small_mod_paper_q(sum, high * PAPER_Q_COMPLEMENT)
}

#[cfg(opa_fixed_q_optimized)]
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

fn u256_from_u128(value: u128) -> U256 {
    U256::from(value)
}

fn u128_from_u256(value: U256) -> u128 {
    let bytes = value.to_be_bytes();
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    u128::from_be_bytes(lower)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, OpaError> {
    let end = offset + 8;
    let slice = bytes.get(offset..end).ok_or(OpaError::InvalidAuxPayload)?;
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}

fn read_u128(bytes: &[u8], offset: usize) -> Result<u128, OpaError> {
    let end = offset + 16;
    let slice = bytes.get(offset..end).ok_or(OpaError::InvalidAuxPayload)?;
    let mut buf = [0_u8; 16];
    buf.copy_from_slice(slice);
    Ok(u128::from_le_bytes(buf))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::SeedableRng;

    fn test_params() -> OpaParameters {
        OpaParameters {
            vector_len: 10,
            seed_dim: 8,
            packed_secret_dim: 2,
            committee_size: 5,
            threshold_r: 3,
            q: 18_446_744_073_709_551_557,
            p: 65_537,
            stat_sec_bits: 8,
        }
    }

    #[test]
    fn packed_seed_round_trip() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(7);
        let secret = vec![7_u128, 11, 13, 17, 19, 23, 29, 31];
        let shares = packed_share_secret(
            &secret,
            params.packed_secret_dim,
            params.threshold_r,
            params.committee_size,
            params.q,
            &mut rng,
        )
        .unwrap();
        let recovered = packed_reconstruct_secret(
            &shares[..params.threshold_r],
            params.seed_dim,
            params.packed_secret_dim,
            params.threshold_r,
            params.q,
        )
        .unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn paper_params_helper_matches_current_choice() {
        let params = paper_benchmark_params(10_000);
        assert_eq!(params.seed_dim, PAPER_SEED_DIM);
        assert_eq!(params.committee_size, PAPER_COMMITTEE_SIZE);
        assert_eq!(params.threshold_r, PAPER_THRESHOLD_R);
        assert_eq!(params.packed_secret_dim, PAPER_PACKED_SECRET_DIM);
        assert_eq!(packed_share_count_for_committee(&params), 128);
        assert_eq!(params.p, PAPER_P);
        assert_eq!(params.q, PAPER_Q);
        assert_eq!(params.stat_sec_bits, PAPER_STAT_SEC_BITS);
        assert_eq!(params.max_safe_aggregate_coordinate(1_000).unwrap(), 7);
    }

    #[test]
    fn opalwr_end_to_end_with_client_and_committee_dropouts() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(42);
        let shprg = LwrShprg::new(params.clone(), &mut rng).unwrap();
        let server = OpaServer::new(shprg.clone());

        let committees = (1..=params.committee_size)
            .map(|id| OpaCommitteeMember::new(id, &mut rng))
            .collect::<Vec<_>>();
        let committee_public_keys = committees
            .iter()
            .map(|member| member.key_pair.public())
            .collect::<Vec<_>>();

        let raw_inputs = [
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            vec![2, 4, 6, 8, 10, 12, 14, 16, 18, 20],
            vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        ];
        let dropped_client = 3_usize;
        let active_uploads = raw_inputs
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != dropped_client)
            .map(|(index, values)| {
                OpaClient { client_id: index + 1 }
                    .encrypt(
                        9,
                        values,
                        &shprg,
                        &committee_public_keys,
                        raw_inputs.len(),
                        &mut rng,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let active_clients = active_uploads
            .iter()
            .map(|upload| upload.client_id)
            .collect::<BTreeSet<_>>();
        let available_committees = [&committees[0], &committees[2], &committees[4]];
        let committee_outputs = available_committees
            .iter()
            .map(|member| {
                member
                    .process(9, &active_clients, &active_uploads, &params)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let aggregate = server.aggregate(9, &active_uploads, &committee_outputs).unwrap();
        let expected = vec![13, 15, 17, 19, 21, 23, 25, 27, 29, 31];
        assert_eq!(expected, aggregate);
        assert_eq!(active_uploads[0].ciphertext.len(), params.vector_len);
    }

    #[test]
    fn committee_rejects_wrong_context() {
        let params = test_params();
        let mut rng = StdRng::seed_from_u64(99);
        let shprg = LwrShprg::new(params.clone(), &mut rng).unwrap();
        let committee = OpaCommitteeMember::new(1, &mut rng);
        let client = OpaClient { client_id: 1 };
        let upload = client
            .encrypt(
                5,
                &[3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                &shprg,
                &[committee.key_pair.public()],
                1,
                &mut rng,
            )
            .unwrap_err();
        assert!(matches!(upload, OpaError::InvalidParameter(_)));
    }
}
