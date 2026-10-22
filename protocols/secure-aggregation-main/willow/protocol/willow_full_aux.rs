use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use std::collections::BTreeMap;

pub const WILLOW_SEED_BYTES: usize = 32;
pub const WILLOW_AUX_CIPHERTEXT_BYTES: usize = 80;

#[derive(Clone, Debug)]
pub struct WillowAuxPublicParameters {
    pub committee_size: usize,
    pub threshold: usize,
    contributor_public_keys: Vec<RistrettoPoint>,
    aggregate_public_key: RistrettoPoint,
}

impl WillowAuxPublicParameters {
    pub fn aggregate_public_key(&self) -> RistrettoPoint {
        self.aggregate_public_key.clone()
    }
}

#[derive(Clone, Debug)]
pub struct WillowAuxRecoveryShare {
    pub committee_member_id: usize,
    pub shares_by_contributor: Vec<[u8; 32]>,
}

impl WillowAuxRecoveryShare {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.shares_by_contributor.len() * 32);
        out.extend_from_slice(&(self.committee_member_id as u64).to_le_bytes());
        out.extend_from_slice(&(self.shares_by_contributor.len() as u64).to_le_bytes());
        for share in &self.shares_by_contributor {
            out.extend_from_slice(share);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, status::StatusError> {
        if bytes.len() < 16 {
            return Err(status::invalid_argument("auxiliary recovery share is too short"));
        }
        let committee_member_id = read_u64(bytes, 0)? as usize;
        let share_count = read_u64(bytes, 8)? as usize;
        let expected = share_count
            .checked_mul(32)
            .and_then(|length| length.checked_add(16))
            .ok_or_else(|| status::invalid_argument("auxiliary recovery share length overflow"))?;
        if bytes.len() != expected {
            return Err(status::invalid_argument("auxiliary recovery share length mismatch"));
        }
        let mut shares_by_contributor = Vec::with_capacity(share_count);
        for chunk in bytes[16..].chunks_exact(32) {
            let mut share = [0_u8; 32];
            share.copy_from_slice(chunk);
            shares_by_contributor.push(share);
        }
        Ok(Self { committee_member_id, shares_by_contributor })
    }
}

#[derive(Clone, Debug)]
pub struct WillowAuxSetup {
    pub public_parameters: WillowAuxPublicParameters,
    pub committee_recovery_shares: Vec<WillowAuxRecoveryShare>,
}

pub fn setup_aux_threshold_keys<R: RngCore>(
    committee_size: usize,
    threshold: usize,
    rng: &mut R,
) -> Result<WillowAuxSetup, status::StatusError> {
    if committee_size == 0 || threshold == 0 || threshold > committee_size {
        return Err(status::invalid_argument("invalid auxiliary committee threshold"));
    }
    let mut shares_by_member = vec![Vec::with_capacity(committee_size); committee_size];
    let mut contributor_public_keys = Vec::with_capacity(committee_size);
    for _ in 0..committee_size {
        let coefficients = (0..threshold).map(|_| random_scalar(rng)).collect::<Vec<_>>();
        contributor_public_keys.push(coefficients[0] * RISTRETTO_BASEPOINT_POINT);
        for member_id in 1..=committee_size {
            let x = Scalar::from(member_id as u64);
            let share = coefficients
                .iter()
                .rev()
                .fold(Scalar::ZERO, |value, coefficient| value * x + *coefficient);
            shares_by_member[member_id - 1].push(share.to_bytes());
        }
    }
    let aggregate_public_key = contributor_public_keys
        .iter()
        .fold(RistrettoPoint::identity(), |sum, point| sum + point);
    let committee_recovery_shares = shares_by_member
        .into_iter()
        .enumerate()
        .map(|(index, shares_by_contributor)| WillowAuxRecoveryShare {
            committee_member_id: index + 1,
            shares_by_contributor,
        })
        .collect();
    Ok(WillowAuxSetup {
        public_parameters: WillowAuxPublicParameters {
            committee_size,
            threshold,
            contributor_public_keys,
            aggregate_public_key,
        },
        committee_recovery_shares,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WillowSeedCiphertext {
    pub ephemeral_public: [u8; 32],
    pub body: [u8; WILLOW_SEED_BYTES],
    pub tag: [u8; 16],
}

impl WillowSeedCiphertext {
    pub fn to_bytes(&self) -> [u8; WILLOW_AUX_CIPHERTEXT_BYTES] {
        let mut out = [0_u8; WILLOW_AUX_CIPHERTEXT_BYTES];
        out[..32].copy_from_slice(&self.ephemeral_public);
        out[32..64].copy_from_slice(&self.body);
        out[64..].copy_from_slice(&self.tag);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, status::StatusError> {
        if bytes.len() != WILLOW_AUX_CIPHERTEXT_BYTES {
            return Err(status::invalid_argument("Willow seed ciphertext length mismatch"));
        }
        let mut ephemeral_public = [0_u8; 32];
        let mut body = [0_u8; WILLOW_SEED_BYTES];
        let mut tag = [0_u8; 16];
        ephemeral_public.copy_from_slice(&bytes[..32]);
        body.copy_from_slice(&bytes[32..64]);
        tag.copy_from_slice(&bytes[64..]);
        Ok(Self { ephemeral_public, body, tag })
    }
}

pub fn encrypt_seed(
    public_key: RistrettoPoint,
    seed: &[u8; WILLOW_SEED_BYTES],
    aad: &[u8],
    ephemeral_randomness: &[u8; 64],
) -> WillowSeedCiphertext {
    let ephemeral_secret = Scalar::from_bytes_mod_order_wide(ephemeral_randomness);
    let ephemeral_public = (ephemeral_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let shared_secret = (ephemeral_secret * public_key).compress().to_bytes();
    let pad = derive_seed_pad(&shared_secret, aad);
    let mut body = [0_u8; WILLOW_SEED_BYTES];
    for index in 0..WILLOW_SEED_BYTES {
        body[index] = seed[index] ^ pad[index];
    }
    let tag = derive_seed_tag(&shared_secret, aad, &body);
    WillowSeedCiphertext { ephemeral_public, body, tag }
}

pub struct RecoveredWillowAuxSecretKey(Scalar);

impl RecoveredWillowAuxSecretKey {
    pub fn decrypt_seed(
        &self,
        ciphertext: &WillowSeedCiphertext,
        aad: &[u8],
    ) -> Result<[u8; WILLOW_SEED_BYTES], status::StatusError> {
        let ephemeral_public = CompressedRistretto(ciphertext.ephemeral_public)
            .decompress()
            .ok_or_else(|| status::invalid_argument("invalid Willow seed ciphertext point"))?;
        let shared_secret = (self.0 * ephemeral_public).compress().to_bytes();
        let expected_tag = derive_seed_tag(&shared_secret, aad, &ciphertext.body);
        let difference = expected_tag
            .iter()
            .zip(ciphertext.tag.iter())
            .fold(0_u8, |difference, (left, right)| difference | (left ^ right));
        if difference != 0 {
            return Err(status::invalid_argument("Willow seed ciphertext authentication failed"));
        }
        let pad = derive_seed_pad(&shared_secret, aad);
        let mut seed = [0_u8; WILLOW_SEED_BYTES];
        for index in 0..WILLOW_SEED_BYTES {
            seed[index] = ciphertext.body[index] ^ pad[index];
        }
        Ok(seed)
    }
}

pub fn recover_aux_secret_key(
    public_parameters: &WillowAuxPublicParameters,
    recovery_shares: &[WillowAuxRecoveryShare],
) -> Result<RecoveredWillowAuxSecretKey, status::StatusError> {
    let mut unique = BTreeMap::new();
    for message in recovery_shares {
        if message.committee_member_id == 0
            || message.committee_member_id > public_parameters.committee_size
        {
            return Err(status::invalid_argument("invalid auxiliary committee member id"));
        }
        if message.shares_by_contributor.len() != public_parameters.committee_size {
            return Err(status::invalid_argument("auxiliary contributor share count mismatch"));
        }
        if unique.insert(message.committee_member_id, message).is_some() {
            return Err(status::invalid_argument("duplicate auxiliary committee member"));
        }
    }
    if unique.len() < public_parameters.threshold {
        return Err(status::invalid_argument("not enough auxiliary recovery shares"));
    }
    let selected = unique
        .into_iter()
        .take(public_parameters.threshold)
        .collect::<Vec<_>>();
    let x_coordinates = selected
        .iter()
        .map(|(member_id, _)| Scalar::from(*member_id as u64))
        .collect::<Vec<_>>();
    let lagrange_coefficients = x_coordinates
        .iter()
        .enumerate()
        .map(|(index, x)| {
            x_coordinates.iter().enumerate().filter(|(other, _)| *other != index).fold(
                Scalar::ONE,
                |coefficient, (_, other_x)| {
                    coefficient * (-*other_x) * (*x - *other_x).invert()
                },
            )
        })
        .collect::<Vec<_>>();

    let mut aggregate_secret_key = Scalar::ZERO;
    for contributor in 0..public_parameters.committee_size {
        let mut contributor_secret_key = Scalar::ZERO;
        for ((_, message), coefficient) in selected.iter().zip(&lagrange_coefficients) {
            let share = Option::<Scalar>::from(Scalar::from_canonical_bytes(
                message.shares_by_contributor[contributor],
            ))
            .ok_or_else(|| status::invalid_argument("non-canonical auxiliary scalar share"))?;
            contributor_secret_key += *coefficient * share;
        }
        if contributor_secret_key * RISTRETTO_BASEPOINT_POINT
            != public_parameters.contributor_public_keys[contributor]
        {
            return Err(status::invalid_argument("auxiliary key share does not match public key"));
        }
        aggregate_secret_key += contributor_secret_key;
    }
    if aggregate_secret_key * RISTRETTO_BASEPOINT_POINT
        != public_parameters.aggregate_public_key
    {
        return Err(status::invalid_argument("recovered auxiliary key does not match public key"));
    }
    Ok(RecoveredWillowAuxSecretKey(aggregate_secret_key))
}

pub fn willow_seed_aad(iteration: u64, client_id: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(56);
    aad.extend_from_slice(b"willow_paper_aux_seed_ciphertext_v1");
    aad.extend_from_slice(&iteration.to_le_bytes());
    aad.extend_from_slice(&(client_id as u64).to_le_bytes());
    aad
}

pub fn expand_seed_ring_mask(
    seed: &[u8; WILLOW_SEED_BYTES],
    coefficient_count: usize,
    modulus_bits: usize,
    iteration: u64,
) -> Vec<u64> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, b"willow_paper_prg_expand_ring_v1");
    Update::update(&mut xof, &iteration.to_le_bytes());
    Update::update(&mut xof, &(coefficient_count as u64).to_le_bytes());
    Update::update(&mut xof, &(modulus_bits as u64).to_le_bytes());
    Update::update(&mut xof, seed);
    let mut reader = xof.finalize_xof();
    let mut out = Vec::with_capacity(coefficient_count * 4);
    for _ in 0..coefficient_count {
        let mut coefficient = [0_u8; 32];
        reader.read(&mut coefficient);
        for chunk in coefficient.chunks_exact(8) {
            let mut limb = [0_u8; 8];
            limb.copy_from_slice(chunk);
            out.push(u64::from_le_bytes(limb));
        }
        let coefficient_start = out.len() - 4;
        truncate_ring_coefficient(&mut out[coefficient_start..], modulus_bits);
    }
    out
}

pub fn add_ring_masks_in_place(destination: &mut [u64], source: &[u64], modulus_bits: usize) {
    assert_eq!(destination.len(), source.len());
    for (destination_coefficient, source_coefficient) in
        destination.chunks_exact_mut(4).zip(source.chunks_exact(4))
    {
        let mut carry = false;
        for limb in 0..4 {
            let (sum_without_carry, first_carry) =
                destination_coefficient[limb].overflowing_add(source_coefficient[limb]);
            let (sum, second_carry) = sum_without_carry.overflowing_add(u64::from(carry));
            destination_coefficient[limb] = sum;
            carry = first_carry || second_carry;
        }
        truncate_ring_coefficient(destination_coefficient, modulus_bits);
    }
}

fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn derive_seed_pad(shared_secret: &[u8; 32], aad: &[u8]) -> [u8; WILLOW_SEED_BYTES] {
    let mut xof = Shake256::default();
    Update::update(&mut xof, b"willow_paper_aux_seed_pad_v1");
    Update::update(&mut xof, shared_secret);
    Update::update(&mut xof, aad);
    let mut reader = xof.finalize_xof();
    let mut pad = [0_u8; WILLOW_SEED_BYTES];
    reader.read(&mut pad);
    pad
}

fn derive_seed_tag(shared_secret: &[u8; 32], aad: &[u8], body: &[u8]) -> [u8; 16] {
    let mut hash = Sha3_256::new();
    Digest::update(&mut hash, b"willow_paper_aux_seed_tag_v1");
    Digest::update(&mut hash, shared_secret);
    Digest::update(&mut hash, aad);
    Digest::update(&mut hash, body);
    let digest = hash.finalize();
    let mut tag = [0_u8; 16];
    tag.copy_from_slice(&digest[..16]);
    tag
}

fn truncate_ring_coefficient(limbs: &mut [u64], modulus_bits: usize) {
    assert_eq!(limbs.len(), 4);
    assert!((1..=256).contains(&modulus_bits));
    let full_limbs = modulus_bits / 64;
    let remaining_bits = modulus_bits % 64;
    let first_zero_limb = full_limbs + usize::from(remaining_bits > 0);
    for limb in limbs.iter_mut().skip(first_zero_limb) {
        *limb = 0;
    }
    if remaining_bits > 0 {
        limbs[full_limbs] &= (1_u64 << remaining_bits) - 1;
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, status::StatusError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| status::invalid_argument("u64 offset overflow"))?;
    if end > bytes.len() {
        return Err(status::invalid_argument("truncated u64 field"));
    }
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..end]);
    Ok(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn threshold_aux_key_recovers_and_decrypts_seed() {
        let mut rng = StdRng::seed_from_u64(0x5749_4c4c_4f57_4155);
        let setup = setup_aux_threshold_keys(7, 5, &mut rng).unwrap();
        let seed = [42_u8; WILLOW_SEED_BYTES];
        let aad = willow_seed_aad(3, 9);
        let mut ephemeral_randomness = [0_u8; 64];
        rng.fill_bytes(&mut ephemeral_randomness);
        let ciphertext = encrypt_seed(
            setup.public_parameters.aggregate_public_key(),
            &seed,
            &aad,
            &ephemeral_randomness,
        );
        let selected = [0, 2, 3, 5, 6]
            .into_iter()
            .map(|index| setup.committee_recovery_shares[index].clone())
            .collect::<Vec<_>>();
        let recovered = recover_aux_secret_key(&setup.public_parameters, &selected).unwrap();
        assert_eq!(recovered.decrypt_seed(&ciphertext, &aad).unwrap(), seed);

        let wire = ciphertext.to_bytes();
        assert_eq!(WillowSeedCiphertext::from_bytes(&wire).unwrap(), ciphertext);
        let share_wire = selected[0].to_bytes();
        let share_roundtrip = WillowAuxRecoveryShare::from_bytes(&share_wire).unwrap();
        assert_eq!(share_roundtrip.committee_member_id, selected[0].committee_member_id);
        assert_eq!(share_roundtrip.shares_by_contributor, selected[0].shares_by_contributor);
    }

    #[test]
    fn auxiliary_recovery_and_ciphertext_reject_tampering() {
        let mut rng = StdRng::seed_from_u64(0x5749_4c4c_4f57_5441);
        let setup = setup_aux_threshold_keys(6, 4, &mut rng).unwrap();
        assert!(recover_aux_secret_key(
            &setup.public_parameters,
            &setup.committee_recovery_shares[..3],
        )
        .is_err());

        let mut selected = setup.committee_recovery_shares[..4].to_vec();
        selected[0].shares_by_contributor[0][0] ^= 1;
        assert!(recover_aux_secret_key(&setup.public_parameters, &selected).is_err());

        let recovered = recover_aux_secret_key(
            &setup.public_parameters,
            &setup.committee_recovery_shares[..4],
        )
        .unwrap();
        let seed = [7_u8; WILLOW_SEED_BYTES];
        let aad = willow_seed_aad(1, 2);
        let mut randomness = [0_u8; 64];
        rng.fill_bytes(&mut randomness);
        let mut ciphertext = encrypt_seed(
            setup.public_parameters.aggregate_public_key(),
            &seed,
            &aad,
            &randomness,
        );
        ciphertext.body[0] ^= 1;
        assert!(recovered.decrypt_seed(&ciphertext, &aad).is_err());
    }

    #[test]
    fn seed_ring_masks_are_deterministic_and_additive() {
        let left = expand_seed_ring_mask(&[1_u8; 32], 17, 168, 4);
        let right = expand_seed_ring_mask(&[2_u8; 32], 17, 168, 4);
        assert_eq!(left, expand_seed_ring_mask(&[1_u8; 32], 17, 168, 4));
        assert_ne!(left, right);
        let mut sum = left.clone();
        add_ring_masks_in_place(&mut sum, &right, 168);
        for coefficient in sum.chunks_exact(4) {
            assert_eq!(coefficient[3] >> 40, 0);
        }
    }
}
