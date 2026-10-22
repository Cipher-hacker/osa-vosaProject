use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use kahe_traits::{KaheBase, KaheKeygen, TrySecretKeyFrom, TrySecretKeyInto};
use prng_traits::SecurePrng;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use shell_kahe::{Ciphertext as ShellKaheCiphertext, ShellKahe};
use single_thread_hkdf::{compute_hkdf, seed_length, Seed, SingleThreadHkdfPrng};
use status;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::time::Instant;

const Q_RSS: u64 = 2_305_843_009_213_693_951;
const Q_RSS_BITS: u32 = 61;
const Q_RSS_COMPACT: u64 = 2_147_483_647;
const Q_RSS_COMPACT_BITS: u32 = 31;
const CHACHA20_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub fn rss_packed_byte_len(element_count: usize) -> Result<usize, status::StatusError> {
    rss_packed_byte_len_for_mode(element_count, OsaRssFieldMode::Paper61)
}

pub fn rss_packed_byte_len_for_mode(
    element_count: usize,
    field_mode: OsaRssFieldMode,
) -> Result<usize, status::StatusError> {
    element_count
        .checked_mul(field_mode.bits() as usize)
        .and_then(|bit_len| bit_len.checked_add(7))
        .map(|bit_len| bit_len / 8)
        .ok_or_else(|| status::invalid_argument("RSS packed length overflow"))
}

pub fn pack_rss_field_elements(values: &[u64]) -> Result<Vec<u8>, status::StatusError> {
    pack_rss_field_elements_for_mode(values, OsaRssFieldMode::Paper61)
}

pub fn pack_rss_field_elements_for_mode(
    values: &[u64],
    field_mode: OsaRssFieldMode,
) -> Result<Vec<u8>, status::StatusError> {
    pack_rss_field_element_iter(values.iter().copied(), values.len(), field_mode)
}

fn pack_rss_field_element_iter<I>(
    values: I,
    element_count: usize,
    field_mode: OsaRssFieldMode,
) -> Result<Vec<u8>, status::StatusError>
where
    I: IntoIterator<Item = u64>,
{
    let modulus = field_mode.modulus();
    let bits = field_mode.bits();
    let mut out = Vec::with_capacity(rss_packed_byte_len_for_mode(element_count, field_mode)?);
    let mut buffer = 0_u128;
    let mut buffered_bits = 0_u32;
    let mut actual_count = 0_usize;
    for value in values {
        if value >= modulus {
            return Err(status::invalid_argument("RSS field element is out of range"));
        }
        buffer |= (value as u128) << buffered_bits;
        buffered_bits += bits;
        while buffered_bits >= 8 {
            out.push(buffer as u8);
            buffer >>= 8;
            buffered_bits -= 8;
        }
        actual_count += 1;
    }
    if actual_count != element_count {
        return Err(status::invalid_argument("RSS element count mismatch"));
    }
    if buffered_bits > 0 {
        out.push(buffer as u8);
    }
    debug_assert_eq!(
        out.len(),
        rss_packed_byte_len_for_mode(element_count, field_mode).unwrap()
    );
    Ok(out)
}

pub fn unpack_rss_field_elements(
    bytes: &[u8],
    element_count: usize,
) -> Result<Vec<u64>, status::StatusError> {
    unpack_rss_field_elements_for_mode(bytes, element_count, OsaRssFieldMode::Paper61)
}

pub fn unpack_rss_field_elements_for_mode(
    bytes: &[u8],
    element_count: usize,
    field_mode: OsaRssFieldMode,
) -> Result<Vec<u64>, status::StatusError> {
    let modulus = field_mode.modulus();
    let bits = field_mode.bits();
    if bytes.len() != rss_packed_byte_len_for_mode(element_count, field_mode)? {
        return Err(status::invalid_argument("RSS packed length mismatch"));
    }
    let mut out = Vec::with_capacity(element_count);
    let mut buffer = 0_u128;
    let mut buffered_bits = 0_u32;
    let mut byte_index = 0_usize;
    for _ in 0..element_count {
        while buffered_bits < bits {
            buffer |= (bytes[byte_index] as u128) << buffered_bits;
            byte_index += 1;
            buffered_bits += 8;
        }
        let value_mask = (1_u128 << bits) - 1;
        let value = (buffer & value_mask) as u64;
        if value >= modulus {
            return Err(status::invalid_argument("non-canonical RSS field element"));
        }
        out.push(value);
        buffer >>= bits;
        buffered_bits -= bits;
    }
    if byte_index != bytes.len() || buffer != 0 {
        return Err(status::invalid_argument("non-zero RSS packing padding"));
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsaRssFieldMode {
    Paper61,
    Compact31,
}

impl OsaRssFieldMode {
    pub fn from_str(value: &str) -> Result<Self, status::StatusError> {
        match value {
            "paper61" => Ok(Self::Paper61),
            "compact31" => Ok(Self::Compact31),
            _ => Err(status::invalid_argument("unsupported OSA RSS field mode")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paper61 => "paper61",
            Self::Compact31 => "compact31",
        }
    }

    pub fn modulus(self) -> u64 {
        match self {
            Self::Paper61 => Q_RSS,
            Self::Compact31 => Q_RSS_COMPACT,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Self::Paper61 => Q_RSS_BITS,
            Self::Compact31 => Q_RSS_COMPACT_BITS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OsaShellKaheParameters {
    pub committee_size: usize,
    pub threshold_t: usize,
    pub rss_secret_dim: usize,
}

impl OsaShellKaheParameters {
    pub fn validate(&self) -> Result<(), status::StatusError> {
        if self.committee_size == 0 {
            return Err(status::invalid_argument("committee_size must be positive"));
        }
        if self.threshold_t == 0 || self.threshold_t > self.committee_size {
            return Err(status::invalid_argument("threshold_t must be in 1..=committee_size"));
        }
        if self.rss_secret_dim == 0 || self.rss_secret_dim >= self.threshold_t {
            return Err(status::invalid_argument("rss_secret_dim must be in 1..threshold_t"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsaShellKaheRngMode {
    DeterministicBenchmark,
    OsRngSecurity,
}

impl OsaShellKaheRngMode {
    pub fn from_str(value: &str) -> Result<Self, status::StatusError> {
        match value {
            "deterministic_benchmark" => Ok(Self::DeterministicBenchmark),
            "os_rng_security" => Ok(Self::OsRngSecurity),
            _ => Err(status::invalid_argument("unsupported OSA ShellKahe rng_mode")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsaDigestMaskMode {
    CounterSha3Reference,
    Shake256Xof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsaAuxEncryptionMode {
    AuthenticatedXChaCha20Poly1305,
    IndCpaShake256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsaDigestSharingMode {
    FullRingDigest,
    SeededPrgDigest,
}

impl OsaDigestSharingMode {
    pub fn from_str(value: &str) -> Result<Self, status::StatusError> {
        match value {
            "full_ring_digest" => Ok(Self::FullRingDigest),
            "seeded_prg_digest" => Ok(Self::SeededPrgDigest),
            _ => Err(status::invalid_argument("unsupported OSA digest sharing mode")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullRingDigest => "full_ring_digest",
            Self::SeededPrgDigest => "seeded_prg_digest",
        }
    }
}

impl OsaAuxEncryptionMode {
    pub fn from_str(value: &str) -> Result<Self, status::StatusError> {
        match value {
            "xchacha20_poly1305" => Ok(Self::AuthenticatedXChaCha20Poly1305),
            "ind_cpa_shake256" => Ok(Self::IndCpaShake256),
            _ => Err(status::invalid_argument("unsupported OSA auxiliary encryption mode")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedXChaCha20Poly1305 => "xchacha20_poly1305",
            Self::IndCpaShake256 => "ind_cpa_shake256",
        }
    }
}

impl OsaDigestMaskMode {
    pub fn from_str(value: &str) -> Result<Self, status::StatusError> {
        match value {
            "counter_sha3_reference" => Ok(Self::CounterSha3Reference),
            "shake256_xof" => Ok(Self::Shake256Xof),
            _ => Err(status::invalid_argument("unsupported OSA digest mask mode")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CounterSha3Reference => "counter_sha3_reference",
            Self::Shake256Xof => "shake256_xof",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommitteeKeyPair {
    secret: Scalar,
    public: RistrettoPoint,
}

impl CommitteeKeyPair {
    pub fn generate(rng: &mut StdRng) -> Self {
        let mut wide = [0_u8; 64];
        rng.fill_bytes(&mut wide);
        let secret = Scalar::from_bytes_mod_order_wide(&wide);
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
    pub tag: Vec<u8>,
}

#[derive(Clone, Debug)]
struct SharePayload {
    iteration: u64,
    client_id: u64,
    key_share: Vec<u64>,
    digest_share: Vec<u64>,
}

impl SharePayload {
    #[cfg(test)]
    fn encode(&self) -> Result<Vec<u8>, status::StatusError> {
        self.encode_with_field_mode(OsaRssFieldMode::Paper61)
    }

    fn encode_with_field_mode(
        &self,
        field_mode: OsaRssFieldMode,
    ) -> Result<Vec<u8>, status::StatusError> {
        let element_count = self
            .key_share
            .len()
            .checked_add(self.digest_share.len())
            .ok_or_else(|| status::invalid_argument("share payload element count overflow"))?;
        let packed = pack_rss_field_element_iter(
            self.key_share.iter().chain(self.digest_share.iter()).copied(),
            element_count,
            field_mode,
        )?;
        let mut out = Vec::with_capacity(32 + packed.len());
        out.extend_from_slice(&self.iteration.to_le_bytes());
        out.extend_from_slice(&self.client_id.to_le_bytes());
        out.extend_from_slice(&(self.key_share.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.digest_share.len() as u64).to_le_bytes());
        out.extend_from_slice(&packed);
        Ok(out)
    }

    #[cfg(test)]
    fn decode(bytes: &[u8]) -> Result<Self, status::StatusError> {
        Self::decode_with_field_mode(bytes, OsaRssFieldMode::Paper61)
    }

    fn decode_with_field_mode(
        bytes: &[u8],
        field_mode: OsaRssFieldMode,
    ) -> Result<Self, status::StatusError> {
        if bytes.len() < 32 {
            return Err(status::invalid_argument("payload too short"));
        }
        let iteration = read_u64(bytes, 0)?;
        let client_id = read_u64(bytes, 8)?;
        let key_len = read_u64(bytes, 16)? as usize;
        let digest_len = read_u64(bytes, 24)? as usize;
        let element_count = key_len
            .checked_add(digest_len)
            .ok_or_else(|| status::invalid_argument("share payload element count overflow"))?;
        let expected = 32_usize
            .checked_add(rss_packed_byte_len_for_mode(element_count, field_mode)?)
            .ok_or_else(|| status::invalid_argument("share payload length overflow"))?;
        if bytes.len() != expected {
            return Err(status::invalid_argument("payload length mismatch"));
        }
        let mut key_share =
            unpack_rss_field_elements_for_mode(&bytes[32..], element_count, field_mode)?;
        let digest_share = key_share.split_off(key_len);
        Ok(Self { iteration, client_id, key_share, digest_share })
    }
}

#[derive(Clone)]
pub struct OsaShellKaheClientUpload {
    pub client_id: usize,
    pub iteration: u64,
    pub ciphertext: ShellKaheCiphertext,
    pub encrypted_key_shares: Vec<CommitteeCiphertext>,
    pub serialized_key_len: usize,
    pub serialized_digest_len: usize,
}

#[derive(Clone, Debug)]
pub struct CommitteeAggregateShare {
    pub committee_member_id: usize,
    pub summed_key_share: Vec<u64>,
    pub digest_shares_by_client: Vec<(usize, Vec<u64>)>,
}

#[derive(Clone, Debug)]
pub struct RoutedCommitteeShare {
    pub client_id: usize,
    pub ciphertext: CommitteeCiphertext,
}

#[derive(Clone)]
pub struct RampSecretSharing {
    params: OsaShellKaheParameters,
    field_mode: OsaRssFieldMode,
    evaluation_powers: Vec<Vec<u64>>,
}

impl RampSecretSharing {
    pub fn new(params: OsaShellKaheParameters) -> Result<Self, status::StatusError> {
        Self::new_with_field_mode(params, OsaRssFieldMode::Paper61)
    }

    pub fn new_with_field_mode(
        params: OsaShellKaheParameters,
        field_mode: OsaRssFieldMode,
    ) -> Result<Self, status::StatusError> {
        params.validate()?;
        let modulus = field_mode.modulus();
        if params.committee_size as u64 >= modulus {
            return Err(status::invalid_argument("committee identifiers exceed RSS field"));
        }
        let evaluation_powers = (1..=params.committee_size)
            .map(|x| {
                let mut powers = Vec::with_capacity(params.threshold_t);
                let mut power = 1_u64;
                for _ in 0..params.threshold_t {
                    powers.push(power);
                    power = mod_mul(power, x as u64, modulus);
                }
                powers
            })
            .collect();
        Ok(Self { params, field_mode, evaluation_powers })
    }

    pub fn field_mode(&self) -> OsaRssFieldMode {
        self.field_mode
    }

    pub fn share_block(&self, secret: &[i64], rng: &mut StdRng) -> Result<Vec<(u64, u64)>, status::StatusError> {
        if secret.len() != self.params.rss_secret_dim {
            return Err(status::invalid_argument("secret block length mismatch"));
        }
        let modulus = self.field_mode.modulus();
        let mut coeffs = secret
            .iter()
            .map(|&v| signed_to_field(v, modulus))
            .collect::<Result<Vec<_>, status::StatusError>>()?;
        while coeffs.len() < self.params.threshold_t {
            coeffs.push(random_mod_q(rng, modulus));
        }
        let mut shares = Vec::with_capacity(self.params.committee_size);
        for (committee_index, powers) in self.evaluation_powers.iter().enumerate() {
            let y = coeffs
                .iter()
                .zip(powers.iter())
                .fold(0_u64, |acc, (&coefficient, &power)| {
                    mod_add(acc, mod_mul(coefficient, power, modulus), modulus)
                });
            shares.push(((committee_index + 1) as u64, y));
        }
        Ok(shares)
    }

    pub fn share_batched_secret(
        &self,
        secret: &[i64],
        rng: &mut StdRng,
    ) -> Result<Vec<(u64, Vec<u64>)>, status::StatusError> {
        let block_count = secret.len().div_ceil(self.params.rss_secret_dim);
        let mut aggregated = (1..=self.params.committee_size)
            .map(|committee_id| (committee_id as u64, Vec::with_capacity(block_count.max(1))))
            .collect::<Vec<_>>();
        for block in secret.chunks(self.params.rss_secret_dim) {
            let mut padded = vec![0_i64; self.params.rss_secret_dim];
            padded[..block.len()].copy_from_slice(block);
            let shares = self.share_block(&padded, rng)?;
            for ((expected_id, acc), (share_id, value)) in aggregated.iter_mut().zip(shares.into_iter()) {
                if *expected_id != share_id {
                    return Err(status::internal("committee share id mismatch"));
                }
                acc.push(value);
            }
        }
        Ok(aggregated)
    }

    pub fn reconstruct_batched_secret(
        &self,
        shares: &[(u64, Vec<u64>)],
        original_len: usize,
    ) -> Result<Vec<i64>, status::StatusError> {
        if original_len == 0 {
            return Ok(Vec::new());
        }
        if shares.len() < self.params.threshold_t {
            return Err(status::invalid_argument("not enough committee shares"));
        }
        let block_count = original_len.div_ceil(self.params.rss_secret_dim);
        let used = &shares[..self.params.threshold_t];
        if used.iter().any(|(_, values)| values.len() != block_count) {
            return Err(status::invalid_argument("share block count mismatch"));
        }
        let x_coordinates = used.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let interpolation =
            invert_vandermonde_with_modulus(&x_coordinates, self.field_mode.modulus())?;
        self.reconstruct_batched_secret_with_interpolation(
            used,
            original_len,
            &interpolation,
        )
    }

    fn reconstruct_batched_secret_with_interpolation(
        &self,
        shares: &[(u64, Vec<u64>)],
        original_len: usize,
        interpolation: &[Vec<u64>],
    ) -> Result<Vec<i64>, status::StatusError> {
        if original_len == 0 {
            return Ok(Vec::new());
        }
        if shares.len() != self.params.threshold_t
            || interpolation.len() != self.params.threshold_t
            || interpolation
                .iter()
                .any(|row| row.len() != self.params.threshold_t)
        {
            return Err(status::invalid_argument("reconstruction plan dimension mismatch"));
        }
        let block_count = original_len.div_ceil(self.params.rss_secret_dim);
        if shares.iter().any(|(_, values)| values.len() != block_count) {
            return Err(status::invalid_argument("share block count mismatch"));
        }
        let mut secret = Vec::with_capacity(block_count * self.params.rss_secret_dim);
        let modulus = self.field_mode.modulus();
        for block_index in 0..block_count {
            for row in interpolation.iter().take(self.params.rss_secret_dim) {
                let coefficient = row
                    .iter()
                    .zip(shares.iter())
                    .fold(0_u64, |acc, (&weight, (_, values))| {
                        mod_add(acc, mod_mul(weight, values[block_index], modulus), modulus)
                    });
                secret.push(field_to_signed(coefficient, modulus));
            }
        }
        secret.truncate(original_len);
        Ok(secret)
    }
}

pub struct OsaShellKaheClient {
    pub client_id: usize,
}

impl OsaShellKaheClient {
    pub fn upload(
        &self,
        iteration: u64,
        plaintext: &HashMap<&str, &[u64]>,
        kahe: &Rc<ShellKahe>,
        rss: &RampSecretSharing,
        committee_public_keys: &[RistrettoPoint],
        rng_mode: OsaShellKaheRngMode,
    ) -> Result<OsaShellKaheClientUpload, status::StatusError> {
        self.upload_with_mask_mode(
            iteration,
            plaintext,
            kahe,
            rss,
            committee_public_keys,
            rng_mode,
            OsaDigestMaskMode::Shake256Xof,
        )
    }

    pub fn upload_with_mask_mode(
        &self,
        iteration: u64,
        plaintext: &HashMap<&str, &[u64]>,
        kahe: &Rc<ShellKahe>,
        rss: &RampSecretSharing,
        committee_public_keys: &[RistrettoPoint],
        rng_mode: OsaShellKaheRngMode,
        digest_mask_mode: OsaDigestMaskMode,
    ) -> Result<OsaShellKaheClientUpload, status::StatusError> {
        self.upload_with_modes(
            iteration,
            plaintext,
            kahe,
            rss,
            committee_public_keys,
            rng_mode,
            digest_mask_mode,
            OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upload_with_modes(
        &self,
        iteration: u64,
        plaintext: &HashMap<&str, &[u64]>,
        kahe: &Rc<ShellKahe>,
        rss: &RampSecretSharing,
        committee_public_keys: &[RistrettoPoint],
        rng_mode: OsaShellKaheRngMode,
        digest_mask_mode: OsaDigestMaskMode,
        aux_encryption_mode: OsaAuxEncryptionMode,
    ) -> Result<OsaShellKaheClientUpload, status::StatusError> {
        self.upload_with_protocol_modes(
            iteration,
            plaintext,
            kahe,
            rss,
            committee_public_keys,
            rng_mode,
            digest_mask_mode,
            aux_encryption_mode,
            OsaDigestSharingMode::FullRingDigest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upload_with_protocol_modes(
        &self,
        iteration: u64,
        plaintext: &HashMap<&str, &[u64]>,
        kahe: &Rc<ShellKahe>,
        rss: &RampSecretSharing,
        committee_public_keys: &[RistrettoPoint],
        rng_mode: OsaShellKaheRngMode,
        digest_mask_mode: OsaDigestMaskMode,
        aux_encryption_mode: OsaAuxEncryptionMode,
        digest_sharing_mode: OsaDigestSharingMode,
    ) -> Result<OsaShellKaheClientUpload, status::StatusError> {
        if committee_public_keys.len() != rss.params.committee_size {
            return Err(status::invalid_argument("committee public key length mismatch"));
        }
        let mut shell_rng = make_shell_rng(
            iteration,
            self.client_id,
            "shell_kahe_keygen_encrypt",
            rng_mode,
        )?;
        let mut share_rng = make_std_rng(
            iteration,
            self.client_id,
            "rss_share_polynomial",
            rng_mode,
        );
        let key = kahe.key_gen(&mut shell_rng)?;
        let (digest_buffer, digest_sharing_secret) = match digest_sharing_mode {
            OsaDigestSharingMode::FullRingDigest => {
                // The faithful target samples dig_i directly from the same
                // discrete-Gaussian ring distribution as the KAHE secret key.
                let digest = kahe.key_gen(&mut shell_rng)?;
                let digest_buffer = kahe.try_secret_key_into(digest)?;
                (digest_buffer.clone(), digest_buffer)
            }
            OsaDigestSharingMode::SeededPrgDigest => {
                let seed_material = make_digest_seed_material(
                    iteration,
                    self.client_id,
                    rng_mode,
                );
                let digest_buffer =
                    derive_digest_buffer_from_seed(kahe, iteration, &seed_material)?;
                let seed_values = seed_material.iter().map(|&value| i64::from(value)).collect();
                (digest_buffer, seed_values)
            }
        };
        let ring_mask = expand_digest_ring_mask(
            &digest_buffer,
            kahe.packed_coefficient_count(),
            kahe.plaintext_modulus_bits(),
            iteration,
            digest_mask_mode,
        );
        let ciphertext =
            kahe.encrypt_with_ring_mask(plaintext, &key, &ring_mask, &mut shell_rng)?;
        let key_buffer = kahe.try_secret_key_into(key)?;
        let key_shares = rss.share_batched_secret(&key_buffer, &mut share_rng)?;
        let digest_shares = rss.share_batched_secret(&digest_sharing_secret, &mut share_rng)?;

        let mut encrypted_key_shares = Vec::with_capacity(rss.params.committee_size);
        for committee_index in 0..rss.params.committee_size {
            let purpose = format!("aux_share_encrypt_committee_{}", committee_index + 1);
            let mut aux_rng = make_std_rng(iteration, self.client_id, &purpose, rng_mode);
            let payload = SharePayload {
                iteration,
                client_id: self.client_id as u64,
                key_share: key_shares[committee_index].1.clone(),
                digest_share: digest_shares[committee_index].1.clone(),
            };
            let payload_bytes = payload.encode_with_field_mode(rss.field_mode())?;
            encrypted_key_shares.push(encrypt_aux(
                committee_public_keys[committee_index],
                &aad(iteration, self.client_id, committee_index + 1),
                &payload_bytes,
                &mut aux_rng,
                aux_encryption_mode,
            ));
        }

        Ok(OsaShellKaheClientUpload {
            client_id: self.client_id,
            iteration,
            ciphertext,
            encrypted_key_shares,
            serialized_key_len: key_buffer.len(),
            serialized_digest_len: digest_sharing_secret.len(),
        })
    }
}

pub struct OsaShellKaheCommitteeMember {
    pub committee_member_id: usize,
    pub key_pair: CommitteeKeyPair,
}

#[derive(Clone, Debug, Default)]
pub struct OsaCommitteePhaseTimings {
    pub active_set_validation_s: f64,
    pub auxiliary_decryption_s: f64,
    pub payload_decode_s: f64,
    pub key_share_accumulation_s: f64,
    pub digest_collection_s: f64,
}

impl OsaShellKaheCommitteeMember {
    pub fn new(committee_member_id: usize) -> Self {
        Self::new_for_iteration(0, committee_member_id)
    }

    pub fn new_for_iteration(iteration: u64, committee_member_id: usize) -> Self {
        Self::new_for_iteration_with_rng_mode(
            iteration,
            committee_member_id,
            OsaShellKaheRngMode::DeterministicBenchmark,
        )
    }

    pub fn new_for_iteration_with_rng_mode(
        iteration: u64,
        committee_member_id: usize,
        rng_mode: OsaShellKaheRngMode,
    ) -> Self {
        let mut rng = make_std_rng(iteration, committee_member_id, "committee_keypair", rng_mode);
        Self { committee_member_id, key_pair: CommitteeKeyPair::generate(&mut rng) }
    }

    pub fn combine(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        uploads: &[OsaShellKaheClientUpload],
        _params: &OsaShellKaheParameters,
    ) -> Result<CommitteeAggregateShare, status::StatusError> {
        let routed = uploads
            .iter()
            .map(|upload| RoutedCommitteeShare {
                client_id: upload.client_id,
                ciphertext: upload.encrypted_key_shares[self.committee_member_id - 1].clone(),
            })
            .collect::<Vec<_>>();
        self.combine_routed(iteration, active_clients, &routed)
    }

    pub fn combine_routed(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        routed: &[RoutedCommitteeShare],
    ) -> Result<CommitteeAggregateShare, status::StatusError> {
        self.combine_routed_with_aux_encryption_mode(
            iteration,
            active_clients,
            routed,
            OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305,
        )
    }

    pub fn combine_routed_with_aux_encryption_mode(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        routed: &[RoutedCommitteeShare],
        aux_encryption_mode: OsaAuxEncryptionMode,
    ) -> Result<CommitteeAggregateShare, status::StatusError> {
        self.combine_routed_with_timings_and_aux_encryption_mode(
            iteration,
            active_clients,
            routed,
            aux_encryption_mode,
        )
            .map(|(output, _)| output)
    }

    pub fn combine_routed_with_timings(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        routed: &[RoutedCommitteeShare],
    ) -> Result<(CommitteeAggregateShare, OsaCommitteePhaseTimings), status::StatusError> {
        self.combine_routed_with_timings_and_aux_encryption_mode(
            iteration,
            active_clients,
            routed,
            OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305,
        )
    }

    pub fn combine_routed_with_timings_and_aux_encryption_mode(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        routed: &[RoutedCommitteeShare],
        aux_encryption_mode: OsaAuxEncryptionMode,
    ) -> Result<(CommitteeAggregateShare, OsaCommitteePhaseTimings), status::StatusError> {
        self.combine_routed_with_timings_and_modes(
            iteration,
            active_clients,
            routed,
            aux_encryption_mode,
            OsaRssFieldMode::Paper61,
        )
    }

    pub fn combine_routed_with_timings_and_modes(
        &self,
        iteration: u64,
        active_clients: &BTreeSet<usize>,
        routed: &[RoutedCommitteeShare],
        aux_encryption_mode: OsaAuxEncryptionMode,
        rss_field_mode: OsaRssFieldMode,
    ) -> Result<(CommitteeAggregateShare, OsaCommitteePhaseTimings), status::StatusError> {
        let mut timings = OsaCommitteePhaseTimings::default();
        let phase_start = Instant::now();
        let routed_clients = routed.iter().map(|share| share.client_id).collect::<BTreeSet<_>>();
        if routed.len() != active_clients.len() || &routed_clients != active_clients {
            return Err(status::invalid_argument("routed shares do not match active client set"));
        }
        timings.active_set_validation_s = phase_start.elapsed().as_secs_f64();

        let mut summed_key_share: Vec<u64> = Vec::new();
        let mut digest_shares_by_client = Vec::new();
        for share in routed {
            if !active_clients.contains(&share.client_id) {
                return Err(status::invalid_argument("upload context mismatch"));
            }
            let phase_start = Instant::now();
            let plaintext = decrypt_aux(
                &self.key_pair,
                &aad(iteration, share.client_id, self.committee_member_id),
                &share.ciphertext,
                aux_encryption_mode,
            )?;
            timings.auxiliary_decryption_s += phase_start.elapsed().as_secs_f64();

            let phase_start = Instant::now();
            let payload = SharePayload::decode_with_field_mode(&plaintext, rss_field_mode)?;
            if payload.iteration != iteration || payload.client_id != share.client_id as u64 {
                return Err(status::invalid_argument("share payload context mismatch"));
            }
            if summed_key_share.is_empty() {
                summed_key_share = vec![0_u64; payload.key_share.len()];
            }
            if summed_key_share.len() != payload.key_share.len() {
                return Err(status::invalid_argument("key share length mismatch"));
            }
            timings.payload_decode_s += phase_start.elapsed().as_secs_f64();

            let phase_start = Instant::now();
            let rss_modulus = rss_field_mode.modulus();
            for (dst, value) in summed_key_share.iter_mut().zip(payload.key_share.iter()) {
                *dst = mod_add(*dst, *value, rss_modulus);
            }
            timings.key_share_accumulation_s += phase_start.elapsed().as_secs_f64();

            let phase_start = Instant::now();
            digest_shares_by_client.push((share.client_id, payload.digest_share));
            timings.digest_collection_s += phase_start.elapsed().as_secs_f64();
        }
        Ok((
            CommitteeAggregateShare {
                committee_member_id: self.committee_member_id,
                summed_key_share,
                digest_shares_by_client,
            },
            timings,
        ))
    }
}

pub struct OsaShellKaheServer {
    pub kahe: Rc<ShellKahe>,
    pub rss: RampSecretSharing,
}

#[derive(Clone, Debug, Default)]
pub struct OsaServerPhaseTimings {
    pub interpolation_s: f64,
    pub key_reconstruction_s: f64,
    pub ciphertext_aggregation_s: f64,
    pub digest_share_collection_s: f64,
    pub digest_reconstruction_s: f64,
    pub digest_mask_expansion_s: f64,
    pub mask_accumulation_s: f64,
    pub final_decryption_s: f64,
}

impl OsaShellKaheServer {
    pub fn aggregate(
        &self,
        iteration: u64,
        uploads: &[OsaShellKaheClientUpload],
        committee_outputs: &[CommitteeAggregateShare],
    ) -> Result<HashMap<String, Vec<u64>>, status::StatusError> {
        self.aggregate_with_timings(iteration, uploads, committee_outputs)
            .map(|(result, _)| result)
    }

    pub fn aggregate_with_timings(
        &self,
        iteration: u64,
        uploads: &[OsaShellKaheClientUpload],
        committee_outputs: &[CommitteeAggregateShare],
    ) -> Result<(HashMap<String, Vec<u64>>, OsaServerPhaseTimings), status::StatusError> {
        self.aggregate_with_timings_and_mask_mode(
            iteration,
            uploads,
            committee_outputs,
            OsaDigestMaskMode::Shake256Xof,
        )
    }

    pub fn aggregate_with_timings_and_mask_mode(
        &self,
        iteration: u64,
        uploads: &[OsaShellKaheClientUpload],
        committee_outputs: &[CommitteeAggregateShare],
        digest_mask_mode: OsaDigestMaskMode,
    ) -> Result<(HashMap<String, Vec<u64>>, OsaServerPhaseTimings), status::StatusError> {
        self.aggregate_with_timings_and_modes(
            iteration,
            uploads,
            committee_outputs,
            digest_mask_mode,
            OsaDigestSharingMode::FullRingDigest,
        )
    }

    pub fn aggregate_with_timings_and_modes(
        &self,
        iteration: u64,
        uploads: &[OsaShellKaheClientUpload],
        committee_outputs: &[CommitteeAggregateShare],
        digest_mask_mode: OsaDigestMaskMode,
        digest_sharing_mode: OsaDigestSharingMode,
    ) -> Result<(HashMap<String, Vec<u64>>, OsaServerPhaseTimings), status::StatusError> {
        let mut timings = OsaServerPhaseTimings::default();
        if uploads.is_empty() {
            return Ok((HashMap::new(), timings));
        }
        if committee_outputs.len() < self.rss.params.threshold_t {
            return Err(status::invalid_argument("not enough committee outputs"));
        }
        let selected_outputs = &committee_outputs[..self.rss.params.threshold_t];
        let phase_start = Instant::now();
        let interpolation = invert_vandermonde_with_modulus(
            &selected_outputs
                .iter()
                .map(|share| share.committee_member_id as u64)
                .collect::<Vec<_>>(),
            self.rss.field_mode().modulus(),
        )?;
        timings.interpolation_s = phase_start.elapsed().as_secs_f64();

        let phase_start = Instant::now();
        let key_points = selected_outputs
            .iter()
            .map(|share| (share.committee_member_id as u64, share.summed_key_share.clone()))
            .collect::<Vec<_>>();
        let key_buffer = self
            .rss
            .reconstruct_batched_secret_with_interpolation(
                &key_points,
                uploads[0].serialized_key_len,
                &interpolation,
            )?;
        let key = self.kahe.try_secret_key_from(key_buffer)?;
        timings.key_reconstruction_s = phase_start.elapsed().as_secs_f64();

        let phase_start = Instant::now();
        let mut ciphertext_sum = uploads[0].ciphertext.clone();
        for upload in uploads.iter().skip(1) {
            if upload.iteration != iteration {
                return Err(status::invalid_argument("iteration mismatch in upload set"));
            }
            self.kahe.add_ciphertexts_in_place(&upload.ciphertext, &mut ciphertext_sum)?;
        }
        timings.ciphertext_aggregation_s = phase_start.elapsed().as_secs_f64();

        let mut aggregate_ring_mask =
            vec![0_u64; self.kahe.packed_coefficient_count() * 4];
        for upload in uploads {
            let phase_start = Instant::now();
            let digest_points = selected_outputs
                .iter()
                .map(|share| {
                    let digest_share = share
                        .digest_shares_by_client
                        .iter()
                        .find(|(client_id, _)| *client_id == upload.client_id)
                        .ok_or_else(|| status::invalid_argument("missing digest share for client"))?;
                    Ok((share.committee_member_id as u64, digest_share.1.clone()))
                })
                .collect::<Result<Vec<_>, status::StatusError>>()?;
            timings.digest_share_collection_s += phase_start.elapsed().as_secs_f64();

            let phase_start = Instant::now();
            let digest_sharing_secret = self
                .rss
                .reconstruct_batched_secret_with_interpolation(
                    &digest_points,
                    upload.serialized_digest_len,
                    &interpolation,
                )?;
            let digest = match digest_sharing_mode {
                OsaDigestSharingMode::FullRingDigest => digest_sharing_secret,
                OsaDigestSharingMode::SeededPrgDigest => {
                    if digest_sharing_secret.len() != 32 {
                        return Err(status::invalid_argument("seeded digest length mismatch"));
                    }
                    let mut seed_material = [0_u8; 32];
                    for (dst, value) in seed_material.iter_mut().zip(digest_sharing_secret) {
                        *dst = u8::try_from(value).map_err(|_| {
                            status::invalid_argument("seeded digest byte is out of range")
                        })?;
                    }
                    derive_digest_buffer_from_seed(&self.kahe, iteration, &seed_material)?
                }
            };
            timings.digest_reconstruction_s += phase_start.elapsed().as_secs_f64();

            let phase_start = Instant::now();
            let ring_mask = expand_digest_ring_mask(
                &digest,
                self.kahe.packed_coefficient_count(),
                self.kahe.plaintext_modulus_bits(),
                iteration,
                digest_mask_mode,
            );
            timings.digest_mask_expansion_s += phase_start.elapsed().as_secs_f64();

            let phase_start = Instant::now();
            add_ring_masks_in_place(
                &mut aggregate_ring_mask,
                &ring_mask,
                self.kahe.plaintext_modulus_bits(),
            );
            timings.mask_accumulation_s += phase_start.elapsed().as_secs_f64();
        }

        let phase_start = Instant::now();
        let result = self.kahe.decrypt_with_ring_mask(&ciphertext_sum, &key, &aggregate_ring_mask)?;
        timings.final_decryption_s = phase_start.elapsed().as_secs_f64();
        Ok((result, timings))
    }
}

fn aad(iteration: u64, client_id: usize, committee_member_id: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&iteration.to_le_bytes());
    out.extend_from_slice(&(client_id as u64).to_le_bytes());
    out.extend_from_slice(&(committee_member_id as u64).to_le_bytes());
    out
}

pub fn expand_digest_ring_mask(
    digest: &[i64],
    coefficient_count: usize,
    modulus_bits: usize,
    iteration: u64,
    mode: OsaDigestMaskMode,
) -> Vec<u64> {
    match mode {
        OsaDigestMaskMode::CounterSha3Reference => expand_digest_ring_mask_counter_sha3(
            digest,
            coefficient_count,
            modulus_bits,
            iteration,
        ),
        OsaDigestMaskMode::Shake256Xof => expand_digest_ring_mask_shake256(
            digest,
            coefficient_count,
            modulus_bits,
            iteration,
        ),
    }
}

fn expand_digest_ring_mask_counter_sha3(
    digest: &[i64],
    coefficient_count: usize,
    modulus_bits: usize,
    iteration: u64,
) -> Vec<u64> {
    let mut out = Vec::with_capacity(coefficient_count * 4);
    for counter in 0..coefficient_count as u64 {
        let mut hash = Sha3_256::new();
        hash.update(b"osa_hash_digest_to_kahe_plaintext_ring_v1");
        hash.update(iteration.to_le_bytes());
        hash.update(counter.to_le_bytes());
        for &value in digest {
            hash.update(value.to_le_bytes());
        }
        let block = hash.finalize();
        for chunk in block.chunks_exact(8) {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(chunk);
            out.push(u64::from_le_bytes(buf));
        }
        let coefficient_start = out.len() - 4;
        truncate_ring_coefficient(&mut out[coefficient_start..], modulus_bits);
    }
    out
}

fn expand_digest_ring_mask_shake256(
    digest: &[i64],
    coefficient_count: usize,
    modulus_bits: usize,
    iteration: u64,
) -> Vec<u64> {
    let mut hasher = Shake256::default();
    sha3::digest::Update::update(
        &mut hasher,
        b"osa_hash_digest_to_kahe_plaintext_ring_shake256_v1",
    );
    sha3::digest::Update::update(&mut hasher, &iteration.to_le_bytes());
    sha3::digest::Update::update(&mut hasher, &(digest.len() as u64).to_le_bytes());
    for &value in digest {
        sha3::digest::Update::update(&mut hasher, &value.to_le_bytes());
    }

    let mut reader = hasher.finalize_xof();
    let mut out = Vec::with_capacity(coefficient_count * 4);
    let mut block = [0_u8; 32];
    for _ in 0..coefficient_count {
        reader.read(&mut block);
        for chunk in block.chunks_exact(8) {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(chunk);
            out.push(u64::from_le_bytes(buf));
        }
        let coefficient_start = out.len() - 4;
        truncate_ring_coefficient(&mut out[coefficient_start..], modulus_bits);
    }
    out
}

pub fn add_ring_masks_in_place(destination: &mut [u64], source: &[u64], modulus_bits: usize) {
    assert_eq!(destination.len(), source.len());
    for (dst, src) in destination.chunks_exact_mut(4).zip(source.chunks_exact(4)) {
        let mut carry = false;
        for limb in 0..4 {
            let (sum0, carry0) = dst[limb].overflowing_add(src[limb]);
            let (sum1, carry1) = sum0.overflowing_add(u64::from(carry));
            dst[limb] = sum1;
            carry = carry0 || carry1;
        }
        truncate_ring_coefficient(dst, modulus_bits);
    }
}

/// Adds canonical R_t representatives as integers for the VOSA R_Q opening.
/// Unlike the OSA decryption mask sum above, this must not reduce modulo t.
pub fn add_vosa_digest_sums_in_place(
    destination: &mut [u64],
    source: &[u64],
) -> Result<(), status::StatusError> {
    if destination.len() != source.len() || destination.len() % 4 != 0 {
        return Err(status::invalid_argument("VOSA digest sum length mismatch"));
    }
    for (dst, src) in destination.chunks_exact_mut(4).zip(source.chunks_exact(4)) {
        let mut carry = false;
        for limb in 0..4 {
            let (sum0, carry0) = dst[limb].overflowing_add(src[limb]);
            let (sum1, carry1) = sum0.overflowing_add(u64::from(carry));
            dst[limb] = sum1;
            carry = carry0 || carry1;
        }
        if carry {
            return Err(status::out_of_range("VOSA digest sum exceeds 256 bits"));
        }
    }
    Ok(())
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

fn derive_hkdf_seed(iteration: u64, party_id: usize, purpose: &str) -> Result<Seed, status::StatusError> {
    let mut input = Vec::with_capacity(64 + purpose.len());
    input.extend_from_slice(b"osa_shell_kahe_shell_rng_seed_v1");
    input.extend_from_slice(&iteration.to_le_bytes());
    input.extend_from_slice(&(party_id as u64).to_le_bytes());
    input.extend_from_slice(purpose.as_bytes());
    compute_hkdf(
        &input,
        b"osa_shell_kahe_shell_rng_salt_v1",
        purpose.as_bytes(),
        seed_length(),
    )
}

fn make_shell_rng(
    iteration: u64,
    party_id: usize,
    purpose: &str,
    rng_mode: OsaShellKaheRngMode,
) -> Result<SingleThreadHkdfPrng, status::StatusError> {
    let seed = match rng_mode {
        OsaShellKaheRngMode::DeterministicBenchmark => derive_hkdf_seed(iteration, party_id, purpose)?,
        OsaShellKaheRngMode::OsRngSecurity => SingleThreadHkdfPrng::generate_seed()?,
    };
    SingleThreadHkdfPrng::create(&seed)
}

fn make_digest_seed_material(
    iteration: u64,
    client_id: usize,
    rng_mode: OsaShellKaheRngMode,
) -> [u8; 32] {
    match rng_mode {
        OsaShellKaheRngMode::DeterministicBenchmark => {
            derive_std_seed(iteration, client_id, "seeded_digest_material")
        }
        OsaShellKaheRngMode::OsRngSecurity => {
            let mut seed_material = [0_u8; 32];
            StdRng::from_entropy().fill_bytes(&mut seed_material);
            seed_material
        }
    }
}

fn derive_digest_buffer_from_seed(
    kahe: &ShellKahe,
    iteration: u64,
    seed_material: &[u8; 32],
) -> Result<Vec<i64>, status::StatusError> {
    let digest_seed = compute_hkdf(
        seed_material,
        b"osa_seeded_digest_shell_rng_salt_v1",
        &iteration.to_le_bytes(),
        seed_length(),
    )?;
    let mut digest_rng = SingleThreadHkdfPrng::create(&digest_seed)?;
    let digest = kahe.key_gen(&mut digest_rng)?;
    kahe.try_secret_key_into(digest)
}

fn make_std_rng(
    iteration: u64,
    party_id: usize,
    purpose: &str,
    rng_mode: OsaShellKaheRngMode,
) -> StdRng {
    match rng_mode {
        OsaShellKaheRngMode::DeterministicBenchmark => {
            StdRng::from_seed(derive_std_seed(iteration, party_id, purpose))
        }
        OsaShellKaheRngMode::OsRngSecurity => StdRng::from_entropy(),
    }
}

fn derive_std_seed(iteration: u64, party_id: usize, purpose: &str) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"osa_shell_kahe_std_rng_seed_v1");
    hash.update(iteration.to_le_bytes());
    hash.update((party_id as u64).to_le_bytes());
    hash.update(purpose.as_bytes());
    hash.finalize().into()
}

fn encrypt_aux(
    public_key: RistrettoPoint,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut StdRng,
    mode: OsaAuxEncryptionMode,
) -> CommitteeCiphertext {
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    let ephemeral_secret = Scalar::from_bytes_mod_order_wide(&wide);
    let ephemeral_public = (ephemeral_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let shared = (ephemeral_secret * public_key).compress().to_bytes();
    let (body, tag) = match mode {
        OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305 => {
            let (key, nonce) = derive_xchacha20_poly1305_key_nonce(&shared, aad);
            xchacha20_poly1305_encrypt(&key, &nonce, aad, plaintext)
        }
        OsaAuxEncryptionMode::IndCpaShake256 => {
            let keystream = derive_ind_cpa_shake256_keystream(&shared, aad, plaintext.len());
            let body = plaintext
                .iter()
                .zip(keystream.iter())
                .map(|(plaintext_byte, mask_byte)| plaintext_byte ^ mask_byte)
                .collect();
            (body, Vec::new())
        }
    };
    CommitteeCiphertext { ephemeral_public, body, tag }
}

fn decrypt_aux(
    key_pair: &CommitteeKeyPair,
    aad: &[u8],
    ciphertext: &CommitteeCiphertext,
    mode: OsaAuxEncryptionMode,
) -> Result<Vec<u8>, status::StatusError> {
    let eph = CompressedRistretto(ciphertext.ephemeral_public)
        .decompress()
        .ok_or_else(|| status::invalid_argument("invalid auxiliary ciphertext"))?;
    let shared = (key_pair.secret * eph).compress().to_bytes();
    match mode {
        OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305 => {
            if ciphertext.tag.len() != 16 {
                return Err(status::invalid_argument("invalid committee share AEAD tag length"));
            }
            let (key, nonce) = derive_xchacha20_poly1305_key_nonce(&shared, aad);
            if let Some(plaintext) =
                xchacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext.body, &ciphertext.tag)
            {
                Ok(plaintext)
            } else {
                Err(status::invalid_argument("committee share AEAD authentication failed"))
            }
        }
        OsaAuxEncryptionMode::IndCpaShake256 => {
            if !ciphertext.tag.is_empty() {
                return Err(status::invalid_argument("unexpected tag on IND-CPA committee share"));
            }
            let keystream = derive_ind_cpa_shake256_keystream(&shared, aad, ciphertext.body.len());
            Ok(ciphertext
                .body
                .iter()
                .zip(keystream.iter())
                .map(|(ciphertext_byte, mask_byte)| ciphertext_byte ^ mask_byte)
                .collect())
        }
    }
}

pub fn committee_share_encryption_scheme() -> &'static str {
    "xchacha20_poly1305"
}

fn derive_ind_cpa_shake256_keystream(
    shared_secret: &[u8; 32],
    aad: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut xof = Shake256::default();
    sha3::digest::Update::update(&mut xof, b"osa_ind_cpa_pke_shake256_v1");
    sha3::digest::Update::update(&mut xof, shared_secret);
    sha3::digest::Update::update(&mut xof, &(aad.len() as u64).to_le_bytes());
    sha3::digest::Update::update(&mut xof, aad);
    sha3::digest::Update::update(&mut xof, &(length as u64).to_le_bytes());
    let mut reader = xof.finalize_xof();
    let mut keystream = vec![0_u8; length];
    reader.read(&mut keystream);
    keystream
}

fn derive_xchacha20_poly1305_key_nonce(shared_secret: &[u8; 32], aad: &[u8]) -> ([u8; 32], [u8; 24]) {
    let mut key_hash = Sha3_256::new();
    key_hash.update(b"osa_shell_kahe_xchacha20_poly1305_key_v1");
    key_hash.update(shared_secret);
    key_hash.update(aad);
    let key = key_hash.finalize().into();

    let mut nonce = [0_u8; 24];
    let mut nonce_hash_0 = Sha3_256::new();
    nonce_hash_0.update(b"osa_shell_kahe_xchacha20_poly1305_nonce_v1");
    nonce_hash_0.update(shared_secret);
    nonce_hash_0.update(aad);
    nonce[..16].copy_from_slice(&nonce_hash_0.finalize()[..16]);
    let mut nonce_hash_1 = Sha3_256::new();
    nonce_hash_1.update(b"osa_shell_kahe_xchacha20_poly1305_nonce_v2");
    nonce_hash_1.update(shared_secret);
    nonce_hash_1.update(aad);
    nonce[16..].copy_from_slice(&nonce_hash_1.finalize()[..8]);
    (key, nonce)
}

fn xchacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let (subkey, nonce12) = xchacha20_subkey_and_nonce(key, nonce);
    let poly_key_block = chacha20_block(&subkey, 0, &nonce12);
    let mut poly_key = [0_u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);
    let body = chacha20_xor(&subkey, &nonce12, 1, plaintext);
    let tag = poly1305_mac(&poly_key, &poly1305_aead_input(aad, &body));
    (body, tag.to_vec())
}

fn xchacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    if tag.len() != 16 {
        return None;
    }
    let (subkey, nonce12) = xchacha20_subkey_and_nonce(key, nonce);
    let poly_key_block = chacha20_block(&subkey, 0, &nonce12);
    let mut poly_key = [0_u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);
    let expected = poly1305_mac(&poly_key, &poly1305_aead_input(aad, ciphertext));
    let mut diff = 0_u8;
    for (lhs, rhs) in expected.iter().zip(tag.iter()) {
        diff |= lhs ^ rhs;
    }
    if diff != 0 {
        return None;
    }
    Some(chacha20_xor(&subkey, &nonce12, 1, ciphertext))
}

fn xchacha20_subkey_and_nonce(key: &[u8; 32], nonce: &[u8; 24]) -> ([u8; 32], [u8; 12]) {
    let mut nonce16 = [0_u8; 16];
    nonce16.copy_from_slice(&nonce[..16]);
    let subkey = hchacha20(key, &nonce16);
    let mut nonce12 = [0_u8; 12];
    nonce12[4..].copy_from_slice(&nonce[16..]);
    (subkey, nonce12)
}

fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut state = [0_u32; 16];
    state[..4].copy_from_slice(&CHACHA20_CONSTANTS);
    for (idx, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + idx] = load_u32_le(chunk);
    }
    for (idx, chunk) in nonce16.chunks_exact(4).enumerate() {
        state[12 + idx] = load_u32_le(chunk);
    }
    chacha20_rounds(&mut state);
    let words = [state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15]];
    let mut out = [0_u8; 32];
    for (idx, word) in words.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], nonce12: &[u8; 12], initial_counter: u32, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (block_index, chunk) in input.chunks(64).enumerate() {
        let block = chacha20_block(key, initial_counter.wrapping_add(block_index as u32), nonce12);
        out.extend(chunk.iter().zip(block.iter()).map(|(lhs, rhs)| lhs ^ rhs));
    }
    out
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce12: &[u8; 12]) -> [u8; 64] {
    let mut state = [0_u32; 16];
    state[..4].copy_from_slice(&CHACHA20_CONSTANTS);
    for (idx, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + idx] = load_u32_le(chunk);
    }
    state[12] = counter;
    for (idx, chunk) in nonce12.chunks_exact(4).enumerate() {
        state[13 + idx] = load_u32_le(chunk);
    }
    let initial = state;
    chacha20_rounds(&mut state);
    let mut out = [0_u8; 64];
    for idx in 0..16 {
        let word = state[idx].wrapping_add(initial[idx]);
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn chacha20_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn poly1305_aead_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    out.extend_from_slice(aad);
    pad16(&mut out, aad.len());
    out.extend_from_slice(ciphertext);
    pad16(&mut out, ciphertext.len());
    out.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out
}

fn pad16(out: &mut Vec<u8>, len: usize) {
    let rem = len % 16;
    if rem != 0 {
        out.extend(std::iter::repeat(0_u8).take(16 - rem));
    }
}

fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0_u8; 16];
    r_bytes.copy_from_slice(&key[..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;
    let r = limbs_from_le_bytes(&r_bytes);
    let mut acc = vec![0_u64];

    for chunk in msg.chunks(16) {
        let mut block = Vec::with_capacity(chunk.len() + 1);
        block.extend_from_slice(chunk);
        block.push(1);
        acc = add_limbs(&acc, &limbs_from_le_bytes(&block));
        acc = reduce_poly1305(mul_limbs(&acc, &r)).to_vec();
    }

    let s = limbs_from_le_bytes(&key[16..32]);
    let mut carry = 0_u64;
    let mut out = [0_u8; 16];
    for idx in 0..4 {
        let total = acc.get(idx).copied().unwrap_or(0) + s.get(idx).copied().unwrap_or(0) + carry;
        out[idx * 4..idx * 4 + 4].copy_from_slice(&(total as u32).to_le_bytes());
        carry = total >> 32;
    }
    out
}

fn limbs_from_le_bytes(bytes: &[u8]) -> Vec<u64> {
    let mut limbs = vec![0_u64; bytes.len().div_ceil(4).max(1)];
    for (idx, &byte) in bytes.iter().enumerate() {
        limbs[idx / 4] |= (byte as u64) << (8 * (idx % 4));
    }
    trim_limbs(normalize_limbs(limbs))
}

fn add_limbs(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
    let len = lhs.len().max(rhs.len());
    let mut out = vec![0_u64; len];
    for idx in 0..len {
        out[idx] = lhs.get(idx).copied().unwrap_or(0) + rhs.get(idx).copied().unwrap_or(0);
    }
    trim_limbs(normalize_limbs(out))
}

fn mul_limbs(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
    let mut wide = vec![0_u128; lhs.len() + rhs.len()];
    for (i, &a) in lhs.iter().enumerate() {
        for (j, &b) in rhs.iter().enumerate() {
            wide[i + j] += a as u128 * b as u128;
        }
    }
    let mut out = Vec::with_capacity(wide.len() + 1);
    let mut carry = 0_u128;
    for value in wide {
        let total = value + carry;
        out.push((total & 0xffff_ffff) as u64);
        carry = total >> 32;
    }
    while carry != 0 {
        out.push((carry & 0xffff_ffff) as u64);
        carry >>= 32;
    }
    trim_limbs(out)
}

fn reduce_poly1305(mut value: Vec<u64>) -> [u64; 5] {
    value = normalize_limbs(value);
    loop {
        let high = shift_right_130(&value);
        if high.is_empty() {
            break;
        }
        let mut low = low_130(&value);
        if low.len() < high.len() {
            low.resize(high.len(), 0);
        }
        for (idx, &word) in high.iter().enumerate() {
            low[idx] += word * 5;
        }
        value = normalize_limbs(low);
    }
    let mut out = [0_u64; 5];
    for (idx, &word) in value.iter().take(5).enumerate() {
        out[idx] = word;
    }
    while cmp_poly1305_p(&out) >= 0 {
        sub_poly1305_p(&mut out);
    }
    out
}

fn low_130(value: &[u64]) -> Vec<u64> {
    let mut out = vec![0_u64; 5];
    for idx in 0..4 {
        out[idx] = value.get(idx).copied().unwrap_or(0);
    }
    out[4] = value.get(4).copied().unwrap_or(0) & 0x3;
    trim_limbs(out)
}

fn shift_right_130(value: &[u64]) -> Vec<u64> {
    if value.len() <= 4 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(value.len() - 4);
    for src in 4..value.len() {
        let word = (value[src] >> 2)
            | value.get(src + 1).map(|next| (next & 0x3) << 30).unwrap_or(0);
        out.push(word & 0xffff_ffff);
    }
    let out = trim_limbs(out);
    if out.len() == 1 && out[0] == 0 {
        Vec::new()
    } else {
        out
    }
}

fn normalize_limbs(mut value: Vec<u64>) -> Vec<u64> {
    let mut carry = 0_u64;
    for word in value.iter_mut() {
        let total = *word + carry;
        *word = total & 0xffff_ffff;
        carry = total >> 32;
    }
    while carry != 0 {
        value.push(carry & 0xffff_ffff);
        carry >>= 32;
    }
    trim_limbs(value)
}

fn trim_limbs(mut value: Vec<u64>) -> Vec<u64> {
    while value.len() > 1 && value.last() == Some(&0) {
        value.pop();
    }
    value
}

fn cmp_poly1305_p(value: &[u64; 5]) -> i8 {
    const P: [u64; 5] = [0xffff_fffb, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0x3];
    for idx in (0..5).rev() {
        if value[idx] > P[idx] {
            return 1;
        }
        if value[idx] < P[idx] {
            return -1;
        }
    }
    0
}

fn sub_poly1305_p(value: &mut [u64; 5]) {
    const P: [u64; 5] = [0xffff_fffb, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0x3];
    let mut borrow = 0_i128;
    for idx in 0..5 {
        let diff = value[idx] as i128 - P[idx] as i128 - borrow;
        if diff < 0 {
            value[idx] = (diff + (1_i128 << 32)) as u64;
            borrow = 1;
        } else {
            value[idx] = diff as u64;
            borrow = 0;
        }
    }
}

fn load_u32_le(bytes: &[u8]) -> u32 {
    let mut out = [0_u8; 4];
    out.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(out)
}

#[cfg(test)]
mod test {
    use super::*;

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        let compact = hex.split_whitespace().collect::<String>();
        assert_eq!(compact.len(), N * 2);
        let mut out = [0_u8; N];
        for idx in 0..N {
            out[idx] = u8::from_str_radix(&compact[idx * 2..idx * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn chacha20_block_matches_rfc8439_vector() {
        let key = decode_hex::<32>(
            "000102030405060708090a0b0c0d0e0f
             101112131415161718191a1b1c1d1e1f",
        );
        let nonce = decode_hex::<12>("000000090000004a00000000");
        let block = chacha20_block(&key, 1, &nonce);
        let expected = decode_hex::<64>(
            "10f1e7e4d13b5915500fdd1fa32071c4
             c7d1f4c733c068030422aa9ac3d46c4e
             d2826446079faa0914c2d705d98b02a2
             b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(block, expected);
    }

    #[test]
    fn poly1305_matches_rfc8439_vector() {
        let key = decode_hex::<32>(
            "85d6be7857556d337f4452fe42d506a8
             0103808afb0db2fd4abff6af4149f51b",
        );
        let tag = poly1305_mac(&key, b"Cryptographic Forum Research Group");
        let expected = decode_hex::<16>("a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(tag, expected);
    }

    #[test]
    fn xchacha20_poly1305_rejects_tampering() {
        let key = [7_u8; 32];
        let nonce = [9_u8; 24];
        let aad = b"round=1;client=2;committee=3";
        let plaintext = b"committee share payload";
        let (mut ciphertext, tag) = xchacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(
            xchacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap(),
            plaintext
        );
        ciphertext[0] ^= 1;
        assert!(xchacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag).is_none());
        assert!(xchacha20_poly1305_decrypt(&key, &nonce, b"bad aad", &ciphertext, &tag).is_none());
    }

    #[test]
    fn ind_cpa_shake256_aux_encryption_round_trips() {
        let mut rng = StdRng::seed_from_u64(0x4f53_415f_504b_45);
        let key_pair = CommitteeKeyPair::generate(&mut rng);
        let aad = b"round=3;client=5;committee=7";
        let plaintext = vec![9_u8; 4_211];
        let ciphertext = encrypt_aux(
            key_pair.public(),
            aad,
            &plaintext,
            &mut rng,
            OsaAuxEncryptionMode::IndCpaShake256,
        );
        assert!(ciphertext.tag.is_empty());
        assert_eq!(
            decrypt_aux(&key_pair, aad, &ciphertext, OsaAuxEncryptionMode::IndCpaShake256)
                .unwrap(),
            plaintext
        );
        assert_ne!(
            decrypt_aux(
                &key_pair,
                b"wrong aad",
                &ciphertext,
                OsaAuxEncryptionMode::IndCpaShake256,
            )
            .unwrap(),
            plaintext
        );
        assert!(decrypt_aux(
            &key_pair,
            aad,
            &ciphertext,
            OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305,
        )
        .is_err());
    }

    #[test]
    fn mersenne_rss_arithmetic_matches_generic_modulo() {
        let edge_values = [0_u64, 1, 2, Q_RSS / 2, Q_RSS - 2, Q_RSS - 1];
        for &a in &edge_values {
            for &b in &edge_values {
                assert_eq!(
                    mod_add(a, b, Q_RSS),
                    ((a as u128 + b as u128) % Q_RSS as u128) as u64
                );
                assert_eq!(
                    mod_sub(a, b, Q_RSS),
                    ((a as u128 + Q_RSS as u128 - b as u128) % Q_RSS as u128) as u64
                );
                assert_eq!(
                    mod_mul(a, b, Q_RSS),
                    ((a as u128 * b as u128) % Q_RSS as u128) as u64
                );
            }
        }

        let mut rng = StdRng::seed_from_u64(0x4f53_415f_5253_53);
        for _ in 0..10_000 {
            let a = rng.next_u64() % Q_RSS;
            let b = rng.next_u64() % Q_RSS;
            assert_eq!(
                mod_mul(a, b, Q_RSS),
                ((a as u128 * b as u128) % Q_RSS as u128) as u64
            );
        }
    }

    #[test]
    fn rss_field_packing_round_trips_canonically() {
        let mut values = vec![0, 1, 2, Q_RSS / 2, Q_RSS - 2, Q_RSS - 1];
        let mut rng = StdRng::seed_from_u64(0x4f53_415f_5041_434b);
        values.extend((0..10_000).map(|_| rng.next_u64() % Q_RSS));
        let packed = pack_rss_field_elements(&values).unwrap();
        assert_eq!(packed.len(), rss_packed_byte_len(values.len()).unwrap());
        assert_eq!(unpack_rss_field_elements(&packed, values.len()).unwrap(), values);

        assert_eq!(pack_rss_field_elements(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(unpack_rss_field_elements(&[], 0).unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn rss_field_packing_rejects_invalid_encodings() {
        assert!(pack_rss_field_elements(&[Q_RSS]).is_err());

        let packed = pack_rss_field_elements(&[1, 2]).unwrap();
        assert!(unpack_rss_field_elements(&packed[..packed.len() - 1], 2).is_err());

        let mut non_canonical_value = vec![0xff; rss_packed_byte_len(1).unwrap()];
        non_canonical_value[7] &= 0x1f;
        assert!(unpack_rss_field_elements(&non_canonical_value, 1).is_err());

        let mut non_zero_padding = pack_rss_field_elements(&[0]).unwrap();
        non_zero_padding[7] |= 0x80;
        assert!(unpack_rss_field_elements(&non_zero_padding, 1).is_err());
    }

    #[test]
    fn share_payload_uses_packed_rss_elements() {
        let payload = SharePayload {
            iteration: 7,
            client_id: 11,
            key_share: vec![1, Q_RSS - 1, 3],
            digest_share: vec![4, 5, Q_RSS - 2, 7],
        };
        let encoded = payload.encode().unwrap();
        assert_eq!(encoded.len(), 32 + rss_packed_byte_len(7).unwrap());
        let decoded = SharePayload::decode(&encoded).unwrap();
        assert_eq!(decoded.iteration, payload.iteration);
        assert_eq!(decoded.client_id, payload.client_id);
        assert_eq!(decoded.key_share, payload.key_share);
        assert_eq!(decoded.digest_share, payload.digest_share);
    }

    #[test]
    fn compact31_packing_and_payload_round_trip_canonically() {
        let mode = OsaRssFieldMode::Compact31;
        let values = vec![0, 1, Q_RSS_COMPACT / 2, Q_RSS_COMPACT - 1];
        let packed = pack_rss_field_elements_for_mode(&values, mode).unwrap();
        assert_eq!(
            packed.len(),
            rss_packed_byte_len_for_mode(values.len(), mode).unwrap()
        );
        assert_eq!(
            unpack_rss_field_elements_for_mode(&packed, values.len(), mode).unwrap(),
            values
        );
        assert!(pack_rss_field_elements_for_mode(&[Q_RSS_COMPACT], mode).is_err());

        let payload = SharePayload {
            iteration: 13,
            client_id: 17,
            key_share: vec![1, Q_RSS_COMPACT - 1, 3],
            digest_share: vec![4, 5],
        };
        let encoded = payload.encode_with_field_mode(mode).unwrap();
        let decoded = SharePayload::decode_with_field_mode(&encoded, mode).unwrap();
        assert_eq!(decoded.iteration, payload.iteration);
        assert_eq!(decoded.client_id, payload.client_id);
        assert_eq!(decoded.key_share, payload.key_share);
        assert_eq!(decoded.digest_share, payload.digest_share);
        assert!(SharePayload::decode_with_field_mode(&encoded, OsaRssFieldMode::Paper61).is_err());
    }

    #[test]
    fn compact31_rss_reconstructs_signed_small_secrets() {
        let params = OsaShellKaheParameters {
            committee_size: 5,
            threshold_t: 3,
            rss_secret_dim: 2,
        };
        let rss = RampSecretSharing::new_with_field_mode(params, OsaRssFieldMode::Compact31)
            .unwrap();
        let secret = vec![-37_i64, 0, 37, 255, -1];
        let mut rng = StdRng::seed_from_u64(0x4f53_415f_4333_31);
        let shares = rss.share_batched_secret(&secret, &mut rng).unwrap();
        let selected = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        assert_eq!(rss.reconstruct_batched_secret(&selected, secret.len()).unwrap(), secret);
        assert!(signed_to_field(Q_RSS_COMPACT as i64, Q_RSS_COMPACT).is_err());
    }
}

fn interpolate_polynomial(points: &[(u64, u64)], threshold_t: usize) -> Result<Vec<u64>, status::StatusError> {
    if points.len() < threshold_t {
        return Err(status::invalid_argument("not enough points for interpolation"));
    }
    let n = threshold_t;
    let mut matrix = vec![vec![0_u64; n + 1]; n];
    for (row, (x, y)) in points.iter().take(n).enumerate() {
        let mut power = 1_u64;
        for col in 0..n {
            matrix[row][col] = power;
            power = mod_mul(power, *x % Q_RSS, Q_RSS);
        }
        matrix[row][n] = *y % Q_RSS;
    }
    gaussian_elimination(matrix)
}

fn invert_vandermonde(x_coordinates: &[u64]) -> Result<Vec<Vec<u64>>, status::StatusError> {
    invert_vandermonde_with_modulus(x_coordinates, Q_RSS)
}

fn invert_vandermonde_with_modulus(
    x_coordinates: &[u64],
    modulus: u64,
) -> Result<Vec<Vec<u64>>, status::StatusError> {
    let n = x_coordinates.len();
    if n == 0 {
        return Err(status::invalid_argument("empty interpolation set"));
    }
    let mut matrix = vec![vec![0_u64; 2 * n]; n];
    for (row, &x) in x_coordinates.iter().enumerate() {
        let mut power = 1_u64;
        for col in 0..n {
            matrix[row][col] = power;
            power = mod_mul(power, x % modulus, modulus);
        }
        matrix[row][n + row] = 1;
    }

    for col in 0..n {
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or_else(|| status::invalid_argument("singular interpolation matrix"))?;
        matrix.swap(col, pivot);
        let inv = mod_inv(matrix[col][col], modulus);
        for value in matrix[col].iter_mut() {
            *value = mod_mul(*value, inv, modulus);
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
                matrix[row][j] = mod_sub(
                    matrix[row][j],
                    mod_mul(factor, matrix[col][j], modulus),
                    modulus,
                );
            }
        }
    }
    Ok(matrix.into_iter().map(|row| row[n..].to_vec()).collect())
}

fn gaussian_elimination(mut matrix: Vec<Vec<u64>>) -> Result<Vec<u64>, status::StatusError> {
    let n = matrix.len();
    for col in 0..n {
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or_else(|| status::invalid_argument("singular interpolation matrix"))?;
        matrix.swap(col, pivot);
        let inv = mod_inv(matrix[col][col], Q_RSS);
        for j in col..=n {
            matrix[col][j] = mod_mul(matrix[col][j], inv, Q_RSS);
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for j in col..=n {
                let sub = mod_mul(factor, matrix[col][j], Q_RSS);
                matrix[row][j] = mod_sub(matrix[row][j], sub, Q_RSS);
            }
        }
    }
    Ok((0..n).map(|row| matrix[row][n]).collect())
}

fn random_mod_q(rng: &mut StdRng, modulus: u64) -> u64 {
    let rejection_limit = u64::MAX - (u64::MAX % modulus);
    loop {
        let value = rng.next_u64();
        if value < rejection_limit {
            return value % modulus;
        }
    }
}

fn signed_to_field(value: i64, modulus: u64) -> Result<u64, status::StatusError> {
    let magnitude = value.unsigned_abs();
    if magnitude > modulus / 2 {
        return Err(status::invalid_argument("signed RSS secret exceeds field range"));
    }
    if value >= 0 {
        Ok(value as u64)
    } else {
        Ok(modulus - magnitude)
    }
}

fn field_to_signed(value: u64, modulus: u64) -> i64 {
    if value <= modulus / 2 {
        value as i64
    } else {
        -((modulus - value) as i64)
    }
}

fn mod_add(a: u64, b: u64, modulus: u64) -> u64 {
    if modulus == Q_RSS {
        reduce_mersenne_q(a as u128 + b as u128)
    } else {
        ((a as u128 + b as u128) % modulus as u128) as u64
    }
}

fn mod_sub(a: u64, b: u64, modulus: u64) -> u64 {
    if modulus == Q_RSS {
        if a >= b { a - b } else { Q_RSS - (b - a) }
    } else {
        ((a as u128 + modulus as u128 - b as u128) % modulus as u128) as u64
    }
}

fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    if modulus == Q_RSS {
        reduce_mersenne_q(a as u128 * b as u128)
    } else {
        ((a as u128 * b as u128) % modulus as u128) as u64
    }
}

#[inline]
fn reduce_mersenne_q(value: u128) -> u64 {
    let modulus = Q_RSS as u128;
    let mut folded = (value & modulus) + (value >> Q_RSS_BITS);
    folded = (folded & modulus) + (folded >> Q_RSS_BITS);
    let mut reduced = folded as u64;
    if reduced >= Q_RSS {
        reduced -= Q_RSS;
    }
    reduced
}

fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exp >>= 1;
    }
    result
}

fn mod_inv(value: u64, modulus: u64) -> u64 {
    mod_pow(value, modulus - 2, modulus)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, status::StatusError> {
    let end = offset + 8;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| status::invalid_argument("payload decode overflow"))?;
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}
