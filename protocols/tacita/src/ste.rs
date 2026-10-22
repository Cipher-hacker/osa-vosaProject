use ark_bls12_381::{Bls12_381 as E, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, PrimeGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, Field, PrimeField};
use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, Zero};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use silent_batched_threshold_encryption::ste::{
    aggregate::{AggregateKey, EncryptionKey},
    crs::CRS,
    decryption::agg_dec,
    encryption,
    setup::{PartialDecryption, PartialDecryptionProof, SecretKey},
    utils::interp_mostly_zero,
};
use std::collections::{BTreeSet, HashMap};

pub type Gt = PairingOutput<E>;
pub type Ciphertext = encryption::Ciphertext<E>;
pub type Result<T, Error = String> = std::result::Result<T, Error>;

pub fn wire<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes)
        .expect("serialize to memory");
    bytes
}
pub fn read<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    let mut remaining = bytes;
    let result = T::deserialize_compressed(&mut remaining).map_err(|e| e.to_string())?;
    if !remaining.is_empty() {
        return Err("trailing bytes".into());
    }
    Ok(result)
}

// All secret material lives in the committee fixture, never in Context/server.
pub struct Member {
    pub id: usize,
    scalar: Fr,
    pub(crate) key: SecretKey<E>,
}
#[derive(Clone)]
pub struct Context {
    pub committee: usize,
    pub threshold: usize,
    pub crs: CRS<E>,
    pub ak: AggregateKey<E>,
    pub ek: EncryptionKey<E>,
    pub aux_crs: CRS<E>,
    pub aux_ek: EncryptionKey<E>,
    pub tag: Vec<u8>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BoundShare {
    pub id: u64,
    pub pd: G1,
    pub challenge: Fr,
    pub response: Fr,
}
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct TagShare {
    pub id: u64,
    pub pd: Vec<G2>,
    pub challenge: Fr,
    pub response: Fr,
}

pub struct TagDecoder {
    threshold: usize,
    lhs: Vec<Vec<G1>>,
    b_g2: Vec<G2>,
    tag_pd: Vec<G2>,
}
impl TagDecoder {
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<Vec<Gt>> {
        if ct.t != self.threshold || ct.ct.len() != self.lhs.len() {
            return Err("auxiliary ciphertext shape mismatch".into());
        }
        Ok((0..self.lhs.len())
            .map(|j| {
                let mut lhs = self.lhs[j].clone();
                lhs.extend([ct.sa1[0], ct.sa1[1]]);
                let mut rhs = ct.sa2.to_vec();
                rhs.extend([self.b_g2[j], self.tag_pd[j]]);
                ct.ct[j] - E::multi_pairing(lhs, rhs)
            })
            .collect())
    }
}

fn h2(tag: &[u8], slot: usize) -> G2 {
    type H = MapToCurveBasedHasher<
        G2,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_381::g2::Config>,
    >;
    let hasher = H::new(b"TACITA_STE_AUX_TAG_BLS12381G2_XMD:SHA-256_SSWU_RO_V1").unwrap();
    let mut msg = tag.to_vec();
    msg.extend_from_slice(&(slot as u64).to_le_bytes());
    hasher.hash(&msg).unwrap().into_group()
}

impl Context {
    pub fn setup<R: RngCore + CryptoRng>(
        committee: usize,
        threshold: usize,
        slots: usize,
        tag: &[u8],
        rng: &mut R,
    ) -> Result<(Self, Vec<Member>)> {
        if committee < 2
            || threshold == 0
            || threshold > committee
            || slots == 0
            || slots > 64
            || tag.is_empty()
        {
            return Err("require committee >= 2, 1 <= threshold <= committee, 1 <= slots <= 64, nonempty tag".into());
        }
        let domain = committee
            .checked_next_power_of_two()
            .ok_or("committee overflow")?;
        let ratios: Vec<_> = (0..slots)
            .map(|i| {
                if i == 0 {
                    Fr::from(1u64)
                } else {
                    Fr::rand(rng)
                }
            })
            .collect();
        let gs = ratios.iter().map(|r| G1::generator() * r).collect();
        let hs = ratios.iter().map(|r| G2::generator() * r).collect();
        let mut crs =
            CRS::<E>::deterministic_new(domain, slots, Fr::rand(rng), gs, hs, Fr::rand(rng));
        // Slot bases must preserve their cross-group ratios for shared randomness.
        // Distinct tags keep reusable auxiliary shares from decrypting input ciphertexts.
        let mut aux_tag = tag.to_vec();
        aux_tag.extend_from_slice(b"/auxiliary");
        crs.gamma_g2 = ratios.iter().map(|r| h2(tag, 0) * r).collect();
        let mut aux_crs = crs.clone();
        aux_crs.gamma_g2 = ratios.iter().map(|r| h2(&aux_tag, 0) * r).collect();
        let members: Vec<_> = (0..committee)
            .map(|id| {
                let mut scalar = Fr::rand(rng);
                while scalar.is_zero() {
                    scalar = Fr::rand(rng);
                }
                Member {
                    id,
                    scalar,
                    key: SecretKey::from_scalar(scalar, id),
                }
            })
            .collect();
        // Dummy positions have public zero keys and never provide decryption shares.
        let pks = (0..domain)
            .map(|id| {
                if id < committee {
                    members[id].key.get_lagrange_pk(id, &crs)
                } else {
                    SecretKey::<E>::from_scalar(Fr::zero(), id).get_lagrange_pk(id, &crs)
                }
            })
            .collect();
        let (ak, ek) = AggregateKey::new(pks, &crs);
        let mut aux_ek = ek.clone();
        aux_ek.gamma_g2 = aux_crs.gamma_g2.clone();
        Ok((
            Self {
                committee,
                threshold,
                crs,
                ak,
                ek,
                aux_crs,
                aux_ek,
                tag: tag.to_vec(),
            },
            members,
        ))
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        messages: &[Gt],
        rng: &mut R,
    ) -> Result<Ciphertext> {
        if messages.len() != self.crs.l {
            return Err("wrong message slot count".into());
        }
        Ok(encryption::encrypt(
            &self.ek,
            self.threshold,
            &self.crs,
            &messages.to_vec(),
            rng,
        ))
    }
    pub fn validate_ct(&self, ct: &Ciphertext) -> Result<()> {
        if ct.t != self.threshold || ct.ct.len() != self.crs.l {
            return Err("ciphertext parameters do not match context".into());
        }
        Ok(())
    }
    pub fn encrypt_seed<R: RngCore + CryptoRng>(&self, seed: Gt, rng: &mut R) -> Ciphertext {
        let mut values = vec![Gt::zero(); self.crs.l];
        values[0] = seed;
        encryption::encrypt(&self.aux_ek, self.threshold, &self.aux_crs, &values, rng)
    }
    pub fn aggregate(&self, cts: &[Ciphertext]) -> Result<Ciphertext> {
        if cts.is_empty() {
            return Err("empty aggregation".into());
        }
        let mut sum = Ciphertext::zero(self.crs.l, self.threshold);
        for ct in cts {
            self.validate_ct(ct)?;
            sum = sum.add(ct);
        }
        Ok(sum)
    }
    pub fn bound_share<R: RngCore + CryptoRng>(
        &self,
        member: &Member,
        ct: &Ciphertext,
        rng: &mut R,
    ) -> Result<BoundShare> {
        self.validate_ct(ct)?;
        if member.id >= self.committee {
            return Err("member outside committee".into());
        }
        let (pd, proof) = member.key.partial_decryption_with_proof(
            ct,
            &self.ak.lag_pks[member.id],
            &self.crs,
            rng,
        );
        Ok(BoundShare {
            id: member.id as u64,
            pd: pd.pd,
            challenge: proof.challenge,
            response: proof.z_sk,
        })
    }
    pub fn verify_bound(&self, ct: &Ciphertext, share: &BoundShare) -> bool {
        let id = share.id as usize;
        self.validate_ct(ct).is_ok()
            && id < self.committee
            && PartialDecryptionProof::<E> {
                challenge: share.challenge,
                z_sk: share.response,
            }
            .verify(
                &PartialDecryption { id, pd: share.pd },
                ct,
                &self.ak.lag_pks[id],
                &self.crs,
            )
    }
    pub(crate) fn selected(&self, ids: impl Iterator<Item = usize>) -> Result<Vec<usize>> {
        let mut set = BTreeSet::new();
        for id in ids {
            if id >= self.committee || !set.insert(id) {
                return Err("invalid or duplicate member id".into());
            }
        }
        if set.len() < self.threshold {
            return Err("fewer than threshold valid shares".into());
        }
        // Upstream reconstruction requires exactly t responders, not all available.
        Ok(set.into_iter().take(self.threshold).collect())
    }
    pub fn decrypt_bound(&self, ct: &Ciphertext, shares: &[BoundShare]) -> Result<Vec<Gt>> {
        self.validate_ct(ct)?;
        let chosen = self.selected(shares.iter().map(|s| s.id as usize))?;
        if shares.iter().any(|s| !self.verify_bound(ct, s)) {
            return Err("invalid ciphertext-bound proof".into());
        }
        let mut pds = vec![PartialDecryption::zero(); self.crs.n];
        let mut selector = vec![false; self.crs.n];
        for s in shares {
            let id = s.id as usize;
            if chosen.binary_search(&id).is_ok() {
                pds[id] = PartialDecryption { id, pd: s.pd };
                selector[id] = true;
            }
        }
        Ok(agg_dec(&pds, ct, &selector, &self.ak, &self.crs))
    }

    // Original STE path: sk * tag in G2 can be reused for individual seed ciphertexts.
    // The modified path above instead binds a G1 share to one aggregate ciphertext.
    fn tag_challenge(&self, id: usize, pd: &[G2], a_pk: G1, a_pd: &[G2]) -> Fr {
        let mut h = Sha256::new();
        h.update(b"TACITA_STE_TAG_SHARE_DLEQ_V1");
        h.update((self.tag.len() as u64).to_le_bytes());
        h.update(&self.tag);
        h.update((id as u64).to_le_bytes());
        h.update(wire(&self.crs.gen_g[0]));
        h.update(wire(&self.ak.lag_pks[id].bls_pk[0]));
        h.update(wire(&self.aux_crs.gamma_g2));
        h.update(wire(&pd.to_vec()));
        h.update(wire(&a_pk));
        h.update(wire(&a_pd.to_vec()));
        Fr::from_le_bytes_mod_order(&h.finalize())
    }
    pub fn tag_share<R: RngCore + CryptoRng>(
        &self,
        member: &Member,
        rng: &mut R,
    ) -> Result<TagShare> {
        if member.id >= self.committee {
            return Err("member outside committee".into());
        }
        let pd: Vec<_> = self
            .aux_crs
            .gamma_g2
            .iter()
            .map(|g| *g * member.scalar)
            .collect();
        let nonce = Fr::rand(rng);
        let a_pk = self.crs.gen_g[0] * nonce;
        let a_pd: Vec<_> = self.aux_crs.gamma_g2.iter().map(|g| *g * nonce).collect();
        let challenge = self.tag_challenge(member.id, &pd, a_pk, &a_pd);
        Ok(TagShare {
            id: member.id as u64,
            pd,
            challenge,
            response: nonce + challenge * member.scalar,
        })
    }
    pub fn verify_tag(&self, share: &TagShare) -> bool {
        let id = share.id as usize;
        if id >= self.committee || share.pd.len() != self.crs.l {
            return false;
        }
        let a_pk =
            self.crs.gen_g[0] * share.response - self.ak.lag_pks[id].bls_pk[0] * share.challenge;
        let a_pd: Vec<_> = self
            .aux_crs
            .gamma_g2
            .iter()
            .zip(&share.pd)
            .map(|(g, pd)| *g * share.response - *pd * share.challenge)
            .collect();
        self.tag_challenge(id, &share.pd, a_pk, &a_pd) == share.challenge
    }
    pub fn decrypt_tag(&self, ct: &Ciphertext, shares: &[TagShare]) -> Result<Vec<Gt>> {
        self.validate_ct(ct)?;
        self.prepare_tag_decoder(shares)?.decrypt(ct)
    }
    pub fn prepare_tag_decoder(&self, shares: &[TagShare]) -> Result<TagDecoder> {
        let chosen = self.selected(shares.iter().map(|s| s.id as usize))?;
        if shares.iter().any(|s| !self.verify_tag(s)) {
            return Err("invalid tag-bound proof".into());
        }
        let selector: Vec<_> = (0..self.crs.n)
            .map(|id| chosen.binary_search(&id).is_ok())
            .collect();
        let domain = Radix2EvaluationDomain::<Fr>::new(self.crs.n).unwrap();
        let roots: Vec<_> = domain
            .elements()
            .enumerate()
            .filter(|(i, _)| !selector[*i])
            .map(|(_, x)| x)
            .collect();
        let b = interp_mostly_zero(&roots);
        let n_inv = Fr::from(self.crs.n as u64).inverse().unwrap();
        let mut aggregated = vec![G2::zero(); self.crs.l];
        for s in shares {
            let id = s.id as usize;
            if selector[id] {
                let weight = b.evaluate(&domain.element(id)) * n_inv;
                for (sum, pd) in aggregated.iter_mut().zip(&s.pd) {
                    *sum += *pd * weight;
                }
            }
        }
        // Fixed interpolation witnesses can be reused for every seed ciphertext.
        // Equations follow upstream ste/decryption.rs (MIT); only ciphertext pairings
        // remain in TagDecoder::decrypt, and share proofs are verified once.
        let mut bhat = vec![Fr::zero(); self.threshold];
        bhat.extend(&b.coeffs);
        let mut lhs = Vec::new();
        let mut b_g2 = Vec::new();
        for j in 0..self.crs.l {
            let mut apk = G1::zero();
            let mut qx = G1::zero();
            let mut qhatx = G1::zero();
            let mut qz = G1::zero();
            for &id in &chosen {
                let w = b.evaluate(&domain.element(id));
                let pk = &self.ak.lag_pks[id];
                apk += pk.bls_pk[j] * (w * n_inv);
                qx += pk.sk_li_x[j] * w;
                qhatx += pk.sk_li_minus0[j] * w;
                qz += self.ak.agg_sk_li_lj_z[j][id] * w;
            }
            lhs.push(vec![
                -apk,
                -qz,
                -qx,
                qhatx,
                -self.aux_crs.commit_g1(&bhat, j),
                -self
                    .aux_crs
                    .compute_opening_proof(&b.coeffs, &Fr::zero(), j),
            ]);
            b_g2.push(self.aux_crs.commit_g2(&b.coeffs, j));
        }
        Ok(TagDecoder {
            threshold: self.threshold,
            lhs,
            b_g2,
            tag_pd: aggregated,
        })
    }
}

// Exact signed BSGS with complete canonical keys and a checked final equation.
pub struct Dlog {
    min: i64,
    max: i64,
    width: u64,
    table: HashMap<Vec<u8>, u64>,
    stride: Gt,
}
impl Dlog {
    pub fn new(min: i64, max: i64) -> Result<Self> {
        if min > max {
            return Err("invalid DLog bounds".into());
        }
        let span = (max as i128 - min as i128 + 1) as u128;
        if span > (1u128 << 40) {
            return Err("DLog range exceeds research benchmark limit".into());
        }
        let mut width = (span as f64).sqrt().ceil() as u64;
        while (width as u128) * (width as u128) < span {
            width += 1;
        }
        let mut table = HashMap::new();
        let mut p = Gt::zero();
        for j in 0..width {
            table.insert(wire(&p), j);
            p += Gt::generator();
        }
        Ok(Self {
            min,
            max,
            width,
            table,
            stride: Gt::generator() * Fr::from(width),
        })
    }
    pub fn solve(&self, target: Gt) -> Result<i64> {
        let mut p = target - encode(self.min);
        for i in 0..=self.width {
            if let Some(j) = self.table.get(&wire(&p)) {
                let value = self.min as i128 + (i as i128) * (self.width as i128) + *j as i128;
                if value <= self.max as i128
                    && value >= self.min as i128
                    && encode(value as i64) == target
                {
                    return Ok(value as i64);
                }
            }
            p -= self.stride;
        }
        Err("DLog outside declared input bounds".into())
    }
}
pub fn scalar(value: i64) -> Fr {
    if value < 0 {
        -Fr::from(value.unsigned_abs())
    } else {
        Fr::from(value as u64)
    }
}
pub fn encode(value: i64) -> Gt {
    Gt::generator() * scalar(value)
}
pub fn seed_mask(seed: Gt, slot: usize) -> Fr {
    let mut h = Sha256::new();
    h.update(b"TACITA_STE_MASK_V1");
    h.update(wire(&seed));
    h.update((slot as u64).to_le_bytes());
    Fr::from_le_bytes_mod_order(&h.finalize())
}
