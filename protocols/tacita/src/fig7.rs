//! Figure 7's two STE paths, without MKLHTS. The multi-slot equations and
//! common header are those of the pinned upstream batched STE implementation.
use crate::ste::{
    encode, read, wire, BoundShare, Ciphertext, Context, Dlog, Gt, Member, Result, TagShare,
};
use ark_bls12_381::{
    Bls12_381 as E, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_std::{UniformRand, Zero};
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use silent_batched_threshold_encryption::ste::{
    encryption,
    setup::{PartialDecryption, PartialDecryptionProof},
    utils::interp_mostly_zero,
};
use std::collections::BTreeSet;

pub const VERSION: &str = "fig7-batched-v2";
pub const SEED_BYTES: usize = 32;

// Retain only public material used by online decoding. The l*n*n hint matrices
// of the expanded upstream CRS are not needed after key preprocessing.
struct Slot {
    mask_base: Gt,
    gamma: G2,
    g: Vec<G1Affine>,
    h: Vec<G2Affine>,
    pk: Vec<G1Affine>,
    qx: Vec<G1Affine>,
    qhatx: Vec<G1Affine>,
    qz: Vec<G1Affine>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyCiphertext {
    pub context_id: [u8; 32],
    pub inner: Ciphertext,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SeedCiphertext {
    pub context_id: [u8; 32],
    pub bytes: Vec<Ciphertext>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response {
    pub context_id: [u8; 32],
    pub bound: BoundShare,
    pub tag: TagShare,
}

pub struct CommitteeMember {
    member: Member,
    answered: BTreeSet<[u8; 32]>,
}

pub struct BatchedContext {
    base: Context,
    slots: Vec<Slot>,
    pub context_id: [u8; 32],
}

fn msm_g(bases: &[G1Affine], scalars: &[Fr]) -> G1 {
    G1::msm(&bases[..scalars.len()], scalars).expect("validated MSM dimensions")
}
fn msm_h(bases: &[G2Affine], scalars: &[Fr]) -> G2 {
    G2::msm(&bases[..scalars.len()], scalars).expect("validated MSM dimensions")
}

impl Slot {
    fn scaled(base: &Context, r: Fr) -> Self {
        let scale = |p: G1| (p * r).into_affine();
        Self {
            mask_base: base.ek.e_gh[0] * r,
            gamma: base.crs.gamma_g2[0] * r,
            g: base.crs.powers_of_g[0]
                .iter()
                .map(|p| scale(p.into_group()))
                .collect(),
            h: base.crs.powers_of_h[0]
                .iter()
                .map(|p| (p.into_group() * r).into_affine())
                .collect(),
            pk: base.ak.lag_pks.iter().map(|p| scale(p.bls_pk[0])).collect(),
            qx: base
                .ak
                .lag_pks
                .iter()
                .map(|p| scale(p.sk_li_x[0]))
                .collect(),
            qhatx: base
                .ak
                .lag_pks
                .iter()
                .map(|p| scale(p.sk_li_minus0[0]))
                .collect(),
            qz: base.ak.agg_sk_li_lj_z[0]
                .iter()
                .map(|p| scale(*p))
                .collect(),
        }
    }
}

impl BatchedContext {
    pub fn setup<R: RngCore + CryptoRng>(
        committee: usize,
        threshold: usize,
        dimensions: usize,
        round_tag: &[u8],
        rng: &mut R,
    ) -> Result<(Self, Vec<CommitteeMember>)> {
        if dimensions == 0 || dimensions > 16384 {
            return Err("require 1..=16384 fixed KAHE key coordinates".into());
        }
        let (base, members) = Context::setup(committee, threshold, 1, round_tag, rng)?;
        // This is the same random cross-group basis construction as upstream
        // CRS::new. Ratios are setup trapdoor material and are NOT retained.
        let slots = (0..dimensions)
            .into_par_iter()
            .map(|j| {
                let mut rng = StdRng::from_entropy();
                let mut r = Fr::from(1u64);
                if j != 0 {
                    r = Fr::rand(&mut rng);
                    while r.is_zero() {
                        r = Fr::rand(&mut rng);
                    }
                }
                Slot::scaled(&base, r)
            })
            .collect::<Vec<_>>();
        let mut h = Sha256::new();
        h.update(VERSION.as_bytes());
        h.update(wire(&base.ek));
        h.update(wire(&base.aux_ek));
        h.update(wire(&round_tag.to_vec()));
        h.update((dimensions as u64).to_le_bytes());
        h.update((threshold as u64).to_le_bytes());
        for slot in &slots {
            h.update(wire(&slot.mask_base));
        }
        let context_id = h.finalize().into();
        Ok((
            Self {
                base,
                slots,
                context_id,
            },
            members
                .into_iter()
                .map(|member| CommitteeMember {
                    member,
                    answered: BTreeSet::new(),
                })
                .collect(),
        ))
    }

    pub fn dimensions(&self) -> usize {
        self.slots.len()
    }
    pub fn domain(&self) -> usize {
        self.base.crs.n
    }

    pub fn encrypt_key<R: RngCore + CryptoRng>(
        &self,
        key: &[i64],
        rng: &mut R,
    ) -> Result<KeyCiphertext> {
        if key.len() != self.dimensions() {
            return Err("wrong key dimension".into());
        }
        let (mut inner, randomness) = encryption::encrypt_with_witness(
            &self.base.ek,
            self.base.threshold,
            &self.base.crs,
            &vec![Gt::zero()],
            rng,
        );
        inner.ct = key
            .par_iter()
            .zip(&self.slots)
            .map(|(&x, slot)| slot.mask_base * randomness.s[4] + encode(x))
            .collect();
        Ok(KeyCiphertext {
            context_id: self.context_id,
            inner,
        })
    }

    pub fn validate_key(&self, ct: &KeyCiphertext) -> Result<()> {
        if ct.context_id != self.context_id
            || ct.inner.t != self.base.threshold
            || ct.inner.ct.len() != self.dimensions()
        {
            return Err("key ciphertext context, threshold or dimension mismatch".into());
        }
        Ok(())
    }

    pub fn aggregate(&self, cts: &[KeyCiphertext]) -> Result<KeyCiphertext> {
        if cts.is_empty() {
            return Err("empty aggregation".into());
        }
        for ct in cts {
            self.validate_key(ct)?;
        }
        let inner = cts.par_iter().map(|ct| ct.inner.clone()).reduce(
            || Ciphertext::zero(self.dimensions(), self.base.threshold),
            |a, b| a.add(&b),
        );
        Ok(KeyCiphertext {
            context_id: self.context_id,
            inner,
        })
    }

    pub fn encrypt_seed<R: RngCore + CryptoRng>(
        &self,
        seed: &[u8; SEED_BYTES],
        rng: &mut R,
    ) -> SeedCiphertext {
        // Exact uniform bit seed, not a hash of a GT message. Independent scalar
        // original-STE encryptions share only the public auxiliary tag.
        SeedCiphertext {
            context_id: self.context_id,
            bytes: seed
                .iter()
                .map(|b| self.base.encrypt_seed(encode(*b as i64), rng))
                .collect(),
        }
    }

    pub fn answer<R: RngCore + CryptoRng>(
        &self,
        member: &mut CommitteeMember,
        aggregate: &KeyCiphertext,
        rng: &mut R,
    ) -> Result<Response> {
        self.validate_key(aggregate)?;
        if member.answered.contains(&self.context_id) {
            return Err("committee already answered this context".into());
        }
        let id = member.member.id;
        if id >= self.base.committee {
            return Err("member outside committee".into());
        }
        // The share uses one common G1 base, while the proof transcript retains
        // the ENTIRE ciphertext, including every GT coordinate, as upstream does.
        let (pd, proof) = member.member.key.partial_decryption_with_proof(
            &aggregate.inner,
            &self.base.ak.lag_pks[id],
            &self.base.crs,
            rng,
        );
        let response = Response {
            context_id: self.context_id,
            bound: BoundShare {
                id: id as u64,
                pd: pd.pd,
                challenge: proof.challenge,
                response: proof.z_sk,
            },
            tag: self.base.tag_share(&member.member, rng)?,
        };
        member.answered.insert(self.context_id);
        Ok(response)
    }

    pub fn decrypt_seeds(
        &self,
        cts: &[SeedCiphertext],
        responses: &[Response],
    ) -> Result<Vec<Vec<u8>>> {
        self.validate_responses(responses)?;
        let tags = responses.iter().map(|s| s.tag.clone()).collect::<Vec<_>>();
        let decoder = self.base.prepare_tag_decoder(&tags)?;
        let dlog = Dlog::new(0, 255)?;
        cts.par_iter()
            .map(|ct| {
                if ct.context_id != self.context_id || ct.bytes.len() != SEED_BYTES {
                    return Err("seed ciphertext context or length mismatch".into());
                }
                ct.bytes
                    .iter()
                    .map(|byte| {
                        let group = decoder.decrypt(byte)?[0];
                        Ok(dlog.solve(group)? as u8)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect()
    }

    fn validate_responses(&self, responses: &[Response]) -> Result<()> {
        if responses
            .iter()
            .any(|s| s.context_id != self.context_id || s.bound.id != s.tag.id)
        {
            return Err("response context or member mismatch".into());
        }
        self.base
            .selected(responses.iter().map(|s| s.bound.id as usize))?;
        Ok(())
    }

    pub fn decrypt_key(&self, ct: &KeyCiphertext, responses: &[Response]) -> Result<Vec<Gt>> {
        self.validate_key(ct)?;
        self.validate_responses(responses)?;
        let chosen = self
            .base
            .selected(responses.iter().map(|s| s.bound.id as usize))?;
        if responses.par_iter().any(|s| {
            !PartialDecryptionProof::<E> {
                challenge: s.bound.challenge,
                z_sk: s.bound.response,
            }
            .verify(
                &PartialDecryption {
                    id: s.bound.id as usize,
                    pd: s.bound.pd,
                },
                &ct.inner,
                &self.base.ak.lag_pks[s.bound.id as usize],
                &self.base.crs,
            )
        }) {
            return Err("invalid ciphertext-bound proof".into());
        }
        let domain = Radix2EvaluationDomain::<Fr>::new(self.base.crs.n).unwrap();
        let roots = domain
            .elements()
            .enumerate()
            .filter(|(id, _)| chosen.binary_search(id).is_err())
            .map(|(_, x)| x)
            .collect::<Vec<_>>();
        let b = interp_mostly_zero(&roots);
        let n_inv = Fr::from(self.base.crs.n as u64).inverse().unwrap();
        let weights = (0..self.base.crs.n)
            .map(|id| {
                if chosen.binary_search(&id).is_ok() {
                    b.evaluate(&domain.element(id))
                } else {
                    Fr::zero()
                }
            })
            .collect::<Vec<_>>();
        let normalized = weights.iter().map(|w| *w * n_inv).collect::<Vec<_>>();
        let mut pd = G1::zero();
        for r in responses {
            pd += r.bound.pd * normalized[r.bound.id as usize];
        }
        let mut bhat = vec![Fr::zero(); self.base.threshold];
        bhat.extend(&b.coeffs);
        // At opening point 0, (B(X)-B(0))/X drops the constant coefficient.
        let q0 = &b.coeffs[1..];
        self.slots
            .par_iter()
            .enumerate()
            .map(|(j, slot)| {
                let lhs = vec![
                    -msm_g(&slot.pk, &normalized),
                    -msm_g(&slot.qz, &weights),
                    -msm_g(&slot.qx, &weights),
                    msm_g(&slot.qhatx, &weights),
                    -msm_g(&slot.g, &bhat),
                    -msm_g(&slot.g, q0),
                    ct.inner.sa1[0],
                    pd,
                ];
                let mut rhs = ct.inner.sa2.to_vec();
                rhs.extend([msm_h(&slot.h, &b.coeffs), slot.gamma]);
                Ok(ct.inner.ct[j] - E::multi_pairing(lhs, rhs))
            })
            .collect()
    }
}

/// Checked subgroup decoding is never bypassed on the new path.
pub fn read_key(mut bytes: &[u8]) -> Result<KeyCiphertext> {
    // Preserve the derived canonical wire layout, with independent checked GT
    // decodes in the caller's bounded Rayon pool. No unchecked points escape.
    let context_id = <[u8; 32]>::deserialize_compressed(&mut bytes).map_err(|e| e.to_string())?;
    let sa1 = <[G1; 2]>::deserialize_compressed(&mut bytes).map_err(|e| e.to_string())?;
    let sa2 = <[G2; 6]>::deserialize_compressed(&mut bytes).map_err(|e| e.to_string())?;
    let len = u64::deserialize_compressed(&mut bytes).map_err(|e| e.to_string())?;
    if len == 0 || len > 16384 {
        return Err("invalid serialized key dimension".into());
    }
    let size = Gt::zero().serialized_size(Compress::Yes);
    let payload_len = size.checked_mul(len as usize).ok_or("payload overflow")?;
    if bytes.len() < payload_len {
        return Err("truncated key payload".into());
    }
    let (payload, mut tail) = bytes.split_at(payload_len);
    let t = usize::deserialize_compressed(&mut tail).map_err(|e| e.to_string())?;
    if !tail.is_empty() {
        return Err("trailing key bytes".into());
    }
    let ct = payload
        .par_chunks_exact(size)
        .map(read::<Gt>)
        .collect::<Result<Vec<_>>>()?;
    Ok(KeyCiphertext {
        context_id,
        inner: Ciphertext { sa1, sa2, ct, t },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_public_material_matches_expanded_upstream_equations() {
        let mut rng = StdRng::seed_from_u64(901);
        let (expanded, members) = Context::setup(3, 2, 4, b"comparison-test", &mut rng).unwrap();
        let values = [-37, 0, 1, 37];
        let ct = expanded.encrypt(&values.map(encode), &mut rng).unwrap();
        let shares = members
            .iter()
            .rev()
            .take(2)
            .map(|m| expanded.bound_share(m, &ct, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let reference = expanded.decrypt_bound(&ct, &shares).unwrap();
        // Extract precisely the public entries used by the compact decoder.
        let slots = (0..4)
            .map(|j| Slot {
                mask_base: expanded.ek.e_gh[j],
                gamma: expanded.crs.gamma_g2[j],
                g: expanded.crs.powers_of_g[j].clone(),
                h: expanded.crs.powers_of_h[j].clone(),
                pk: expanded
                    .ak
                    .lag_pks
                    .iter()
                    .map(|p| p.bls_pk[j].into_affine())
                    .collect(),
                qx: expanded
                    .ak
                    .lag_pks
                    .iter()
                    .map(|p| p.sk_li_x[j].into_affine())
                    .collect(),
                qhatx: expanded
                    .ak
                    .lag_pks
                    .iter()
                    .map(|p| p.sk_li_minus0[j].into_affine())
                    .collect(),
                qz: expanded.ak.agg_sk_li_lj_z[j]
                    .iter()
                    .map(|p| p.into_affine())
                    .collect(),
            })
            .collect();
        let responses = shares
            .into_iter()
            .zip(members.iter().rev())
            .map(|(bound, m)| Response {
                context_id: [0; 32],
                bound,
                tag: expanded.tag_share(m, &mut rng).unwrap(),
            })
            .collect::<Vec<_>>();
        let ctx = BatchedContext {
            base: expanded,
            slots,
            context_id: [0; 32],
        };
        assert_eq!(
            ctx.decrypt_key(
                &KeyCiphertext {
                    context_id: [0; 32],
                    inner: ct
                },
                &responses
            )
            .unwrap(),
            reference
        );
    }
}
