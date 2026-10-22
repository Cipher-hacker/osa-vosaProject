use crate::{
    benchmark::{Config, Fixture, Report},
    fig7::*,
    ste::{read, wire, Dlog, Result},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Serialize)]
pub struct Fig7Report {
    #[serde(flatten)]
    pub common: Report,
    pub implementation_version: &'static str,
    pub main_ciphertexts_per_client: usize,
    pub main_headers_per_client: usize,
    pub key_coordinates: usize,
    pub slot_policy: &'static str,
    pub seed_bytes: usize,
    pub bound_shares_per_member: usize,
    pub tag_shares_per_member: usize,
    pub server_parse_aggregate_s: f64,
    pub server_seed_recovery_s: f64,
    pub server_key_recovery_s: f64,
    pub committee_batch_wall_s: f64,
    pub round_context_id: Vec<u8>,
    pub seed_encoding: &'static str,
    pub group_validation: &'static str,
}

struct Upload {
    key: Vec<u8>,
    seed: Vec<u8>,
    elapsed: f64,
}
fn upload(ctx: &BatchedContext, key: &[i64], seed: &[u8]) -> Result<Upload> {
    let start = Instant::now();
    let mut rng = StdRng::from_entropy();
    let seed: [u8; SEED_BYTES] = seed.try_into().map_err(|_| "expected 32 seed bytes")?;
    let key = wire(&ctx.encrypt_key(key, &mut rng)?);
    let seed = wire(&ctx.encrypt_seed(&seed, &mut rng));
    Ok(Upload {
        key,
        seed,
        elapsed: start.elapsed().as_secs_f64(),
    })
}

pub fn run(config: Config, fixture: Fixture) -> Result<Fig7Report> {
    if config.active_clients == 0
        || config.active_clients > config.n_clients
        || config.threads == 0
        || config.input_bound <= 0
        || config.mask_inputs
        || config.slots != 1
    {
        return Err("fig7 requires valid counts, slots=1 (one whole-key ciphertext), unmasked KAHE key inputs".into());
    }
    if fixture.values.len() != config.active_clients || fixture.values[0].is_empty() {
        return Err("invalid KAHE key fixture count".into());
    }
    let dimensions = fixture.values[0].len();
    if fixture.values.iter().any(|v| {
        v.len() != dimensions
            || v.iter()
                .any(|x| x.unsigned_abs() > config.input_bound as u64)
    }) {
        return Err(
            "ragged keys or coefficient outside declared DLog bound; no clipping performed".into(),
        );
    }
    let seeds = fixture.seeds.ok_or("fig7 requires uniform byte seeds")?;
    if seeds.len() != config.active_clients || seeds.iter().any(|s| s.len() != SEED_BYTES) {
        return Err("wrong seed count or encoding; legacy GT seeds are not accepted".into());
    }
    let mut expected = vec![0i64; dimensions];
    for key in &fixture.values {
        for (s, x) in expected.iter_mut().zip(key) {
            *s = s.checked_add(*x).ok_or("sum overflow")?;
        }
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build()
        .map_err(|e| e.to_string())?;
    pool.install(|| {
        let setup_start = Instant::now();
        let mut rng = StdRng::from_entropy();
        let mut nonce = [0u8;32]; rng.fill_bytes(&mut nonce);
        let mut h = Sha256::new(); h.update(VERSION); h.update(nonce);
        h.update(serde_json::to_vec(&config).map_err(|e| e.to_string())?);
        let tag = h.finalize();
        eprintln!("[fig7] setup: fixed_key_coordinates={dimensions} threads={}", config.threads);
        let (ctx, mut members) = BatchedContext::setup(config.committee_size, config.threshold, dimensions, &tag, &mut rng)?;
        let bound = config.input_bound.checked_mul(config.active_clients.try_into().map_err(|_| "client count overflow")?)
            .ok_or("DLog bound overflow")?;
        let dlog = Dlog::new(-bound, bound)?;
        let setup_s = setup_start.elapsed().as_secs_f64();
        // One-thread uncontended client sample; parallel batch is a separate metric.
        let serial = rayon::ThreadPoolBuilder::new().num_threads(1).build().map_err(|e| e.to_string())?;
        let client_compute_s = serial.install(|| upload(&ctx, &fixture.values[0], &seeds[0]))?.elapsed;
        eprintln!("[fig7] client batch starting; setup_s={setup_s:.3}");
        let online_start = Instant::now();
        let start = Instant::now();
        let uploads = fixture.values.par_iter().zip(&seeds).map(|(key, seed)| upload(&ctx, key, seed))
            .collect::<Result<Vec<_>>>()?;
        let client_batch_wall_s = start.elapsed().as_secs_f64();
        let client_observed_mean_s = uploads.iter().map(|u| u.elapsed).sum::<f64>() / config.active_clients as f64;
        let client_to_server_bytes = uploads.iter().map(|u| u.key.len() + u.seed.len()).sum();
        eprintln!("[fig7] checked deserialization and aggregation; client_batch_s={client_batch_wall_s:.3}");
        let start = Instant::now();
        let keys = uploads.par_iter().map(|u| read_key(&u.key)).collect::<Result<Vec<_>>>()?;
        let aggregate = ctx.aggregate(&keys)?;
        drop(keys);
        let seed_cts = uploads.par_iter().map(|u| read::<SeedCiphertext>(&u.seed)).collect::<Result<Vec<_>>>()?;
        let request = wire(&aggregate);
        // Context ID binds setup and both domain-separated tags, already distributed.
        let server_to_committee_bytes = request.len() * config.threshold;
        let server_parse_aggregate_s = start.elapsed().as_secs_f64();
        eprintln!("[fig7] committee; parse_aggregate_s={server_parse_aggregate_s:.3}");
        let start = Instant::now();
        let mut responses = Vec::new();
        for member in members.iter_mut().rev().take(config.threshold) {
            let request = read_key(&request)?;
            responses.push(wire(&ctx.answer(member, &request, &mut rng)?));
        }
        let committee_batch_wall_s = start.elapsed().as_secs_f64();
        let committee_to_server_bytes = responses.iter().map(Vec::len).sum();
        let start = Instant::now();
        let responses = responses.iter().map(|s| read::<Response>(s)).collect::<Result<Vec<_>>>()?;
        let recovered_mask_seeds = ctx.decrypt_seeds(&seed_cts, &responses)?;
        let server_seed_recovery_s = start.elapsed().as_secs_f64();
        eprintln!("[fig7] aggregate key recovery; seed_recovery_s={server_seed_recovery_s:.3}");
        let start = Instant::now();
        let groups = ctx.decrypt_key(&aggregate, &responses)?;
        let dlog_start = Instant::now();
        let decoded_sum = groups.par_iter().map(|g| dlog.solve(*g)).collect::<Result<Vec<_>>>()?;
        let server_dlog_s = dlog_start.elapsed().as_secs_f64();
        let server_key_recovery_s = start.elapsed().as_secs_f64();
        let online_wall_s = online_start.elapsed().as_secs_f64();
        if decoded_sum != expected || recovered_mask_seeds != seeds { return Err("key or seed recovery mismatch".into()); }
        eprintln!("[fig7] STE correctness=pass; KAHE finalization still required by driver");
        Ok(Fig7Report {
            implementation_version: VERSION, main_ciphertexts_per_client: 1, main_headers_per_client: 1,
            key_coordinates: dimensions, slot_policy: "one_ciphertext_with_all_key_coordinates", seed_bytes: SEED_BYTES, bound_shares_per_member: 1,
            tag_shares_per_member: 1, server_parse_aggregate_s, server_seed_recovery_s,
            server_key_recovery_s, committee_batch_wall_s, round_context_id: ctx.context_id.to_vec(),
            seed_encoding: "32 independent original-STE byte ciphertexts; exact 256-bit random seed",
            group_validation: "checked canonical subgroup decoding",
            common: Report {
                protocol: "TACITA-STE-Fig7-v2", implementation_scope: "batched_STE_key_and_original_STE_seed_no_MKLHTS",
                mklhts_enabled: false, input_soundness: false, ste_share_proofs: true,
                interpolation_domain: ctx.domain(), plaintext_dimensions: dimensions, setup_s,
                client_compute_s, client_observed_mean_s, client_batch_wall_s,
                committee_compute_s: committee_batch_wall_s / config.threshold as f64,
                server_compute_s: server_parse_aggregate_s + server_seed_recovery_s + server_key_recovery_s,
                server_dlog_s, online_wall_s, client_to_server_bytes, server_to_committee_bytes,
                committee_to_server_bytes, total_bytes: client_to_server_bytes + server_to_committee_bytes + committee_to_server_bytes,
                decoded_sum, recovered_mask_seeds, correctness: "pass", config: Config { slots:dimensions, ..config },
            },
        })
    })
}
