use crate::ste::*;
use ark_bls12_381::Fr;
use ark_ec::PrimeGroup;
use ark_std::{UniformRand, Zero};
use rand::{rngs::StdRng, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub n_clients: usize,
    pub active_clients: usize,
    pub committee_size: usize,
    pub threshold: usize,
    pub slots: usize,
    pub threads: usize,
    pub input_bound: i64,
    pub mask_inputs: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            n_clients: 1000,
            active_clients: 800,
            committee_size: 50,
            threshold: 40,
            slots: 1,
            threads: 32,
            input_bound: 255,
            mask_inputs: true,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Fixture {
    pub values: Vec<Vec<i64>>,
    pub seeds: Option<Vec<Vec<u8>>>,
}
#[derive(Serialize)]
pub struct Report {
    pub protocol: &'static str,
    pub implementation_scope: &'static str,
    pub mklhts_enabled: bool,
    pub input_soundness: bool,
    pub ste_share_proofs: bool,
    pub config: Config,
    pub interpolation_domain: usize,
    pub plaintext_dimensions: usize,
    pub setup_s: f64,
    pub client_compute_s: f64,
    pub client_observed_mean_s: f64,
    pub client_batch_wall_s: f64,
    pub committee_compute_s: f64,
    pub server_compute_s: f64,
    pub server_dlog_s: f64,
    pub online_wall_s: f64,
    pub client_to_server_bytes: usize,
    pub server_to_committee_bytes: usize,
    pub committee_to_server_bytes: usize,
    pub total_bytes: usize,
    pub decoded_sum: Vec<i64>,
    pub recovered_mask_seeds: Vec<Vec<u8>>,
    pub correctness: &'static str,
}
pub fn mask_seed(seed: Gt) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"TACITA_STE_KAHE_MASK_SEED_V1");
    h.update(wire(&seed));
    h.finalize().to_vec()
}
struct Upload {
    cts: Vec<Vec<u8>>,
    seed_ct: Vec<u8>,
    seed: Gt,
    elapsed: f64,
}
fn upload(
    ctx: &Context,
    values: &[i64],
    supplied_seed: Option<&Vec<u8>>,
    masked: bool,
) -> Result<Upload> {
    let started = Instant::now();
    let mut rng = StdRng::from_entropy();
    let seed = match supplied_seed {
        Some(bytes) => read(bytes)?,
        None => Gt::rand(&mut rng),
    };
    let mut cts = Vec::new();
    for (block, chunk) in values.chunks(ctx.crs.l).enumerate() {
        let mut pts = vec![Gt::zero(); ctx.crs.l];
        for (j, &value) in chunk.iter().enumerate() {
            pts[j] = encode(value);
            if masked {
                pts[j] += Gt::generator() * seed_mask(seed, block * ctx.crs.l + j);
            }
        }
        cts.push(wire(&ctx.encrypt(&pts, &mut rng)?));
    }
    let seed_ct = wire(&ctx.encrypt_seed(seed, &mut rng));
    Ok(Upload {
        cts,
        seed_ct,
        seed,
        elapsed: started.elapsed().as_secs_f64(),
    })
}
pub fn run(config: Config, fixture: Option<Fixture>) -> Result<Report> {
    if config.active_clients == 0
        || config.active_clients > config.n_clients
        || config.threads == 0
        || config.input_bound <= 0
    {
        return Err("invalid client counts, threads, or input bound".into());
    }
    let fixture = fixture.unwrap_or_else(|| Fixture {
        values: (0..config.active_clients)
            .map(|i| vec![(i as i64 % (config.input_bound + 1))])
            .collect(),
        seeds: None,
    });
    if fixture.values.len() != config.active_clients || fixture.values[0].is_empty() {
        return Err("wrong input count or empty vectors".into());
    }
    let dimensions = fixture.values[0].len();
    if fixture.values.iter().any(|v| {
        v.len() != dimensions
            || v.iter()
                .any(|x| x.unsigned_abs() > config.input_bound as u64)
    }) {
        return Err("ragged vectors or input outside declared bound".into());
    }
    if fixture
        .seeds
        .as_ref()
        .is_some_and(|s| s.len() != config.active_clients)
    {
        return Err("wrong seed count".into());
    }
    let mut expected = vec![0i64; dimensions];
    for v in &fixture.values {
        for (s, x) in expected.iter_mut().zip(v) {
            *s = s.checked_add(*x).ok_or("sum overflow")?;
        }
    }
    let setup_start = Instant::now();
    let mut rng = StdRng::from_entropy();
    let (ctx, members) = Context::setup(
        config.committee_size,
        config.threshold,
        config.slots,
        b"tacita-ste-bench/v1/round-1",
        &mut rng,
    )?;
    let bound = config
        .input_bound
        .checked_mul(config.active_clients as i64)
        .ok_or("DLog bound overflow")?;
    let dlog = Dlog::new(-bound, bound)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build()
        .map_err(|e| e.to_string())?;
    let setup_s = setup_start.elapsed().as_secs_f64();
    // Standalone uncontended sample matches the existing unified driver's client metric.
    let client_compute_s = upload(
        &ctx,
        &fixture.values[0],
        fixture.seeds.as_ref().map(|s| &s[0]),
        config.mask_inputs,
    )?
    .elapsed;
    let online_start = Instant::now();
    let batch = Instant::now();
    let uploads: Vec<Upload> = pool.install(|| {
        fixture
            .values
            .par_iter()
            .enumerate()
            .map(|(i, v)| {
                upload(
                    &ctx,
                    v,
                    fixture.seeds.as_ref().map(|s| &s[i]),
                    config.mask_inputs,
                )
            })
            .collect::<Result<Vec<_>>>()
    })?;
    let client_batch_wall_s = batch.elapsed().as_secs_f64();
    let client_observed_mean_s =
        uploads.iter().map(|u| u.elapsed).sum::<f64>() / uploads.len() as f64;
    let client_to_server_bytes = uploads
        .iter()
        .map(|u| u.cts.iter().map(Vec::len).sum::<usize>() + u.seed_ct.len())
        .sum();

    let start = Instant::now();
    let blocks = dimensions.div_ceil(config.slots);
    let mut aggregates = Vec::new();
    for block in 0..blocks {
        let parsed = uploads
            .iter()
            .map(|u| read::<Ciphertext>(&u.cts[block]))
            .collect::<Result<Vec<_>>>()?;
        aggregates.push(wire(&ctx.aggregate(&parsed)?));
    }
    let seed_cts = uploads
        .iter()
        .map(|u| read::<Ciphertext>(&u.seed_ct))
        .collect::<Result<Vec<_>>>()?;
    // Explicit public tags are part of each routed request; setup keys are excluded.
    let route_bytes = aggregates.iter().map(Vec::len).sum::<usize>()
        + wire(&ctx.crs.gamma_g2).len()
        + wire(&ctx.aux_crs.gamma_g2).len();
    let server_to_committee_bytes = route_bytes * config.threshold;
    let mut server_compute_s = start.elapsed().as_secs_f64();
    let mut committee_times = Vec::new();
    let mut responses = Vec::new();
    // Non-prefix members exercise the actual threshold selection and padding.
    for member in members.iter().rev().take(config.threshold) {
        let start = Instant::now();
        let mut local_rng = StdRng::from_entropy();
        let main = aggregates
            .iter()
            .map(|bytes| {
                let ct: Ciphertext = read(bytes)?;
                Ok(wire(&ctx.bound_share(member, &ct, &mut local_rng)?))
            })
            .collect::<Result<Vec<_>>>()?;
        let tag = wire(&ctx.tag_share(member, &mut local_rng)?);
        committee_times.push(start.elapsed().as_secs_f64());
        responses.push((main, tag));
    }
    let committee_to_server_bytes = responses
        .iter()
        .map(|(v, t)| v.iter().map(Vec::len).sum::<usize>() + t.len())
        .sum();
    let start = Instant::now();
    let tags = responses
        .iter()
        .map(|(_, t)| read::<TagShare>(t))
        .collect::<Result<Vec<_>>>()?;
    let tag_decoder = ctx.prepare_tag_decoder(&tags)?;
    let recovered = seed_cts
        .iter()
        .map(|ct| tag_decoder.decrypt(ct).map(|v| v[0]))
        .collect::<Result<Vec<_>>>()?;
    let mut groups = Vec::new();
    for (block, agg) in aggregates.iter().enumerate() {
        let shares = responses
            .iter()
            .map(|(v, _)| read::<BoundShare>(&v[block]))
            .collect::<Result<Vec<_>>>()?;
        groups.extend(ctx.decrypt_bound(&read::<Ciphertext>(agg)?, &shares)?);
    }
    groups.truncate(dimensions);
    if config.mask_inputs {
        for (j, value) in groups.iter_mut().enumerate() {
            let mask = recovered
                .iter()
                .fold(Fr::zero(), |sum, seed| sum + seed_mask(*seed, j));
            *value -= Gt::generator() * mask;
        }
    }
    let dlog_start = Instant::now();
    let decoded_sum = groups
        .iter()
        .map(|g| dlog.solve(*g))
        .collect::<Result<Vec<_>>>()?;
    let server_dlog_s = dlog_start.elapsed().as_secs_f64();
    let recovered_mask_seeds = recovered.iter().map(|s| mask_seed(*s)).collect();
    server_compute_s += start.elapsed().as_secs_f64();
    let online_wall_s = online_start.elapsed().as_secs_f64();
    if decoded_sum != expected {
        return Err("decrypted sum differs from plaintext oracle".into());
    }
    if recovered
        .iter()
        .zip(&uploads)
        .any(|(seed, upload)| *seed != upload.seed)
    {
        return Err("individual mask seed recovery failed".into());
    }
    Ok(Report {
        protocol: "TACITA-STE-only",
        implementation_scope: "STE_with_tag_seed_path_and_share_proofs",
        mklhts_enabled: false,
        input_soundness: false,
        ste_share_proofs: true,
        interpolation_domain: ctx.crs.n,
        plaintext_dimensions: dimensions,
        setup_s,
        client_compute_s,
        client_observed_mean_s,
        client_batch_wall_s,
        committee_compute_s: committee_times.iter().sum::<f64>() / committee_times.len() as f64,
        server_compute_s,
        server_dlog_s,
        online_wall_s,
        client_to_server_bytes,
        server_to_committee_bytes,
        committee_to_server_bytes,
        total_bytes: client_to_server_bytes + server_to_committee_bytes + committee_to_server_bytes,
        decoded_sum,
        recovered_mask_seeds,
        correctness: "pass",
        config,
    })
}
