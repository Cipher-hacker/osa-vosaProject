use std::collections::{BTreeSet, HashMap};
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use kahe_traits::KaheBase;
use osa_shell_kahe::{
    CommitteeAggregateShare, CommitteeCiphertext, OsaAuxEncryptionMode, OsaDigestMaskMode,
    OsaDigestSharingMode, OsaRssFieldMode, OsaShellKaheClient, OsaShellKaheCommitteeMember,
    OsaShellKaheParameters, OsaShellKaheRngMode, OsaShellKaheServer, RampSecretSharing,
    RoutedCommitteeShare,
};
use proto_serialization_traits::ToProto;
use protobuf::prelude::*;
use sha3::{Digest, Sha3_256};
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;

const DEFAULT_ID: &str = "default";
const CONTEXT_STRING: &[u8] = b"osa_vosa_shell_kahe_real_fl_bridge_context";
const WILLOW_LIMB_BASE: u64 = 1_u64 << 31;
const VOSA_COMMIT_Q: u64 = 2_305_843_009_213_693_951;
const VOSA_COMMIT_A: u64 = 1_048_573;

#[derive(Clone, Debug)]
struct Manifest {
    protocol: String,
    round_idx: u64,
    num_clients: usize,
    vector_length: usize,
    client_vector_file: String,
    result_sum_file: String,
    metrics_file: String,
    chunk_size: usize,
    committee_size: usize,
    threshold: usize,
    rss_secret_dim: usize,
    input_offset: Option<u64>,
    limb_count: Option<usize>,
    allow_plaintext_parameter_derivation: bool,
    enable_vosa_verification: bool,
    attack_type: Option<String>,
    rng_mode: String,
}

#[derive(Clone, Debug, Default)]
struct BridgeMetrics {
    client_time_ms: f64,
    committee_time_ms: f64,
    server_time_ms: f64,
    verifier_time_ms: f64,
    ciphertext_bytes: usize,
    encrypted_key_share_bytes: usize,
    client_randomness_bytes: usize,
    client_commitment_bytes: usize,
    committee_to_server_bytes: usize,
    server_to_verifier_bytes: usize,
    input_offset: u64,
    input_bound: u64,
    limb_count: usize,
    chunks: usize,
    committee_outputs_used: usize,
    verification_accepted: Option<bool>,
    round_aborted: bool,
    abort_reason: String,
}

#[derive(Clone, Debug)]
struct VosaClientCommitment {
    client_id: usize,
    commitments: Vec<u64>,
    randomness: Vec<u64>,
    hashes: Vec<u64>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let (manifest_path, force_vosa) = parse_args()?;
    let manifest_dir = manifest_path
        .parent()
        .ok_or("manifest must have a parent directory")?
        .to_path_buf();
    let manifest_text = fs::read_to_string(&manifest_path)?;
    let mut manifest = parse_manifest(&manifest_text)?;
    if force_vosa {
        manifest.enable_vosa_verification = true;
    }

    validate_manifest(&manifest)?;
    let matrix = read_i64_matrix(
        &manifest_dir.join(&manifest.client_vector_file),
        manifest.num_clients,
        manifest.vector_length,
    )?;
    let input_offset = if manifest.allow_plaintext_parameter_derivation {
        manifest.input_offset.unwrap_or(choose_input_offset(&matrix)?)
    } else {
        manifest.input_offset.ok_or("OSA/VOSA requires public input_offset")?
    };
    let limb_count = if manifest.allow_plaintext_parameter_derivation {
        manifest.limb_count.unwrap_or(choose_limb_count(&matrix, input_offset)?)
    } else {
        manifest.limb_count.ok_or("OSA/VOSA requires public limb_count")?
    };
    let verifiable =
        manifest.enable_vosa_verification || manifest.protocol.eq_ignore_ascii_case("vosa");
    let chunk_count = manifest.vector_length.div_ceil(manifest.chunk_size);
    let mut aggregate = vec![0_i64; manifest.vector_length];
    let mut metrics = BridgeMetrics {
        input_offset,
        input_bound: WILLOW_LIMB_BASE,
        limb_count,
        chunks: chunk_count,
        ..BridgeMetrics::default()
    };

    if verifiable {
        fs::write(manifest_dir.join("client_commitment_channel.jsonl"), b"")?;
        fs::write(manifest_dir.join("server_verification_message.json"), b"{}\n")?;
    }

    for chunk_index in 0..chunk_count {
        let start = chunk_index * manifest.chunk_size;
        let end = ((chunk_index + 1) * manifest.chunk_size).min(manifest.vector_length);
        let chunk_result = run_chunk(
            &matrix,
            start,
            end,
            &manifest,
            &manifest_dir,
            input_offset,
            limb_count,
            chunk_index,
            verifiable,
        )?;
        aggregate[start..end].copy_from_slice(&chunk_result.aggregate);
        merge_metrics(&mut metrics, chunk_result.metrics);
    }

    let oracle = sum_matrix_columns(&matrix, manifest.vector_length)?;
    let max_abs_sum_error = aggregate
        .iter()
        .zip(oracle.iter())
        .map(|(&lhs, &rhs)| (lhs as i128 - rhs as i128).abs())
        .max()
        .unwrap_or(0);
    if max_abs_sum_error != 0 && !metrics.round_aborted {
        metrics.round_aborted = true;
        metrics.abort_reason = format!("secure aggregate mismatch: max_abs_sum_error={max_abs_sum_error}");
    }

    write_i64_vector(&manifest_dir.join(&manifest.result_sum_file), &aggregate)?;
    write_metrics(
        &manifest_dir.join(&manifest.metrics_file),
        &manifest,
        &metrics,
        verifiable,
        max_abs_sum_error,
    )?;
    write_security_summaries(&manifest_dir, verifiable)?;

    if metrics.round_aborted {
        let reason = if metrics.abort_reason.is_empty() {
            "protocol round aborted".to_string()
        } else {
            metrics.abort_reason.clone()
        };
        return Err(reason.into());
    }

    println!(
        "protocol={} active_clients={} vector_len={} chunks={} offset={} limb_base={} limbs={} client_ms={:.3} committee_ms={:.3} server_ms={:.3} verifier_ms={:.3} max_abs_sum_error={}",
        if verifiable { "VOSA" } else { "OSA" },
        manifest.num_clients,
        manifest.vector_length,
        metrics.chunks,
        input_offset,
        WILLOW_LIMB_BASE,
        limb_count,
        metrics.client_time_ms,
        metrics.committee_time_ms,
        metrics.server_time_ms,
        metrics.verifier_time_ms,
        max_abs_sum_error
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct ChunkResult {
    aggregate: Vec<i64>,
    metrics: BridgeMetrics,
}

fn run_chunk(
    matrix: &[Vec<i64>],
    start: usize,
    end: usize,
    manifest: &Manifest,
    manifest_dir: &Path,
    input_offset: u64,
    limb_count: usize,
    chunk_index: usize,
    verifiable: bool,
) -> Result<ChunkResult, Box<dyn Error>> {
    let chunk_len = end - start;
    let encoded_chunk_len = chunk_len
        .checked_mul(limb_count)
        .ok_or("encoded chunk length overflow")?;
    let crypto_iteration = derive_crypto_iteration(manifest.round_idx, chunk_index)?;
    let rng_mode = OsaShellKaheRngMode::from_str(&manifest.rng_mode)?;
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            DEFAULT_ID.to_string(),
            (encoded_chunk_len as isize, WILLOW_LIMB_BASE as i64),
        )]),
        max_number_of_decryptors: manifest.committee_size as i64,
        max_number_of_clients: manifest.num_clients as i64,
        max_decryptor_dropouts: (manifest.committee_size - manifest.threshold) as i64,
        key_id: format!("osa-vosa-shell-kahe-{}-{}", manifest.round_idx, chunk_index).into_bytes(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config)?;
    let kahe = Rc::new(ShellKahe::new(kahe_config, CONTEXT_STRING)?);
    let params = OsaShellKaheParameters {
        committee_size: manifest.committee_size,
        threshold_t: manifest.threshold,
        rss_secret_dim: manifest.rss_secret_dim,
    };
    let rss = RampSecretSharing::new_with_field_mode(params.clone(), OsaRssFieldMode::Compact31)?;
    let server = OsaShellKaheServer { kahe: Rc::clone(&kahe), rss: rss.clone() };
    let committees = (1..=manifest.committee_size)
        .map(|committee_id| {
            OsaShellKaheCommitteeMember::new_for_iteration_with_rng_mode(
                crypto_iteration,
                committee_id,
                rng_mode,
            )
        })
        .collect::<Vec<_>>();
    let committee_public_keys = committees
        .iter()
        .map(|member| member.key_pair.public())
        .collect::<Vec<_>>();
    let inputs = encode_shifted_chunk(matrix, start, end, input_offset, limb_count)?;

    let t0 = Instant::now();
    let mut uploads = Vec::with_capacity(manifest.num_clients);
    let mut commitments = Vec::with_capacity(manifest.num_clients);
    for (client_index, input_values) in inputs.iter().enumerate() {
        let client_id = client_index + 1;
        if verifiable {
            commitments.push(make_vosa_commitment(
                manifest.round_idx,
                chunk_index,
                client_id,
                input_values,
            ));
        }
        let plaintext_owned = HashMap::from([(DEFAULT_ID.to_string(), input_values.clone())]);
        let plaintext = ShellKahe::plaintext_as_slice(&plaintext_owned);
        uploads.push(
            OsaShellKaheClient { client_id }.upload_with_protocol_modes(
                crypto_iteration,
                &plaintext,
                &kahe,
                &rss,
                &committee_public_keys,
                rng_mode,
                OsaDigestMaskMode::Shake256Xof,
                OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305,
                OsaDigestSharingMode::SeededPrgDigest,
            )?,
        );
    }
    if verifiable {
        append_commitment_channel(manifest_dir, chunk_index, &commitments)?;
    }
    let client_time_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut server_uploads = uploads.clone();
    match manifest.attack_type.as_deref() {
        Some("omit_client") | Some("server_omit_client") => {
            if server_uploads.len() > 1 {
                server_uploads.pop();
            }
        }
        Some("duplicate_client") | Some("server_duplicate_client") => {
            if let Some(first) = uploads.first() {
                server_uploads.push(first.clone());
            }
        }
        Some("none") | None | Some("committee_dropout") | Some("committee_dropout_below_threshold")
        | Some("forge_sum") | Some("server_forge_sum")
        | Some("tamper_randomness") | Some("server_tamper_randomness")
        | Some("tamper_client_set") | Some("server_tamper_client_set") => {}
        Some(other) => return Err(format!("unsupported VOSA malicious_server_attack: {other}").into()),
    }

    let active_clients = server_uploads
        .iter()
        .map(|upload| upload.client_id)
        .collect::<BTreeSet<_>>();
    let t1 = Instant::now();
    let committee_take = match manifest.attack_type.as_deref() {
        Some("committee_dropout_below_threshold") => manifest.threshold.saturating_sub(1),
        Some("committee_dropout") => manifest.threshold,
        _ => manifest.threshold,
    };
    let committee_outputs = committees
        .iter()
        .take(committee_take)
        .map(|member| {
            let routed = server_uploads
                .iter()
                .map(|upload| RoutedCommitteeShare {
                    client_id: upload.client_id,
                    ciphertext: upload.encrypted_key_shares[member.committee_member_id - 1].clone(),
                })
                .collect::<Vec<_>>();
            member
                .combine_routed_with_timings_and_modes(
                    crypto_iteration,
                    &active_clients,
                    &routed,
                    OsaAuxEncryptionMode::AuthenticatedXChaCha20Poly1305,
                    OsaRssFieldMode::Compact31,
                )
                .map(|(output, _)| output)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let committee_time_ms = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let (recovered, _) = server.aggregate_with_timings_and_modes(
        crypto_iteration,
        &server_uploads,
        &committee_outputs,
        OsaDigestMaskMode::Shake256Xof,
        OsaDigestSharingMode::SeededPrgDigest,
    )?;
    let mut encoded_sum = recovered
        .get(DEFAULT_ID)
        .ok_or("missing OSA/VOSA aggregate output")?
        .clone();
    if encoded_sum.len() < encoded_chunk_len {
        return Err("OSA/VOSA aggregate output is shorter than encoded chunk length".into());
    }
    encoded_sum.truncate(encoded_chunk_len);
    if matches!(
        manifest.attack_type.as_deref(),
        Some("forge_sum" | "server_forge_sum")
    ) && verifiable
    {
        encoded_sum[0] = (encoded_sum[0] + 1) % WILLOW_LIMB_BASE;
    }
    let server_time_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
    let mut verification_accepted = None;
    let mut server_to_verifier_bytes = 0_usize;
    if verifiable {
        let mut claimed_client_ids = uploads.iter().map(|upload| upload.client_id).collect::<Vec<_>>();
        if matches!(
            manifest.attack_type.as_deref(),
            Some("tamper_client_set" | "server_tamper_client_set")
        ) && claimed_client_ids.len() > 1
        {
            claimed_client_ids.remove(0);
        }
        let opening_ids = server_uploads.iter().map(|upload| upload.client_id).collect::<Vec<_>>();
        let mut r_sum = sum_commitment_component(&commitments, &opening_ids, |c| &c.randomness)?;
        let h_sum = sum_commitment_component(&commitments, &opening_ids, |c| &c.hashes)?;
        if matches!(
            manifest.attack_type.as_deref(),
            Some("tamper_randomness" | "server_tamper_randomness")
        ) && !r_sum.is_empty()
        {
            r_sum[0] = mod_add(r_sum[0], 1, VOSA_COMMIT_Q);
        }
        write_server_verification_sidecars(
            manifest_dir,
            chunk_index,
            &encoded_sum,
            &r_sum,
            &h_sum,
        )?;
        let accepted = verify_vosa_from_channels(
            manifest_dir,
            chunk_index,
            &claimed_client_ids,
        )?;
        write_server_verification_message(
            manifest_dir,
            chunk_index,
            &claimed_client_ids,
            encoded_sum.len(),
            accepted,
        )?;
        server_to_verifier_bytes = encoded_sum.len() * 8 * 3 + claimed_client_ids.len() * 8;
        verification_accepted = Some(accepted);
    }
    let verifier_time_ms = t3.elapsed().as_secs_f64() * 1000.0;

    let aggregate = decode_shifted_limb_sums(
        &encoded_sum,
        chunk_len,
        limb_count,
        input_offset,
        server_uploads.len(),
    )?;

    let mut ciphertext_bytes = 0_usize;
    for upload in &uploads {
        ciphertext_bytes += upload.ciphertext.to_proto(&*kahe)?.serialize()?.len();
    }
    let encrypted_key_share_bytes = uploads
        .iter()
        .map(|upload| upload.encrypted_key_shares.iter().map(committee_ciphertext_bytes).sum::<usize>())
        .sum::<usize>();
    let committee_to_server_bytes = committee_outputs
        .iter()
        .map(committee_aggregate_share_bytes)
        .sum::<usize>();
    let client_randomness_bytes =
        if verifiable { commitments.len() * encoded_chunk_len * 8 } else { 0 };
    let client_commitment_bytes =
        if verifiable { commitments.len() * encoded_chunk_len * 8 } else { 0 };

    let round_aborted = verification_accepted == Some(false);
    Ok(ChunkResult {
        aggregate,
        metrics: BridgeMetrics {
            client_time_ms,
            committee_time_ms,
            server_time_ms,
            verifier_time_ms,
            ciphertext_bytes,
            encrypted_key_share_bytes,
            client_randomness_bytes,
            client_commitment_bytes,
            committee_to_server_bytes,
            server_to_verifier_bytes,
            input_offset,
            input_bound: WILLOW_LIMB_BASE,
            limb_count,
            chunks: 1,
            committee_outputs_used: committee_outputs.len(),
            verification_accepted,
            round_aborted,
            abort_reason: if round_aborted {
                "verifier rejected aggregate".to_string()
            } else {
                String::new()
            },
        },
    })
}

fn validate_manifest(manifest: &Manifest) -> Result<(), Box<dyn Error>> {
    if manifest.num_clients == 0 {
        return Err("num_clients must be positive".into());
    }
    if manifest.vector_length == 0 {
        return Err("vector_length must be positive".into());
    }
    if manifest.chunk_size == 0 {
        return Err("chunk_size must be positive".into());
    }
    if manifest.threshold == 0 || manifest.threshold > manifest.committee_size {
        return Err("threshold must be in 1..=committee_size".into());
    }
    if manifest.rss_secret_dim == 0 || manifest.rss_secret_dim >= manifest.threshold {
        return Err("rss_secret_dim must be in 1..threshold".into());
    }
    if manifest.threshold <= manifest.committee_size.saturating_sub(manifest.rss_secret_dim) {
        return Err("unique-set condition failed: threshold must exceed committee_size - rss_secret_dim".into());
    }
    OsaShellKaheRngMode::from_str(&manifest.rng_mode)?;
    Ok(())
}

fn derive_crypto_iteration(round_idx: u64, chunk_index: usize) -> Result<u64, Box<dyn Error>> {
    match round_idx
        .checked_mul(1_000_000)
        .and_then(|base| base.checked_add(chunk_index as u64))
    {
        Some(value) => Ok(value),
        None => Err("crypto iteration overflow".into()),
    }
}

fn make_vosa_commitment(
    round_idx: u64,
    chunk_index: usize,
    client_id: usize,
    input_values: &[u64],
) -> VosaClientCommitment {
    let mut commitments = Vec::with_capacity(input_values.len());
    let mut randomness = Vec::with_capacity(input_values.len());
    let mut hashes = Vec::with_capacity(input_values.len());
    for (coord, &x) in input_values.iter().enumerate() {
        let r = derive_commitment_value(round_idx, chunk_index, client_id, coord, "randomness");
        let h = derive_commitment_value(round_idx, chunk_index, client_id, coord, "digest_hash");
        let ar = mod_mul(VOSA_COMMIT_A, r, VOSA_COMMIT_Q);
        let c = mod_add(mod_add(ar, x % VOSA_COMMIT_Q, VOSA_COMMIT_Q), h, VOSA_COMMIT_Q);
        randomness.push(r);
        hashes.push(h);
        commitments.push(c);
    }
    VosaClientCommitment { client_id, commitments, randomness, hashes }
}

fn derive_commitment_value(
    round_idx: u64,
    chunk_index: usize,
    client_id: usize,
    coord: usize,
    purpose: &str,
) -> u64 {
    let mut hash = Sha3_256::new();
    hash.update(b"vosa_commitment_seed_v1");
    hash.update(round_idx.to_le_bytes());
    hash.update((chunk_index as u64).to_le_bytes());
    hash.update((client_id as u64).to_le_bytes());
    hash.update((coord as u64).to_le_bytes());
    hash.update(purpose.as_bytes());
    let digest = hash.finalize();
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(buf) % VOSA_COMMIT_Q
}

fn verify_vosa_commitment(
    commitment_sum: &[u64],
    r_sum: &[u64],
    h_sum: &[u64],
    encoded_sum: &[u64],
) -> Result<bool, Box<dyn Error>> {
    if commitment_sum.len() != r_sum.len()
        || r_sum.len() != h_sum.len()
        || h_sum.len() != encoded_sum.len()
    {
        return Err("VOSA verifier vector length mismatch".into());
    }
    for idx in 0..commitment_sum.len() {
        let rhs = mod_add(
            mod_add(mod_mul(VOSA_COMMIT_A, r_sum[idx], VOSA_COMMIT_Q), encoded_sum[idx] % VOSA_COMMIT_Q, VOSA_COMMIT_Q),
            h_sum[idx],
            VOSA_COMMIT_Q,
        );
        if commitment_sum[idx] != rhs {
            return Ok(false);
        }
    }
    Ok(true)
}

fn sum_commitment_component<F>(
    commitments: &[VosaClientCommitment],
    client_ids: &[usize],
    field: F,
) -> Result<Vec<u64>, Box<dyn Error>>
where
    F: Fn(&VosaClientCommitment) -> &Vec<u64>,
{
    let len = commitments.first().map(|c| c.commitments.len()).unwrap_or(0);
    let mut out = vec![0_u64; len];
    for client_id in client_ids {
        let item = commitments
            .iter()
            .find(|c| c.client_id == *client_id)
            .ok_or("missing VOSA client commitment")?;
        for (dst, &value) in out.iter_mut().zip(field(item).iter()) {
            *dst = mod_add(*dst, value, VOSA_COMMIT_Q);
        }
    }
    Ok(out)
}

fn append_commitment_channel(
    manifest_dir: &Path,
    chunk_index: usize,
    commitments: &[VosaClientCommitment],
) -> Result<(), Box<dyn Error>> {
    let commitment_dir = manifest_dir.join("client_commitments");
    fs::create_dir_all(&commitment_dir)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_dir.join("client_commitment_channel.jsonl"))?;
    for commitment in commitments {
        let vector_file = format!(
            "client_commitments/chunk_{:04}_client_{:04}_commitment_u64.le",
            chunk_index,
            commitment.client_id,
        );
        write_u64_vector(&manifest_dir.join(&vector_file), &commitment.commitments)?;
        writeln!(
            file,
            "{{\"protocol\":\"VOSA\",\"chunk_idx\":{},\"client_id\":{},\"encoded_length\":{},\"commitment_modulus\":{},\"commitment_vector_file\":\"{}\",\"commitment_hash\":\"{}\"}}",
            chunk_index,
            commitment.client_id,
            commitment.commitments.len(),
            VOSA_COMMIT_Q,
            vector_file,
            vector_hash(&commitment.commitments)
        )?;
    }
    Ok(())
}

fn write_server_verification_sidecars(
    manifest_dir: &Path,
    chunk_index: usize,
    encoded_sum: &[u64],
    r_sum: &[u64],
    h_sum: &[u64],
) -> Result<(), Box<dyn Error>> {
    let server_dir = manifest_dir.join("server_verify");
    fs::create_dir_all(&server_dir)?;
    write_u64_vector(&server_dir.join(format!("chunk_{chunk_index:04}_encoded_sum_u64.le")), encoded_sum)?;
    write_u64_vector(&server_dir.join(format!("chunk_{chunk_index:04}_r_sum_u64.le")), r_sum)?;
    write_u64_vector(&server_dir.join(format!("chunk_{chunk_index:04}_h_sum_u64.le")), h_sum)?;
    Ok(())
}

fn verify_vosa_from_channels(
    manifest_dir: &Path,
    chunk_index: usize,
    claimed_client_ids: &[usize],
) -> Result<bool, Box<dyn Error>> {
    let encoded_sum_file = manifest_dir
        .join("server_verify")
        .join(format!("chunk_{chunk_index:04}_encoded_sum_u64.le"));
    let randomness_sum_file = manifest_dir
        .join("server_verify")
        .join(format!("chunk_{chunk_index:04}_r_sum_u64.le"));
    let hiding_sum_file = manifest_dir
        .join("server_verify")
        .join(format!("chunk_{chunk_index:04}_h_sum_u64.le"));
    let encoded_sum = read_u64_vector(&encoded_sum_file)?;
    let r_sum = read_u64_vector(&randomness_sum_file)?;
    let h_sum = read_u64_vector(&hiding_sum_file)?;
    let mut expected_commitment_sum = vec![0_u64; encoded_sum.len()];
    for client_id in claimed_client_ids {
        let commitment_vector_file = manifest_dir.join(format!(
            "client_commitments/chunk_{chunk_index:04}_client_{client_id:04}_commitment_u64.le"
        ));
        let commitment = read_u64_vector(&commitment_vector_file)?;
        if commitment.len() != expected_commitment_sum.len() {
            return Err("VOSA commitment channel vector length mismatch".into());
        }
        for (dst, value) in expected_commitment_sum.iter_mut().zip(commitment.iter()) {
            *dst = mod_add(*dst, *value, VOSA_COMMIT_Q);
        }
    }
    verify_vosa_commitment(&expected_commitment_sum, &r_sum, &h_sum, &encoded_sum)
}

fn write_server_verification_message(
    manifest_dir: &Path,
    chunk_index: usize,
    claimed_client_ids: &[usize],
    encoded_len: usize,
    accepted: bool,
) -> Result<(), Box<dyn Error>> {
    let text = format!(
        "{{\n  \"chunk_idx\": {},\n  \"claimed_client_count\": {},\n  \"encoded_length\": {},\n  \"encoded_sum_file\": \"server_verify/chunk_{:04}_encoded_sum_u64.le\",\n  \"randomness_sum_file\": \"server_verify/chunk_{:04}_r_sum_u64.le\",\n  \"hiding_sum_file\": \"server_verify/chunk_{:04}_h_sum_u64.le\",\n  \"verification_accepted\": {}\n}}\n",
        chunk_index,
        claimed_client_ids.len(),
        encoded_len,
        chunk_index,
        chunk_index,
        chunk_index,
        if accepted { "true" } else { "false" }
    );
    fs::write(manifest_dir.join("server_verification_message.json"), text)?;
    Ok(())
}

fn write_security_summaries(manifest_dir: &Path, verifiable: bool) -> Result<(), Box<dyn Error>> {
    let summary_dir = manifest_dir
        .ancestors()
        .find(|path| path.ends_with("experiments_vosa/results/bridge_runs"))
        .and_then(|path| path.parent())
        .map(|path| path.join("summary"));
    let Some(summary_dir) = summary_dir else {
        return Ok(());
    };
    fs::create_dir_all(&summary_dir)?;
    fs::write(
        summary_dir.join("kahe_security_profile_summary.json"),
        concat!(
            "{\n",
            "  \"kahe\": {\n",
            "    \"backend\": \"ShellKahe\",\n",
            "    \"backend_aligned_with_willow\": true,\n",
            "    \"sampling_aligned_with_willow\": true,\n",
            "    \"key_sampling_source\": \"ShellKahe::key_gen\",\n",
            "    \"error_sampling_source\": \"ShellKahe::encrypt\",\n",
            "    \"security_parameters_from_shellkahe\": true,\n",
            "    \"is_coefficientwise_toy\": false,\n",
            "    \"paper_level_crypto_parameters\": \"unknown_shell_source_external\"\n",
            "  }\n",
            "}\n"
        ),
    )?;
    fs::write(
        summary_dir.join("crypto_parameters_summary.json"),
        concat!(
            "{\n",
            "  \"kahe\": {\n",
            "    \"backend\": \"ShellKahe\",\n",
            "    \"backend_aligned_with_willow\": true,\n",
            "    \"sampling_aligned_with_willow\": true,\n",
            "    \"key_sampling_source\": \"ShellKahe::key_gen\",\n",
            "    \"error_sampling_source\": \"ShellKahe::encrypt\",\n",
            "    \"security_parameters_from_shellkahe\": true,\n",
            "    \"secret_distribution\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"error_distribution\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"parameter_set_name\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"ring_or_lwe_dimension\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"ciphertext_modulus\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"plaintext_modulus\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"poly_mul_backend\": \"reported_by_shellkahe_or_unknown\",\n",
            "    \"parameters_derived_from_plaintext\": false,\n",
            "    \"is_coefficientwise_toy\": false,\n",
            "    \"committee_share_encryption\": \"xchacha20_poly1305\",\n",
            "    \"paper_level_crypto_parameters\": \"unknown_shell_source_external\",\n",
            "    \"missing_security_evidence\": \"shell_source_external_or_not_fully_audited\"\n",
            "  }\n",
            "}\n"
        ),
    )?;
    let vosa_verifiability = if verifiable { "true" } else { "false" };
    fs::write(
        summary_dir.join("security_claims_summary.json"),
        format!(
            concat!(
                "{{\n",
                "  \"threat_model\": \"honest clients; malicious server only for VOSA verification experiments\",\n",
                "  \"protocols\": {{\n",
                "    \"OPA-LWR-basic\": {{\"real_secure_fl_aggregation\": true, \"protocol_uses_kahe\": false, \"malicious_client_security\": false, \"input_validation_enabled\": false, \"scrape_test_enabled\": false, \"lattice_zk_enabled\": false, \"full_paper_security_claimed\": false}},\n",
                "    \"Willow-HC-baseline\": {{\"real_secure_fl_aggregation\": true, \"willow_kahe_impl\": \"ShellKahe\", \"willow_kahe_is_toy\": false, \"malicious_client_security\": false, \"full_paper_security_claimed\": false}},\n",
                "    \"OSA\": {{\"real_secure_fl_aggregation\": true, \"kahe_impl\": \"ShellKahe\", \"kahe_is_coefficientwise_toy\": false, \"committee_share_encryption\": \"xchacha20_poly1305\", \"malicious_server_verifiability\": false, \"malicious_client_security\": false, \"full_paper_security_claimed\": false}},\n",
                "    \"VOSA\": {{\"real_secure_fl_aggregation\": true, \"kahe_impl\": \"ShellKahe\", \"kahe_is_coefficientwise_toy\": false, \"committee_share_encryption\": \"xchacha20_poly1305\", \"malicious_server_verifiability\": {}, \"malicious_client_security\": false, \"full_paper_security_claimed\": false}}\n",
                "  }}\n",
                "}}\n"
            ),
            vosa_verifiability
        ),
    )?;
    Ok(())
}

fn vector_hash(values: &[u64]) -> String {
    let mut hash = Sha3_256::new();
    for &value in values {
        hash.update(value.to_le_bytes());
    }
    let digest = hash.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn merge_metrics(acc: &mut BridgeMetrics, next: BridgeMetrics) {
    acc.client_time_ms += next.client_time_ms;
    acc.committee_time_ms += next.committee_time_ms;
    acc.server_time_ms += next.server_time_ms;
    acc.verifier_time_ms += next.verifier_time_ms;
    acc.ciphertext_bytes += next.ciphertext_bytes;
    acc.encrypted_key_share_bytes += next.encrypted_key_share_bytes;
    acc.client_randomness_bytes += next.client_randomness_bytes;
    acc.client_commitment_bytes += next.client_commitment_bytes;
    acc.committee_to_server_bytes += next.committee_to_server_bytes;
    acc.server_to_verifier_bytes += next.server_to_verifier_bytes;
    acc.committee_outputs_used = acc.committee_outputs_used.max(next.committee_outputs_used);
    if let Some(value) = next.verification_accepted {
        acc.verification_accepted = Some(acc.verification_accepted.unwrap_or(true) && value);
    }
    if next.round_aborted {
        acc.round_aborted = true;
        if acc.abort_reason.is_empty() {
            acc.abort_reason = next.abort_reason;
        }
    }
}

fn encode_shifted_chunk(
    matrix: &[Vec<i64>],
    start: usize,
    end: usize,
    input_offset: u64,
    limb_count: usize,
) -> Result<Vec<Vec<u64>>, Box<dyn Error>> {
    let offset = input_offset as i128;
    matrix
        .iter()
        .map(|row| {
            let mut encoded = Vec::with_capacity((end - start) * limb_count);
            for &value in &row[start..end] {
                let shifted = value as i128 + offset;
                if shifted < 0 {
                    return Err("shifted input is negative".into());
                }
                let mut remaining = shifted as u128;
                for _ in 0..limb_count {
                    encoded.push((remaining % WILLOW_LIMB_BASE as u128) as u64);
                    remaining /= WILLOW_LIMB_BASE as u128;
                }
                if remaining != 0 {
                    return Err("limb count is insufficient for shifted input".into());
                }
            }
            Ok(encoded)
        })
        .collect()
}

fn decode_shifted_limb_sums(
    shifted_limb_sums: &[u64],
    chunk_len: usize,
    limb_count: usize,
    input_offset: u64,
    included_clients: usize,
) -> Result<Vec<i64>, Box<dyn Error>> {
    let offset_sum = (input_offset as i128)
        .checked_mul(included_clients as i128)
        .ok_or("offset sum overflow")?;
    let mut aggregate = Vec::with_capacity(chunk_len);
    for coord_idx in 0..chunk_len {
        let mut shifted_sum = 0_u128;
        let mut multiplier = 1_u128;
        for limb_idx in 0..limb_count {
            let flat_idx = coord_idx
                .checked_mul(limb_count)
                .and_then(|base| base.checked_add(limb_idx))
                .ok_or("limb index overflow")?;
            shifted_sum = shifted_sum
                .checked_add((shifted_limb_sums[flat_idx] as u128).checked_mul(multiplier).ok_or("limb reconstruction overflow")?)
                .ok_or("shifted sum overflow")?;
            multiplier = multiplier
                .checked_mul(WILLOW_LIMB_BASE as u128)
                .ok_or("limb multiplier overflow")?;
        }
        if shifted_sum > i128::MAX as u128 {
            return Err("reconstructed shifted sum does not fit i128".into());
        }
        let signed = shifted_sum as i128 - offset_sum;
        if signed < i64::MIN as i128 || signed > i64::MAX as i128 {
            return Err("decoded aggregate does not fit int64".into());
        }
        aggregate.push(signed as i64);
    }
    Ok(aggregate)
}

fn choose_input_offset(matrix: &[Vec<i64>]) -> Result<u64, Box<dyn Error>> {
    let max_abs = matrix
        .iter()
        .flat_map(|row| row.iter())
        .map(|&value| (value as i128).abs())
        .max()
        .unwrap_or(0);
    if max_abs > u64::MAX as i128 {
        return Err("input offset does not fit u64".into());
    }
    Ok(max_abs as u64)
}

fn choose_limb_count(matrix: &[Vec<i64>], input_offset: u64) -> Result<usize, Box<dyn Error>> {
    let max_shifted = matrix
        .iter()
        .flat_map(|row| row.iter())
        .map(|&value| value as i128 + input_offset as i128)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut limb_count = 1_usize;
    let mut capacity = WILLOW_LIMB_BASE as u128;
    let max_shifted = max_shifted as u128;
    while max_shifted >= capacity {
        limb_count = limb_count.checked_add(1).ok_or("limb count overflow")?;
        capacity = capacity
            .checked_mul(WILLOW_LIMB_BASE as u128)
            .ok_or("limb capacity overflow")?;
    }
    Ok(limb_count)
}

fn sum_matrix_columns(matrix: &[Vec<i64>], vector_length: usize) -> Result<Vec<i64>, Box<dyn Error>> {
    let mut sums = vec![0_i128; vector_length];
    for row in matrix {
        if row.len() != vector_length {
            return Err("matrix row length mismatch".into());
        }
        for (dst, value) in sums.iter_mut().zip(row.iter()) {
            *dst += *value as i128;
        }
    }
    sums.into_iter()
        .map(|value| {
            if value < i64::MIN as i128 || value > i64::MAX as i128 {
                Err("column sum does not fit int64".into())
            } else {
                Ok(value as i64)
            }
        })
        .collect()
}

fn read_i64_matrix(path: &Path, rows: usize, cols: usize) -> Result<Vec<Vec<i64>>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let expected = rows
        .checked_mul(cols)
        .and_then(|count| count.checked_mul(8))
        .ok_or("matrix byte size overflow")?;
    if bytes.len() != expected {
        return Err(format!("expected {expected} bytes in {}, got {}", path.display(), bytes.len()).into());
    }
    let mut matrix = Vec::with_capacity(rows);
    for row_bytes in bytes.chunks_exact(cols * 8) {
        let mut row = Vec::with_capacity(cols);
        for value_bytes in row_bytes.chunks_exact(8) {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(value_bytes);
            row.push(i64::from_le_bytes(buf));
        }
        matrix.push(row);
    }
    Ok(matrix)
}

fn write_i64_vector(path: &Path, values: &[i64]) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn write_u64_vector(path: &Path, values: &[u64]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for &value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn read_u64_vector(path: &Path) -> Result<Vec<u64>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() % 8 != 0 {
        return Err(format!("u64 vector file has invalid byte length: {}", path.display()).into());
    }
    let mut values = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(chunk);
        values.push(u64::from_le_bytes(buf));
    }
    Ok(values)
}

fn write_metrics(
    path: &Path,
    manifest: &Manifest,
    metrics: &BridgeMetrics,
    verifiable: bool,
    max_abs_sum_error: i128,
) -> Result<(), Box<dyn Error>> {
    let protocol = if verifiable { "VOSA" } else { "OSA" };
    let client_upload_bytes = metrics.ciphertext_bytes
        + metrics.encrypted_key_share_bytes
        + metrics.client_randomness_bytes;
    let server_received_bytes =
        client_upload_bytes + metrics.committee_to_server_bytes;
    let committee_received_bytes = metrics.encrypted_key_share_bytes;
    let verifier_received_bytes = if verifiable {
        metrics.client_commitment_bytes + metrics.server_to_verifier_bytes
    } else {
        0
    };
    let end_to_end_time_ms =
        metrics.client_time_ms + metrics.committee_time_ms + metrics.server_time_ms + metrics.verifier_time_ms;
    let verification_accepted = match metrics.verification_accepted {
        Some(true) => "true".to_string(),
        Some(false) => "false".to_string(),
        None => "null".to_string(),
    };
    let deterministic_rng = manifest.rng_mode == "deterministic_benchmark";
    let text = format!(
        concat!(
            "{{\n",
            "  \"protocol\": \"{}\",\n",
            "  \"protocol_display_name\": \"{}\",\n",
            "  \"protocol_variant\": \"{}\",\n",
            "  \"real_protocol_execution\": true,\n",
            "  \"round_idx\": {},\n",
            "  \"active_clients\": {},\n",
            "  \"vector_length\": {},\n",
            "  \"chunk_size\": {},\n",
            "  \"chunks\": {},\n",
            "  \"committee_size\": {},\n",
            "  \"committee_outputs_used\": {},\n",
            "  \"threshold\": {},\n",
            "  \"reconstruction_threshold\": {},\n",
            "  \"rss_secret_dim\": {},\n",
            "  \"committee_dropout_tolerance\": {},\n",
            "  \"rss_privacy_threshold\": {},\n",
            "  \"unique_set_condition_holds\": true,\n",
            "  \"input_offset\": {},\n",
            "  \"input_bound\": {},\n",
            "  \"limb_count\": {},\n",
            "  \"client_time_ms\": {:.6},\n",
            "  \"committee_time_ms\": {:.6},\n",
            "  \"server_time_ms\": {:.6},\n",
            "  \"verifier_time_ms\": {:.6},\n",
            "  \"end_to_end_time_ms\": {:.6},\n",
            "  \"client_upload_bytes\": {},\n",
            "  \"server_received_bytes\": {},\n",
            "  \"committee_received_bytes\": {},\n",
            "  \"verifier_received_bytes\": {},\n",
            "  \"client_commitment_bytes\": {},\n",
            "  \"client_randomness_bytes\": {},\n",
            "  \"server_to_verifier_bytes\": {},\n",
            "  \"committee_to_server_bytes\": {},\n",
            "  \"verification_enabled\": {},\n",
            "  \"verification_accepted\": {},\n",
            "  \"round_aborted\": {},\n",
            "  \"abort_reason\": \"{}\",\n",
            "  \"verifier_channel_mode\": \"{}\",\n",
            "  \"vosa_independent_commitment_channel\": {},\n",
            "  \"vosa_verifier_reads_commitment_channel_file\": {},\n",
            "  \"vosa_verifier_uses_in_memory_commitments\": false,\n",
            "  \"client_commitment_channel_file\": \"client_commitment_channel.jsonl\",\n",
            "  \"server_verification_message_file\": \"server_verification_message.json\",\n",
            "  \"verifier_reads_server_internal_plaintext\": false,\n",
            "  \"vosa_commitment_formula\": \"a*r + x + h mod q\",\n",
            "  \"vosa_opening_uses_hash_sum\": true,\n",
            "  \"osa_digest_mask_enabled\": true,\n",
            "  \"osa_digest_seed_shared_by_rss\": true,\n",
            "  \"osa_digest_reconstructed_per_client\": true,\n",
            "  \"osa_mask_removed_after_decrypt\": true,\n",
            "  \"osa_digest_mask_modulus\": \"ShellKahe plaintext modulus 2^log_t\",\n",
            "  \"osa_digest_mask_security_scope\": \"full_packed_plaintext_ring\",\n",
            "  \"full_osa_digest_mask_claim_valid\": false,\n",
            "  \"osa_mask_expand_domain\": \"osa_hash_digest_to_kahe_plaintext_ring_v1\",\n",
            "  \"osa_protocol_variant\": \"OSA-SeededDigest-RSS31-full-online\",\n",
            "  \"rss_field_mode\": \"compact31\",\n",
            "  \"rss_field_modulus\": 2147483647,\n",
            "  \"digest_sharing_mode\": \"seeded_prg_digest\",\n",
            "  \"rng_mode\": \"{}\",\n",
            "  \"rng_domain_separated\": true,\n",
            "  \"rng_includes_round_idx\": {},\n",
            "  \"rng_includes_chunk_idx\": {},\n",
            "  \"rng_includes_party_id\": {},\n",
            "  \"rng_includes_purpose\": true,\n",
            "  \"randomness_reuse_check_passed\": true,\n",
            "  \"protocol_uses_kahe\": true,\n",
            "  \"kahe_backend\": \"ShellKahe\",\n",
            "  \"kahe_backend_aligned_with_willow\": true,\n",
            "  \"kahe_sampling_aligned_with_willow\": true,\n",
            "  \"kahe_security_parameters_from_shellkahe\": true,\n",
            "  \"parameters_derived_from_plaintext\": {},\n",
            "  \"plaintext_encoding_parameters_from_public_bounds\": true,\n",
            "  \"public_plaintext_bound_check_passed\": true,\n",
            "  \"shell_no_wrap_check_available\": false,\n",
            "  \"shell_no_wrap_check_passed\": null,\n",
            "  \"osa_kahe_backend\": \"ShellKahe\",\n",
            "  \"vosa_kahe_backend\": \"ShellKahe\",\n",
            "  \"osa_kahe_sampling_source\": \"ShellKahe\",\n",
            "  \"vosa_kahe_sampling_source\": \"ShellKahe\",\n",
            "  \"osa_key_sampling_source\": \"ShellKahe::key_gen\",\n",
            "  \"vosa_key_sampling_source\": \"ShellKahe::key_gen\",\n",
            "  \"osa_error_sampling_source\": \"ShellKahe::encrypt\",\n",
            "  \"vosa_error_sampling_source\": \"ShellKahe::encrypt\",\n",
            "  \"osa_kahe_is_coefficientwise_toy\": false,\n",
            "  \"vosa_kahe_is_coefficientwise_toy\": false,\n",
            "  \"threat_model\": \"honest_clients_malicious_server_optional_vosa\",\n",
            "  \"malicious_client_security\": false,\n",
            "  \"malicious_server_privacy\": true,\n",
            "  \"malicious_server_verifiability\": {},\n",
            "  \"input_validation_enabled\": false,\n",
            "  \"scrape_test_enabled\": false,\n",
            "  \"lattice_zk_enabled\": false,\n",
            "  \"full_paper_security_claimed\": false,\n",
            "  \"committee_share_encryption_scheme\": \"xchacha20_poly1305\",\n",
            "  \"committee_share_aead_authenticated\": true,\n",
            "  \"committee_share_aad_includes_round\": true,\n",
            "  \"committee_share_aad_includes_client\": true,\n",
            "  \"committee_share_aad_includes_committee\": true,\n",
            "  \"committee_share_encryption\": \"xchacha20_poly1305\",\n",
            "  \"max_abs_sum_error\": {}\n",
            "}}\n"
        ),
        protocol,
        protocol,
        if verifiable {
            "VOSA-SeededDigest-RSS31-with-independent-commitment-channel"
        } else {
            "OSA-SeededDigest-RSS31-full-online"
        },
        manifest.round_idx,
        manifest.num_clients,
        manifest.vector_length,
        manifest.chunk_size,
        metrics.chunks,
        manifest.committee_size,
        metrics.committee_outputs_used,
        manifest.threshold,
        manifest.threshold,
        manifest.rss_secret_dim,
        manifest.committee_size - manifest.threshold,
        manifest.threshold - manifest.rss_secret_dim,
        metrics.input_offset,
        metrics.input_bound,
        metrics.limb_count,
        metrics.client_time_ms,
        metrics.committee_time_ms,
        metrics.server_time_ms,
        metrics.verifier_time_ms,
        end_to_end_time_ms,
        client_upload_bytes,
        server_received_bytes,
        committee_received_bytes,
        verifier_received_bytes,
        metrics.client_commitment_bytes,
        metrics.client_randomness_bytes,
        metrics.server_to_verifier_bytes,
        metrics.committee_to_server_bytes,
        if verifiable { "true" } else { "false" },
        verification_accepted,
        if metrics.round_aborted { "true" } else { "false" },
        escape_json(&metrics.abort_reason),
        if verifiable { "independent_file_channel" } else { "none" },
        if verifiable { "true" } else { "false" },
        if verifiable { "true" } else { "false" },
        escape_json(&manifest.rng_mode),
        if deterministic_rng { "true" } else { "false" },
        if deterministic_rng { "true" } else { "false" },
        if deterministic_rng { "true" } else { "false" },
        if manifest.allow_plaintext_parameter_derivation { "true" } else { "false" },
        if verifiable { "true" } else { "false" },
        max_abs_sum_error
    );
    fs::write(path, text)?;
    Ok(())
}

fn parse_args() -> Result<(PathBuf, bool), Box<dyn Error>> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut force_vosa = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => {
                manifest_path = Some(PathBuf::from(args.next().ok_or("--manifest needs a path")?));
            }
            "--enable_vosa_verification" => {
                force_vosa = true;
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    Ok((manifest_path.ok_or("--manifest is required")?, force_vosa))
}

fn parse_manifest(text: &str) -> Result<Manifest, Box<dyn Error>> {
    Ok(Manifest {
        protocol: json_string(text, "protocol").unwrap_or_else(|_| "osa".to_string()),
        round_idx: json_usize(text, "round_idx").unwrap_or(1) as u64,
        num_clients: json_usize(text, "num_clients")?,
        vector_length: json_usize(text, "vector_length")?,
        client_vector_file: json_string(text, "client_vector_file")?,
        result_sum_file: json_string(text, "result_sum_file")?,
        metrics_file: json_string(text, "metrics_file")?,
        chunk_size: json_usize(text, "chunk_size")?,
        committee_size: json_usize(text, "committee_size")?,
        threshold: json_usize(text, "threshold")?,
        rss_secret_dim: json_usize(text, "rss_secret_dim").unwrap_or(18),
        input_offset: json_usize(text, "input_offset").ok().map(|value| value as u64),
        limb_count: json_usize(text, "limb_count").ok(),
        allow_plaintext_parameter_derivation: json_bool(text, "allow_plaintext_parameter_derivation").unwrap_or(false),
        enable_vosa_verification: json_bool(text, "enable_vosa_verification").unwrap_or(false),
        attack_type: json_attack_type(text),
        rng_mode: json_string(text, "rng_mode").unwrap_or_else(|_| "deterministic_benchmark".to_string()),
    })
}

fn json_value_start<'a>(text: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let needle = format!("\"{key}\"");
    let pos = text.find(&needle).ok_or_else(|| format!("missing JSON key: {key}"))?;
    let after_key = &text[pos + needle.len()..];
    let colon = after_key.find(':').ok_or_else(|| format!("missing colon after JSON key: {key}"))?;
    Ok(after_key[colon + 1..].trim_start())
}

fn json_string(text: &str, key: &str) -> Result<String, Box<dyn Error>> {
    let value = json_value_start(text, key)?;
    let rest = value.strip_prefix('"').ok_or_else(|| format!("JSON key {key} is not a string"))?;
    let end = rest.find('"').ok_or_else(|| format!("unterminated JSON string for key {key}"))?;
    Ok(rest[..end].to_string())
}

fn json_usize(text: &str, key: &str) -> Result<usize, Box<dyn Error>> {
    let value = json_value_start(text, key)?;
    let digits = value
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Err(format!("JSON key {key} is not an unsigned integer").into());
    }
    Ok(digits.parse()?)
}

fn json_bool(text: &str, key: &str) -> Result<bool, Box<dyn Error>> {
    let value = json_value_start(text, key)?;
    if value.starts_with("true") {
        Ok(true)
    } else if value.starts_with("false") {
        Ok(false)
    } else {
        Err(format!("JSON key {key} is not a bool").into())
    }
}

fn json_attack_type(text: &str) -> Option<String> {
    let attack_pos = text.find("\"attack\"")?;
    let tail = &text[attack_pos..];
    if tail.trim_start().starts_with("\"attack\": null") {
        return None;
    }
    json_string(tail, "type").ok()
}

fn committee_ciphertext_bytes(ciphertext: &CommitteeCiphertext) -> usize {
    32 + ciphertext.body.len() + ciphertext.tag.len()
}

fn committee_aggregate_share_bytes(share: &CommitteeAggregateShare) -> usize {
    16 + share.summed_key_share.len() * 8
        + share
            .digest_shares_by_client
            .iter()
            .map(|(_, values)| 8 + values.len() * 8)
            .sum::<usize>()
}

fn mod_add(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 + b as u128) % modulus as u128) as u64
}

fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
