use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use ahe_traits::AheBase;
use client_traits::SecureAggregationClient;
use decryptor_traits::SecureAggregationDecryptor;
use kahe_traits::KaheBase;
use proto_serialization_traits::ToProto;
use protobuf::prelude::*;
use server_traits::SecureAggregationServer;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use testing_utils::generate_random_nonce;
use verifier_traits::SecureAggregationVerifier;
use willow_v1_client::WillowV1Client;
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
use willow_v1_server::{ServerState, WillowV1Server};
use willow_v1_verifier::{VerifierState, WillowV1Verifier};

const DEFAULT_ID: &str = "default";
const CONTEXT_STRING: &[u8] = b"willow_real_fl_bridge_context";
const WILLOW_LIMB_BASE: u64 = 1_u64 << 31;

#[derive(Clone, Debug)]
struct Manifest {
    round_idx: u64,
    num_clients: usize,
    vector_length: usize,
    client_vector_file: String,
    result_sum_file: String,
    metrics_file: String,
    chunk_size: usize,
    committee_size: usize,
    threshold: usize,
    input_offset: Option<u64>,
    limb_count: Option<usize>,
    allow_plaintext_parameter_derivation: bool,
}

#[derive(Clone, Debug, Default)]
struct BridgeMetrics {
    client_time_ms: f64,
    committee_time_ms: f64,
    server_time_ms: f64,
    verifier_time_ms: f64,
    ciphertext_bytes: usize,
    verifier_received_bytes: usize,
    server_to_committee_bytes: usize,
    committee_to_server_bytes: usize,
    input_offset: u64,
    input_bound: u64,
    limb_count: usize,
    chunks: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_path = parse_args()?;
    let manifest_dir = manifest_path
        .parent()
        .ok_or("manifest must have a parent directory")?
        .to_path_buf();
    let manifest_text = fs::read_to_string(&manifest_path)?;
    let manifest = parse_manifest(&manifest_text)?;

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

    let matrix = read_i64_matrix(
        &manifest_dir.join(&manifest.client_vector_file),
        manifest.num_clients,
        manifest.vector_length,
    )?;
    let input_offset = if manifest.allow_plaintext_parameter_derivation {
        manifest.input_offset.unwrap_or(choose_input_offset(&matrix)?)
    } else {
        manifest.input_offset.ok_or("Willow requires public input_offset")?
    };
    let limb_count = if manifest.allow_plaintext_parameter_derivation {
        manifest.limb_count.unwrap_or(choose_limb_count(&matrix, input_offset)?)
    } else {
        manifest.limb_count.ok_or("Willow requires public limb_count")?
    };

    let mut aggregate = vec![0_i64; manifest.vector_length];
    let mut metrics = BridgeMetrics {
        input_offset,
        input_bound: WILLOW_LIMB_BASE,
        limb_count,
        chunks: manifest.vector_length.div_ceil(manifest.chunk_size),
        ..BridgeMetrics::default()
    };

    for chunk_index in 0..metrics.chunks {
        let start = chunk_index * manifest.chunk_size;
        let end = ((chunk_index + 1) * manifest.chunk_size).min(manifest.vector_length);
        let chunk_result =
            run_willow_chunk(&matrix, start, end, &manifest, input_offset, limb_count, chunk_index)?;
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

    write_i64_vector(&manifest_dir.join(&manifest.result_sum_file), &aggregate)?;
    write_metrics(&manifest_dir.join(&manifest.metrics_file), &manifest, &metrics, max_abs_sum_error)?;
    if max_abs_sum_error != 0 {
        return Err(format!("Willow aggregate mismatch: max_abs_sum_error={max_abs_sum_error}").into());
    }

    println!(
        "protocol=Willow active_clients={} vector_len={} chunks={} offset={} limb_base={} limbs={} client_ms={:.3} committee_ms={:.3} server_ms={:.3} max_abs_sum_error={}",
        manifest.num_clients,
        manifest.vector_length,
        metrics.chunks,
        input_offset,
        WILLOW_LIMB_BASE,
        limb_count,
        metrics.client_time_ms,
        metrics.committee_time_ms,
        metrics.server_time_ms,
        max_abs_sum_error
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct ChunkResult {
    aggregate: Vec<i64>,
    metrics: BridgeMetrics,
}

fn run_willow_chunk(
    matrix: &[Vec<i64>],
    start: usize,
    end: usize,
    manifest: &Manifest,
    input_offset: u64,
    limb_count: usize,
    _chunk_index: usize,
) -> Result<ChunkResult, Box<dyn Error>> {
    let chunk_len = end - start;
    let encoded_chunk_len = chunk_len
        .checked_mul(limb_count)
        .ok_or("Willow encoded chunk length overflow")?;
    if WILLOW_LIMB_BASE > i64::MAX as u64 {
        return Err("Willow input bound does not fit i64".into());
    }
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            DEFAULT_ID.to_string(),
            (encoded_chunk_len as isize, WILLOW_LIMB_BASE as i64),
        )]),
        max_number_of_decryptors: manifest.committee_size as i64,
        max_number_of_clients: manifest.num_clients as i64,
        max_decryptor_dropouts: (manifest.committee_size - manifest.threshold) as i64,
        key_id: format!("willow-real-fl-{}", manifest.round_idx).into_bytes(),
    };
    let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config)?;
    let kahe = Rc::new(ShellKahe::new(kahe_config, CONTEXT_STRING)?);
    let vahe = Rc::new(ShellVahe::new(ahe_config, CONTEXT_STRING)?);
    let server = WillowV1Server { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();

    let mut decryptor_states = Vec::with_capacity(manifest.committee_size);
    let mut decryptors = Vec::with_capacity(manifest.committee_size);
    for _ in 0..manifest.committee_size {
        decryptor_states.push(DecryptorState::default());
        decryptors.push(WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe))?);
    }
    let mut server_state = ServerState::default();
    for (idx, decryptor) in decryptors.iter().enumerate() {
        let public_key_share = decryptor.create_public_key_share(&mut decryptor_states[idx])?;
        server.handle_decryptor_public_key_share(
            public_key_share,
            format!("Decryptor {idx}").as_str(),
            &mut server_state,
        )?;
    }
    let public_key = server.create_decryptor_public_key(&server_state)?;
    let inputs = encode_shifted_chunk(matrix, start, end, input_offset, limb_count)?;

    let t0 = Instant::now();
    let mut client_messages = Vec::with_capacity(manifest.num_clients);
    let mut ciphertext_bytes = 0_usize;
    for input_values in &inputs {
        let client = WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))?;
        let plaintext_owned = HashMap::from([(DEFAULT_ID.to_string(), input_values.clone())]);
        let plaintext = ShellKahe::plaintext_as_slice(&plaintext_owned);
        let nonce = generate_random_nonce();
        let message = client.create_client_message(&plaintext, &public_key, &nonce)?;
        ciphertext_bytes += message.to_proto(&client)?.serialize()?.len();
        client_messages.push(message);
    }
    let client_time_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut server_handle_ms = 0.0_f64;
    let mut verifier_time_ms = 0.0_f64;
    let mut verifier_received_bytes = 0_usize;
    let mut verifier_contributions = Vec::with_capacity(manifest.num_clients);
    for message in client_messages {
        let t_split = Instant::now();
        let (ciphertext_contribution, dec_req_contribution) = server.split_client_message(message)?;
        server_handle_ms += t_split.elapsed().as_secs_f64() * 1000.0;

        verifier_received_bytes += dec_req_contribution.to_proto(&server)?.serialize()?.len();
        verifier_contributions.push(dec_req_contribution);

        let t_handle = Instant::now();
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)?;
        server_handle_ms += t_handle.elapsed().as_secs_f64() * 1000.0;
    }

    let t_verify = Instant::now();
    verifier_contributions.sort_by(|lhs, rhs| lhs.nonce.cmp(&rhs.nonce));
    for contribution in verifier_contributions {
        verifier.verify_and_include(contribution, &mut verifier_state)?;
    }
    verifier_time_ms += t_verify.elapsed().as_secs_f64() * 1000.0;

    let t_verify_request = Instant::now();
    let partial_decryption_request =
        verifier.create_partial_decryption_request(verifier_state)?;
    verifier_time_ms += t_verify_request.elapsed().as_secs_f64() * 1000.0;
    let request_bytes = partial_decryption_request
        .to_proto(&decryptors[0])?
        .serialize()?
        .len();
    let server_to_committee_bytes = request_bytes * manifest.threshold;

    let t2 = Instant::now();
    let mut committee_to_server_bytes = 0_usize;
    for idx in 0..manifest.threshold {
        let response = decryptors[idx]
            .handle_partial_decryption_request(partial_decryption_request.clone(), &decryptor_states[idx])?;
        committee_to_server_bytes += response.to_proto(&server)?.serialize()?.len();
        server.handle_partial_decryption(response, &mut server_state)?;
    }
    let committee_time_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let t3 = Instant::now();
    let recovered = server.recover_aggregation_result(&server_state)?;
    let server_recover_ms = t3.elapsed().as_secs_f64() * 1000.0;
    let shifted_limb_sums = recovered.get(DEFAULT_ID).ok_or("missing Willow aggregate output")?;
    if shifted_limb_sums.len() < encoded_chunk_len {
        return Err("Willow aggregate output is shorter than encoded chunk length".into());
    }

    let offset_sum = (input_offset as i128)
        .checked_mul(manifest.num_clients as i128)
        .ok_or("Willow offset sum overflow")?;
    let mut aggregate = Vec::with_capacity(chunk_len);
    for coord_idx in 0..chunk_len {
        let mut shifted_sum = 0_u128;
        let mut multiplier = 1_u128;
        for limb_idx in 0..limb_count {
            let flat_idx = coord_idx
                .checked_mul(limb_count)
                .and_then(|base| base.checked_add(limb_idx))
                .ok_or("Willow limb index overflow")?;
            shifted_sum = shifted_sum
                .checked_add((shifted_limb_sums[flat_idx] as u128).checked_mul(multiplier).ok_or("Willow limb reconstruction overflow")?)
                .ok_or("Willow shifted sum overflow")?;
            multiplier = multiplier
                .checked_mul(WILLOW_LIMB_BASE as u128)
                .ok_or("Willow limb multiplier overflow")?;
        }
        if shifted_sum > i128::MAX as u128 {
            return Err("Willow reconstructed shifted sum does not fit i128".into());
        }
        let signed = shifted_sum as i128 - offset_sum;
        if signed < i64::MIN as i128 || signed > i64::MAX as i128 {
            return Err("Willow decoded aggregate does not fit int64".into());
        }
        aggregate.push(signed as i64);
    }

    Ok(ChunkResult {
        aggregate,
        metrics: BridgeMetrics {
            client_time_ms,
            committee_time_ms,
            server_time_ms: server_handle_ms + server_recover_ms,
            verifier_time_ms,
            ciphertext_bytes,
            verifier_received_bytes,
            server_to_committee_bytes,
            committee_to_server_bytes,
            input_offset,
            input_bound: WILLOW_LIMB_BASE,
            limb_count,
            chunks: 1,
        },
    })
}

fn merge_metrics(acc: &mut BridgeMetrics, next: BridgeMetrics) {
    acc.client_time_ms += next.client_time_ms;
    acc.committee_time_ms += next.committee_time_ms;
    acc.server_time_ms += next.server_time_ms;
    acc.verifier_time_ms += next.verifier_time_ms;
    acc.ciphertext_bytes += next.ciphertext_bytes;
    acc.verifier_received_bytes += next.verifier_received_bytes;
    acc.server_to_committee_bytes += next.server_to_committee_bytes;
    acc.committee_to_server_bytes += next.committee_to_server_bytes;
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
                    return Err("shifted Willow input is negative".into());
                }
                let mut remaining = shifted as u128;
                for _ in 0..limb_count {
                    encoded.push((remaining % WILLOW_LIMB_BASE as u128) as u64);
                    remaining /= WILLOW_LIMB_BASE as u128;
                }
                if remaining != 0 {
                    return Err("Willow limb count is insufficient for shifted input".into());
                }
            }
            Ok(encoded)
        })
        .collect()
}

fn choose_input_offset(matrix: &[Vec<i64>]) -> Result<u64, Box<dyn Error>> {
    let max_abs = matrix
        .iter()
        .flat_map(|row| row.iter())
        .map(|&value| (value as i128).abs())
        .max()
        .unwrap_or(0);
    if max_abs > u64::MAX as i128 {
        return Err("Willow input offset does not fit u64".into());
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
    if max_shifted < 0 {
        return Err("Willow shifted input is negative".into());
    }
    let mut limb_count = 1_usize;
    let mut capacity = WILLOW_LIMB_BASE as u128;
    let max_shifted = max_shifted as u128;
    while max_shifted >= capacity {
        limb_count = limb_count.checked_add(1).ok_or("Willow limb count overflow")?;
        capacity = capacity
            .checked_mul(WILLOW_LIMB_BASE as u128)
            .ok_or("Willow limb capacity overflow")?;
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

fn write_metrics(
    path: &Path,
    manifest: &Manifest,
    metrics: &BridgeMetrics,
    max_abs_sum_error: i128,
) -> Result<(), Box<dyn Error>> {
    let server_received_bytes = metrics.ciphertext_bytes + metrics.committee_to_server_bytes;
    let committee_received_bytes = metrics.server_to_committee_bytes;
    let end_to_end_time_ms =
        metrics.client_time_ms + metrics.committee_time_ms + metrics.server_time_ms + metrics.verifier_time_ms;
    let round_aborted = max_abs_sum_error != 0;
    let abort_reason = if round_aborted {
        format!("Willow aggregate mismatch: max_abs_sum_error={max_abs_sum_error}")
    } else {
        String::new()
    };
    let text = format!(
        concat!(
            "{{\n",
            "  \"protocol\": \"Willow\",\n",
            "  \"protocol_display_name\": \"Willow-FL-bridge\",\n",
            "  \"protocol_variant\": \"Willow-honest-client-baseline\",\n",
            "  \"real_protocol_execution\": true,\n",
            "  \"round_idx\": {},\n",
            "  \"active_clients\": {},\n",
            "  \"vector_length\": {},\n",
            "  \"chunk_size\": {},\n",
            "  \"chunks\": {},\n",
            "  \"committee_size\": {},\n",
            "  \"threshold\": {},\n",
            "  \"input_offset\": {},\n",
            "  \"input_bound\": {},\n",
            "  \"limb_count\": {},\n",
            "  \"parameters_derived_from_plaintext\": {},\n",
            "  \"public_bounds_present\": {},\n",
            "  \"client_time_ms\": {:.6},\n",
            "  \"committee_time_ms\": {:.6},\n",
            "  \"server_time_ms\": {:.6},\n",
            "  \"verifier_time_ms\": {:.6},\n",
            "  \"end_to_end_time_ms\": {:.6},\n",
            "  \"client_upload_bytes\": {},\n",
            "  \"server_received_bytes\": {},\n",
            "  \"committee_received_bytes\": {},\n",
            "  \"verifier_received_bytes\": {},\n",
            "  \"server_to_committee_bytes\": {},\n",
            "  \"committee_to_server_bytes\": {},\n",
            "  \"verification_enabled\": false,\n",
            "  \"verification_accepted\": null,\n",
            "  \"round_aborted\": {},\n",
            "  \"abort_reason\": \"{}\",\n",
            "  \"willow_kahe_backend\": \"ShellKahe\",\n",
            "  \"willow_kahe_is_toy\": false,\n",
            "  \"willow_key_sampling_source\": \"ShellKahe::key_gen\",\n",
            "  \"willow_error_sampling_source\": \"ShellKahe::encrypt\",\n",
            "  \"kahe_backend\": \"ShellKahe\",\n",
            "  \"kahe_backend_aligned_with_willow\": true,\n",
            "  \"kahe_sampling_aligned_with_willow\": true,\n",
            "  \"paper_level_crypto_parameters\": \"unknown_shell_source_external\",\n",
            "  \"missing_security_evidence\": \"shell_source_external_or_not_fully_audited\",\n",
            "  \"malicious_client_security\": false,\n",
            "  \"input_validation_enabled\": false,\n",
            "  \"scrape_test_enabled\": false,\n",
            "  \"lattice_zk_enabled\": false,\n",
            "  \"full_paper_security_claimed\": false,\n",
            "  \"max_abs_sum_error\": {}\n",
            "}}\n"
        ),
        manifest.round_idx,
        manifest.num_clients,
        manifest.vector_length,
        manifest.chunk_size,
        metrics.chunks,
        manifest.committee_size,
        manifest.threshold,
        metrics.input_offset,
        metrics.input_bound,
        metrics.limb_count,
        if manifest.input_offset.is_some() && manifest.limb_count.is_some() { "false" } else { "true" },
        if manifest.input_offset.is_some() && manifest.limb_count.is_some() { "true" } else { "false" },
        metrics.client_time_ms,
        metrics.committee_time_ms,
        metrics.server_time_ms,
        metrics.verifier_time_ms,
        end_to_end_time_ms,
        metrics.ciphertext_bytes,
        server_received_bytes,
        committee_received_bytes,
        metrics.verifier_received_bytes,
        metrics.server_to_committee_bytes,
        metrics.committee_to_server_bytes,
        if round_aborted { "true" } else { "false" },
        escape_json(&abort_reason),
        max_abs_sum_error
    );
    fs::write(path, text)?;
    Ok(())
}

fn parse_args() -> Result<PathBuf, Box<dyn Error>> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => {
                manifest_path = Some(PathBuf::from(args.next().ok_or("--manifest needs a path")?));
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }
    manifest_path.ok_or_else(|| "--manifest is required".into())
}

fn parse_manifest(text: &str) -> Result<Manifest, Box<dyn Error>> {
    Ok(Manifest {
        round_idx: json_usize(text, "round_idx").unwrap_or(1) as u64,
        num_clients: json_usize(text, "num_clients")?,
        vector_length: json_usize(text, "vector_length")?,
        client_vector_file: json_string(text, "client_vector_file")?,
        result_sum_file: json_string(text, "result_sum_file")?,
        metrics_file: json_string(text, "metrics_file")?,
        chunk_size: json_usize(text, "chunk_size")?,
        committee_size: json_usize(text, "committee_size")?,
        threshold: json_usize(text, "threshold")?,
        input_offset: json_usize(text, "input_offset").ok().map(|value| value as u64),
        limb_count: json_usize(text, "limb_count").ok(),
        allow_plaintext_parameter_derivation: json_bool(text, "allow_plaintext_parameter_derivation").unwrap_or(false),
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

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
