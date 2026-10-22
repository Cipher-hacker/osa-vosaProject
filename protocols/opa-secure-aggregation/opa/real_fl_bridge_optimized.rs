use opalwr_optimized::{
    paper_fl_benchmark_params, ClientUpload, CommitteeAggregate, CommitteeCiphertext, LwrShprg,
    OpaClient, OpaCommitteeMember, OpaServer, RoutedAuxShare,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Clone, Debug)]
struct Manifest {
    round_idx: u64,
    num_clients: usize,
    vector_length: usize,
    client_vector_file: String,
    result_sum_file: String,
    metrics_file: String,
    committee_size: usize,
    threshold: usize,
    input_offset: u64,
    allow_plaintext_parameter_derivation: bool,
    rng_mode: String,
}

#[derive(Clone, Debug, Default)]
struct Metrics {
    client_time_ms: f64,
    committee_time_ms: f64,
    server_time_ms: f64,
    ciphertext_bytes: usize,
    encrypted_aux_share_bytes: usize,
    client_message_bytes: usize,
    server_to_committee_bytes: usize,
    committee_to_server_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
enum RngMode {
    DeterministicBenchmark,
    OsRngSecurity,
}

impl RngMode {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "deterministic_benchmark" => Ok(Self::DeterministicBenchmark),
            "os_rng_security" => Ok(Self::OsRngSecurity),
            other => Err(format!("unsupported OPA rng_mode: {other}").into()),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_path = parse_args()?;
    let manifest_dir = manifest_path.parent().ok_or("manifest must have a parent")?;
    let manifest = parse_manifest(&fs::read_to_string(&manifest_path)?)?;
    validate_manifest(&manifest)?;
    let matrix = read_i64_matrix(
        &manifest_dir.join(&manifest.client_vector_file),
        manifest.num_clients,
        manifest.vector_length,
    )?;
    let rng_mode = RngMode::parse(&manifest.rng_mode)?;
    let params = paper_fl_benchmark_params(manifest.vector_length);
    if manifest.committee_size != params.committee_size || manifest.threshold != params.threshold_r {
        return Err("OPA-P85-FL fixes committee_size=50 and threshold=34".into());
    }
    let max_safe_sum = params.max_safe_aggregate_coordinate(manifest.num_clients)?;
    let public_shifted_sum_bound = (manifest.num_clients as u128)
        .checked_mul(2_u128 * manifest.input_offset as u128)
        .ok_or("OPA public shifted-sum bound overflow")?;
    if public_shifted_sum_bound > max_safe_sum {
        return Err(format!(
            "OPA-P85-FL public correctness bound failed: clients*2*offset={} > max_safe_sum={}",
            public_shifted_sum_bound, max_safe_sum
        ).into());
    }
    let shifted_inputs = encode_shifted(&matrix, manifest.input_offset, max_safe_sum)?;

    let setup_start = Instant::now();
    let mut setup_rng = make_rng(rng_mode, manifest.round_idx, 0, "setup");
    let shprg = LwrShprg::new(params.clone(), &mut setup_rng)?;
    let server = OpaServer::new(shprg);
    let committees = (1..=params.committee_size)
        .map(|id| {
            let mut rng = make_rng(rng_mode, manifest.round_idx, id, "committee_keypair");
            OpaCommitteeMember::new(id, &mut rng)
        })
        .collect::<Vec<_>>();
    let public_keys = committees.iter().map(|member| member.key_pair.public()).collect::<Vec<_>>();
    let setup_time_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let client_start = Instant::now();
    let uploads = shifted_inputs
        .iter()
        .enumerate()
        .map(|(index, values)| {
            let mut rng = make_rng(rng_mode, manifest.round_idx, index + 1, "client_upload");
            OpaClient { client_id: index + 1 }.encrypt(
                manifest.round_idx,
                values,
                &server.shprg,
                &public_keys,
                manifest.num_clients,
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let client_time_ms = client_start.elapsed().as_secs_f64() * 1000.0;

    let active_set = uploads.iter().map(|upload| upload.client_id).collect::<BTreeSet<_>>();
    let route_messages = (0..params.threshold_r)
        .map(|committee_index| serialize_route_batch(manifest.round_idx, &active_set, &uploads, committee_index))
        .collect::<Vec<_>>();
    let committee_start = Instant::now();
    let committee_outputs = committees
        .iter()
        .take(params.threshold_r)
        .zip(route_messages.iter())
        .map(|(member, bytes)| {
            let (iteration, routed_set, routed) = deserialize_route_batch(bytes)?;
            member.process_routed(iteration, &routed_set, &routed, &params)
                .map_err(|error| -> Box<dyn Error> { Box::new(error) })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let committee_time_ms = committee_start.elapsed().as_secs_f64() * 1000.0;

    let server_start = Instant::now();
    let shifted_sum = server.aggregate(manifest.round_idx, &uploads, &committee_outputs)?;
    let offset_sum = manifest.input_offset as i128 * manifest.num_clients as i128;
    let aggregate = shifted_sum
        .iter()
        .map(|&value| i64::try_from(value as i128 - offset_sum).map_err(|_| "OPA aggregate does not fit i64".into()))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let server_time_ms = server_start.elapsed().as_secs_f64() * 1000.0;

    let oracle = sum_matrix_columns(&matrix, manifest.vector_length)?;
    let max_abs_sum_error = aggregate.iter().zip(oracle.iter())
        .map(|(&lhs, &rhs)| (lhs as i128 - rhs as i128).abs()).max().unwrap_or(0);
    if max_abs_sum_error != 0 {
        return Err(format!("OPA aggregate mismatch: max_abs_sum_error={max_abs_sum_error}").into());
    }

    let metrics = Metrics {
        client_time_ms,
        committee_time_ms,
        server_time_ms,
        ciphertext_bytes: uploads.iter().map(|upload| upload.ciphertext.len() * 16).sum(),
        encrypted_aux_share_bytes: uploads.iter().flat_map(|upload| upload.encrypted_aux_shares.iter())
            .map(committee_ciphertext_bytes).sum(),
        client_message_bytes: uploads.iter().map(|upload| serialize_upload(upload).len()).sum(),
        server_to_committee_bytes: route_messages.iter().map(Vec::len).sum(),
        committee_to_server_bytes: committee_outputs.iter().map(committee_output_bytes).sum(),
    };
    write_i64_vector(&manifest_dir.join(&manifest.result_sum_file), &aggregate)?;
    write_metrics(
        &manifest_dir.join(&manifest.metrics_file),
        &manifest,
        &params,
        &metrics,
        setup_time_ms,
        max_safe_sum,
        public_shifted_sum_bound,
        max_abs_sum_error,
    )?;
    println!(
        "protocol=OPA-P85-FL clients={} vector_len={} p={} q={} client_ms={:.3} committee_ms={:.3} server_ms={:.3} correctness=pass",
        manifest.num_clients, manifest.vector_length, params.p, params.q,
        client_time_ms, committee_time_ms, server_time_ms
    );
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<(), Box<dyn Error>> {
    if manifest.num_clients == 0 || manifest.vector_length == 0 {
        return Err("num_clients and vector_length must be positive".into());
    }
    if manifest.allow_plaintext_parameter_derivation {
        return Err("OPA-P85-FL forbids plaintext-derived parameters".into());
    }
    Ok(())
}

fn encode_shifted(matrix: &[Vec<i64>], offset: u64, max_safe_sum: u128) -> Result<Vec<Vec<u64>>, Box<dyn Error>> {
    let mut shifted_sum = vec![0_u128; matrix.first().map(Vec::len).unwrap_or(0)];
    let mut output = Vec::with_capacity(matrix.len());
    for row in matrix {
        let encoded = row.iter().enumerate().map(|(column, &value)| {
            let shifted = value as i128 + offset as i128;
            if shifted < 0 || shifted > u64::MAX as i128 {
                return Err("OPA shifted input is outside u64".into());
            }
            shifted_sum[column] = shifted_sum[column]
                .checked_add(shifted as u128).ok_or("OPA shifted sum overflow")?;
            Ok(shifted as u64)
        }).collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        output.push(encoded);
    }
    if shifted_sum.iter().any(|&value| value > max_safe_sum) {
        return Err("OPA actual shifted sum exceeds the public correctness bound".into());
    }
    Ok(output)
}

fn make_rng(mode: RngMode, round: u64, party: usize, purpose: &str) -> StdRng {
    match mode {
        RngMode::DeterministicBenchmark => {
            let mut hash = Sha3_256::new();
            hash.update(b"opa_p85_fl_bridge_v1");
            hash.update(round.to_le_bytes());
            hash.update((party as u64).to_le_bytes());
            hash.update(purpose.as_bytes());
            let digest = hash.finalize();
            let mut seed = [0_u8; 32];
            seed.copy_from_slice(&digest[..32]);
            StdRng::from_seed(seed)
        }
        RngMode::OsRngSecurity => {
            let mut seed = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            StdRng::from_seed(seed)
        }
    }
}

fn serialize_route_batch(iteration: u64, active: &BTreeSet<usize>, uploads: &[ClientUpload], committee_index: usize) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, iteration);
    push_u64(&mut out, active.len() as u64);
    for &client_id in active { push_u64(&mut out, client_id as u64); }
    push_u64(&mut out, uploads.len() as u64);
    for upload in uploads {
        push_u64(&mut out, upload.client_id as u64);
        let ciphertext = &upload.encrypted_aux_shares[committee_index];
        out.extend_from_slice(&ciphertext.ephemeral_public);
        push_u64(&mut out, ciphertext.body.len() as u64);
        out.extend_from_slice(&ciphertext.body);
    }
    out
}

fn deserialize_route_batch(bytes: &[u8]) -> Result<(u64, BTreeSet<usize>, Vec<RoutedAuxShare>), Box<dyn Error>> {
    let mut offset = 0;
    let iteration = read_u64(bytes, &mut offset)?;
    let active_len = read_u64(bytes, &mut offset)? as usize;
    let mut active = BTreeSet::new();
    for _ in 0..active_len { active.insert(read_u64(bytes, &mut offset)? as usize); }
    let routed_len = read_u64(bytes, &mut offset)? as usize;
    let mut routed = Vec::with_capacity(routed_len);
    for _ in 0..routed_len {
        let client_id = read_u64(bytes, &mut offset)? as usize;
        let end = offset.checked_add(32).ok_or("route offset overflow")?;
        let mut ephemeral_public = [0_u8; 32];
        ephemeral_public.copy_from_slice(bytes.get(offset..end).ok_or("truncated route public key")?);
        offset = end;
        let body_len = read_u64(bytes, &mut offset)? as usize;
        let end = offset.checked_add(body_len).ok_or("route body overflow")?;
        let body = bytes.get(offset..end).ok_or("truncated route body")?.to_vec();
        offset = end;
        routed.push(RoutedAuxShare { client_id, ciphertext: CommitteeCiphertext { ephemeral_public, body } });
    }
    if offset != bytes.len() { return Err("trailing bytes in OPA route".into()); }
    Ok((iteration, active, routed))
}

fn serialize_committee_ciphertext(value: &CommitteeCiphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 8 + value.body.len());
    out.extend_from_slice(&value.ephemeral_public);
    push_u64(&mut out, value.body.len() as u64);
    out.extend_from_slice(&value.body);
    out
}

fn committee_ciphertext_bytes(value: &CommitteeCiphertext) -> usize {
    serialize_committee_ciphertext(value).len()
}

fn serialize_upload(upload: &ClientUpload) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, upload.client_id as u64);
    push_u64(&mut out, upload.iteration);
    push_u64(&mut out, upload.encoding_client_bound as u64);
    push_u64(&mut out, upload.ciphertext.len() as u64);
    for value in &upload.ciphertext {
        out.extend_from_slice(&value.to_le_bytes());
    }
    push_u64(&mut out, upload.encrypted_aux_shares.len() as u64);
    for share in &upload.encrypted_aux_shares {
        let bytes = serialize_committee_ciphertext(share);
        push_u64(&mut out, bytes.len() as u64);
        out.extend_from_slice(&bytes);
    }
    out
}

fn committee_output_bytes(value: &CommitteeAggregate) -> usize {
    8 + 8 + value.summed_seed_share.len() * 16 + 8 + value.digest_shares.len() * (8 + 16)
}

fn write_metrics(
    path: &Path,
    manifest: &Manifest,
    params: &opalwr_optimized::OpaParameters,
    metrics: &Metrics,
    setup_time_ms: f64,
    max_safe_sum: u128,
    public_shifted_sum_bound: u128,
    max_abs_sum_error: i128,
) -> Result<(), Box<dyn Error>> {
    let client_upload_bytes = metrics.client_message_bytes;
    let server_received_bytes = client_upload_bytes + metrics.committee_to_server_bytes;
    let committee_received_bytes = metrics.server_to_committee_bytes;
    let end_to_end_time_ms = metrics.client_time_ms + metrics.committee_time_ms + metrics.server_time_ms;
    let text = format!(
        concat!(
            "{{\n",
            "  \"protocol\": \"OPA\",\n",
            "  \"protocol_display_name\": \"OPA-P85-FL-optimized\",\n",
            "  \"protocol_variant\": \"OPA-LWR-fixed-q-optimized-p85-fl\",\n",
            "  \"real_protocol_execution\": true,\n",
            "  \"round_idx\": {},\n",
            "  \"active_clients\": {},\n",
            "  \"vector_length\": {},\n",
            "  \"committee_size\": {},\n",
            "  \"threshold\": {},\n",
            "  \"seed_dim\": {},\n",
            "  \"packed_secret_dim\": {},\n",
            "  \"p\": \"{}\",\n",
            "  \"q\": \"{}\",\n",
            "  \"stat_sec_bits\": {},\n",
            "  \"fixed_q_fast_reduction\": true,\n",
            "  \"full_paper_security_claimed\": false,\n",
            "  \"security_estimator_revalidated\": false,\n",
            "  \"parameters_derived_from_plaintext\": false,\n",
            "  \"input_offset\": {},\n",
            "  \"max_safe_aggregate_coordinate\": \"{}\",\n",
            "  \"public_shifted_sum_bound\": \"{}\",\n",
            "  \"public_correctness_bound_passed\": true,\n",
            "  \"setup_time_ms\": {:.6},\n",
            "  \"client_time_ms\": {:.6},\n",
            "  \"committee_time_ms\": {:.6},\n",
            "  \"server_time_ms\": {:.6},\n",
            "  \"verifier_time_ms\": 0.0,\n",
            "  \"end_to_end_time_ms\": {:.6},\n",
            "  \"client_upload_bytes\": {},\n",
            "  \"server_received_bytes\": {},\n",
            "  \"committee_received_bytes\": {},\n",
            "  \"verifier_received_bytes\": 0,\n",
            "  \"ciphertext_bytes\": {},\n",
            "  \"encrypted_aux_share_bytes\": {},\n",
            "  \"client_message_bytes\": {},\n",
            "  \"server_to_committee_bytes\": {},\n",
            "  \"committee_to_server_bytes\": {},\n",
            "  \"verification_enabled\": false,\n",
            "  \"verification_accepted\": null,\n",
            "  \"round_aborted\": false,\n",
            "  \"max_abs_sum_error\": {}\n",
            "}}\n"
        ),
        manifest.round_idx, manifest.num_clients, manifest.vector_length,
        params.committee_size, params.threshold_r, params.seed_dim, params.packed_secret_dim,
        params.p, params.q, params.stat_sec_bits, manifest.input_offset,
        max_safe_sum, public_shifted_sum_bound, setup_time_ms,
        metrics.client_time_ms, metrics.committee_time_ms, metrics.server_time_ms,
        end_to_end_time_ms, client_upload_bytes, server_received_bytes,
        committee_received_bytes, metrics.ciphertext_bytes, metrics.encrypted_aux_share_bytes,
        metrics.client_message_bytes,
        metrics.server_to_committee_bytes, metrics.committee_to_server_bytes, max_abs_sum_error
    );
    fs::write(path, text)?;
    Ok(())
}

fn read_i64_matrix(path: &Path, rows: usize, cols: usize) -> Result<Vec<Vec<i64>>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let expected = rows.checked_mul(cols).and_then(|n| n.checked_mul(8)).ok_or("matrix size overflow")?;
    if bytes.len() != expected { return Err(format!("expected {expected} matrix bytes, got {}", bytes.len()).into()); }
    Ok(bytes.chunks_exact(cols * 8).map(|row| row.chunks_exact(8).map(|chunk| {
        let mut value = [0_u8; 8]; value.copy_from_slice(chunk); i64::from_le_bytes(value)
    }).collect()).collect())
}

fn sum_matrix_columns(matrix: &[Vec<i64>], cols: usize) -> Result<Vec<i64>, Box<dyn Error>> {
    let mut sums = vec![0_i128; cols];
    for row in matrix { for (sum, &value) in sums.iter_mut().zip(row) { *sum += value as i128; } }
    sums.into_iter().map(|value| i64::try_from(value).map_err(|_| "column sum does not fit i64".into())).collect()
}

fn write_i64_vector(path: &Path, values: &[i64]) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values { bytes.extend_from_slice(&value.to_le_bytes()); }
    fs::write(path, bytes)?;
    Ok(())
}

fn parse_args() -> Result<PathBuf, Box<dyn Error>> {
    let mut path = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--manifest" { path = Some(PathBuf::from(args.next().ok_or("--manifest needs a path")?)); }
        else { return Err(format!("unknown argument: {arg}").into()); }
    }
    path.ok_or_else(|| "--manifest is required".into())
}

fn parse_manifest(text: &str) -> Result<Manifest, Box<dyn Error>> {
    Ok(Manifest {
        round_idx: json_u64(text, "round_idx")?,
        num_clients: json_usize(text, "num_clients")?,
        vector_length: json_usize(text, "vector_length")?,
        client_vector_file: json_string(text, "client_vector_file")?,
        result_sum_file: json_string(text, "result_sum_file")?,
        metrics_file: json_string(text, "metrics_file")?,
        committee_size: json_usize(text, "committee_size")?,
        threshold: json_usize(text, "threshold")?,
        input_offset: json_u64(text, "input_offset")?,
        allow_plaintext_parameter_derivation: json_bool(text, "allow_plaintext_parameter_derivation")?,
        rng_mode: json_string(text, "rng_mode")?,
    })
}

fn json_start<'a>(text: &'a str, key: &str) -> Result<&'a str, Box<dyn Error>> {
    let needle = format!("\"{key}\"");
    let after = &text[text.find(&needle).ok_or_else(|| format!("missing JSON key {key}"))? + needle.len()..];
    Ok(after[after.find(':').ok_or("missing JSON colon")? + 1..].trim_start())
}

fn json_string(text: &str, key: &str) -> Result<String, Box<dyn Error>> {
    let value = json_start(text, key)?.strip_prefix('"').ok_or("JSON value is not a string")?;
    Ok(value[..value.find('"').ok_or("unterminated JSON string")?].to_string())
}

fn json_u64(text: &str, key: &str) -> Result<u64, Box<dyn Error>> {
    let digits = json_start(text, key)?.chars().take_while(char::is_ascii_digit).collect::<String>();
    if digits.is_empty() { return Err(format!("JSON key {key} is not unsigned").into()); }
    Ok(digits.parse()?)
}

fn json_usize(text: &str, key: &str) -> Result<usize, Box<dyn Error>> { Ok(json_u64(text, key)? as usize) }

fn json_bool(text: &str, key: &str) -> Result<bool, Box<dyn Error>> {
    let value = json_start(text, key)?;
    if value.starts_with("true") { Ok(true) } else if value.starts_with("false") { Ok(false) }
    else { Err(format!("JSON key {key} is not bool").into()) }
}

fn push_u64(output: &mut Vec<u8>, value: u64) { output.extend_from_slice(&value.to_le_bytes()); }

fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, Box<dyn Error>> {
    let end = offset.checked_add(8).ok_or("u64 offset overflow")?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(bytes.get(*offset..end).ok_or("truncated u64")?);
    *offset = end;
    Ok(u64::from_le_bytes(value))
}
