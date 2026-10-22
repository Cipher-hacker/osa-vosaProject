use crate::protocol::{
    paper_benchmark_params, ClientUpload, CommitteeAggregate, CommitteeCiphertext, LwrShprg,
    OpaClient, OpaCommitteeMember, OpaServer, RoutedAuxShare,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

struct ClientBatch {
    messages: Vec<Vec<u8>>,
    operation_seconds: Vec<f64>,
    wall_seconds: f64,
}

pub fn run(arithmetic_backend: &str) {
    let n_clients = env_usize_any(&["BENCH_N_CLIENTS", "OPA_N_CLIENTS"], 1_000);
    let vector_len = env_usize_any(&["BENCH_VECTOR_LEN", "OPA_VECTOR_LEN"], 10_000);
    let active_clients = env_usize_any(
        &["BENCH_ACTIVE_CLIENTS"],
        n_clients.saturating_sub(env_usize_any(&["OPA_DROPPED_CLIENTS"], 200)),
    );
    let bench_threads = env_usize_any(&["BENCH_THREADS"], default_thread_count()).max(1);
    let mut params = paper_benchmark_params(vector_len);
    params.committee_size = env_usize_any(&["BENCH_COMMITTEE_SIZE"], params.committee_size);
    params.threshold_r =
        env_usize_any(&["BENCH_THRESHOLD", "OPA_THRESHOLD_R"], params.threshold_r);
    assert!(active_clients <= n_clients);
    assert!(params.threshold_r <= params.committee_size);
    let max_safe_coordinate = params.max_safe_aggregate_coordinate(n_clients).unwrap();
    assert!(max_safe_coordinate >= 7, "standard OPA correctness bound is below 7");

    let setup_start = Instant::now();
    let mut setup_rng = StdRng::seed_from_u64(7);
    let shprg = LwrShprg::new(params.clone(), &mut setup_rng).unwrap();
    let server = OpaServer::new(shprg);
    let committees = (1..=params.committee_size)
        .map(|id| OpaCommitteeMember::new(id, &mut setup_rng))
        .collect::<Vec<_>>();
    let committee_public_keys = committees
        .iter()
        .map(|member| member.key_pair.public())
        .collect::<Vec<_>>();
    let one_input = vec![1_u64; vector_len];
    let zero_input = vec![0_u64; vector_len];
    let setup_seconds = setup_start.elapsed().as_secs_f64();

    let mut sample_rng = StdRng::seed_from_u64(10_000);
    let sample_start = Instant::now();
    let sample_upload = OpaClient { client_id: 1 }
        .encrypt(
            1,
            &one_input,
            &server.shprg,
            &committee_public_keys,
            n_clients,
            &mut sample_rng,
        )
        .unwrap();
    let sample_bytes = serialize_upload(&sample_upload);
    std::hint::black_box(&sample_bytes);
    let client_single_seconds = sample_start.elapsed().as_secs_f64();

    let online_start = Instant::now();
    let client_batch = parallel_clients(
        active_clients,
        bench_threads,
        n_clients,
        &one_input,
        &zero_input,
        &server.shprg,
        &committee_public_keys,
    );
    let client_to_server_bytes = client_batch.messages.iter().map(Vec::len).sum::<usize>();

    let initial_server_start = Instant::now();
    let uploads = client_batch
        .messages
        .iter()
        .map(|bytes| deserialize_upload(bytes))
        .collect::<Vec<_>>();
    let active_set = uploads.iter().map(|upload| upload.client_id).collect::<BTreeSet<_>>();
    assert_eq!(active_set.len(), active_clients, "duplicate OPA client identifiers");
    assert!(active_set.iter().all(|&id| id > 0 && id <= n_clients));
    let route_messages = (0..params.threshold_r)
        .map(|committee_index| {
            serialize_route_batch(1, &active_set, &uploads, committee_index)
        })
        .collect::<Vec<_>>();
    let mut server_seconds = initial_server_start.elapsed().as_secs_f64();
    let server_to_committee_bytes = route_messages.iter().map(Vec::len).sum::<usize>();

    let mut committee_operation_seconds = Vec::with_capacity(params.threshold_r);
    let mut committee_messages = Vec::with_capacity(params.threshold_r);
    for (member, route_bytes) in committees.iter().take(params.threshold_r).zip(&route_messages) {
        let member_start = Instant::now();
        let (iteration, local_active_set, routed) = deserialize_route_batch(route_bytes);
        let output = member
            .process_routed(iteration, &local_active_set, &routed, &params)
            .unwrap();
        let bytes = serialize_committee_output(&output);
        committee_operation_seconds.push(member_start.elapsed().as_secs_f64());
        committee_messages.push(bytes);
    }
    let committee_to_server_bytes = committee_messages.iter().map(Vec::len).sum::<usize>();

    let final_server_start = Instant::now();
    let committee_outputs = committee_messages
        .iter()
        .map(|bytes| deserialize_committee_output(bytes))
        .collect::<Vec<_>>();
    let aggregate = server.aggregate(1, &uploads, &committee_outputs).unwrap();
    server_seconds += final_server_start.elapsed().as_secs_f64();
    let online_wall_seconds = online_start.elapsed().as_secs_f64();

    let expected = active_clients.min(7) as u64;
    assert_eq!(aggregate.len(), vector_len);
    assert!(
        aggregate.iter().all(|&value| value == expected),
        "OPA aggregate mismatch: expected {}, first values {:?}",
        expected,
        &aggregate[..aggregate.len().min(8)]
    );

    let committee_single_seconds = mean(&committee_operation_seconds);
    let client_observed_mean_seconds = mean(&client_batch.operation_seconds);
    let total_bytes = client_to_server_bytes + server_to_committee_bytes + committee_to_server_bytes;
    println!(
        "protocol=OPA-LWR-full-online arithmetic_backend={} implementation_scope=figure2_flow_pke_routed_packed_shares n_clients={} active_clients={} vector_len={} committee_size={} threshold_r={} seed_dim={} packed_secret_dim={} packed_share_count={} p={} p_log2={} q_bits={} stat_sec_bits={} max_safe_aggregate_coordinate={} bench_threads={} setup_s={:.6} client_compute_s={:.6} client_observed_mean_s={:.6} client_batch_wall_s={:.6} committee_compute_s={:.6} verifier_compute_s=0.000000 server_compute_s={:.6} online_wall_s={:.6} client_to_server_bytes={} server_to_committee_bytes={} committee_to_server_bytes={} client_bytes_mean={:.3} committee_receive_bytes_mean={:.3} committee_send_bytes_mean={:.3} committee_bytes_mean={:.3} server_receive_bytes={} server_send_bytes={} total_bytes={} correctness=pass",
        arithmetic_backend,
        n_clients,
        active_clients,
        vector_len,
        params.committee_size,
        params.threshold_r,
        params.seed_dim,
        params.packed_secret_dim,
        params.seed_dim / params.packed_secret_dim,
        params.p,
        params.p.trailing_zeros(),
        128 - params.q.leading_zeros(),
        params.stat_sec_bits,
        max_safe_coordinate,
        bench_threads,
        setup_seconds,
        client_single_seconds,
        client_observed_mean_seconds,
        client_batch.wall_seconds,
        committee_single_seconds,
        server_seconds,
        online_wall_seconds,
        client_to_server_bytes,
        server_to_committee_bytes,
        committee_to_server_bytes,
        client_to_server_bytes as f64 / active_clients as f64,
        server_to_committee_bytes as f64 / params.threshold_r as f64,
        committee_to_server_bytes as f64 / params.threshold_r as f64,
        (server_to_committee_bytes + committee_to_server_bytes) as f64
            / params.threshold_r as f64,
        client_to_server_bytes + committee_to_server_bytes,
        server_to_committee_bytes,
        total_bytes,
    );
}

#[allow(clippy::too_many_arguments)]
fn parallel_clients(
    active_clients: usize,
    thread_count: usize,
    encoding_client_bound: usize,
    one_input: &[u64],
    zero_input: &[u64],
    shprg: &LwrShprg,
    committee_public_keys: &[curve25519_dalek::ristretto::RistrettoPoint],
) -> ClientBatch {
    let workers = thread_count.min(active_clients).max(1);
    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let (wall_seconds, results) = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * active_clients / workers;
            let end = (worker + 1) * active_clients / workers;
            let local_ready = Arc::clone(&ready);
            let local_go = Arc::clone(&go);
            handles.push(scope.spawn(move || {
                local_ready.wait();
                local_go.wait();
                let mut output = Vec::with_capacity(end - start);
                for client_index in start..end {
                    let client_id = client_index + 1;
                    let input = if client_id <= 7 { one_input } else { zero_input };
                    let mut rng = StdRng::seed_from_u64(10_000 + client_index as u64);
                    let operation_start = Instant::now();
                    let upload = OpaClient { client_id }
                        .encrypt(
                            1,
                            input,
                            shprg,
                            committee_public_keys,
                            encoding_client_bound,
                            &mut rng,
                        )
                        .unwrap();
                    let bytes = serialize_upload(&upload);
                    output.push((bytes, operation_start.elapsed().as_secs_f64()));
                }
                output
            }));
        }
        ready.wait();
        let wall_start = Instant::now();
        go.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        (wall_start.elapsed().as_secs_f64(), results)
    });
    let mut messages = Vec::with_capacity(active_clients);
    let mut operation_seconds = Vec::with_capacity(active_clients);
    for worker_output in results {
        for (message, seconds) in worker_output {
            messages.push(message);
            operation_seconds.push(seconds);
        }
    }
    ClientBatch { messages, operation_seconds, wall_seconds }
}

fn serialize_upload(upload: &ClientUpload) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, upload.client_id as u64);
    push_u64(&mut out, upload.iteration);
    push_u64(&mut out, upload.encoding_client_bound as u64);
    push_u64(&mut out, upload.ciphertext.len() as u64);
    for &value in &upload.ciphertext {
        push_u128(&mut out, value);
    }
    push_u64(&mut out, upload.encrypted_aux_shares.len() as u64);
    for share in &upload.encrypted_aux_shares {
        let bytes = serialize_committee_ciphertext(share);
        push_blob(&mut out, &bytes);
    }
    out
}

fn deserialize_upload(bytes: &[u8]) -> ClientUpload {
    let mut offset = 0;
    let client_id = read_u64(bytes, &mut offset) as usize;
    let iteration = read_u64(bytes, &mut offset);
    let encoding_client_bound = read_u64(bytes, &mut offset) as usize;
    let ciphertext_len = read_u64(bytes, &mut offset) as usize;
    let ciphertext = (0..ciphertext_len)
        .map(|_| read_u128(bytes, &mut offset))
        .collect::<Vec<_>>();
    let share_count = read_u64(bytes, &mut offset) as usize;
    let encrypted_aux_shares = (0..share_count)
        .map(|_| deserialize_committee_ciphertext(read_blob(bytes, &mut offset)))
        .collect::<Vec<_>>();
    assert_eq!(offset, bytes.len());
    ClientUpload {
        client_id,
        iteration,
        encoding_client_bound,
        ciphertext,
        encrypted_aux_shares,
    }
}

fn serialize_route_batch(
    iteration: u64,
    active_set: &BTreeSet<usize>,
    uploads: &[ClientUpload],
    committee_index: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, iteration);
    push_u64(&mut out, active_set.len() as u64);
    for &client_id in active_set {
        push_u64(&mut out, client_id as u64);
    }
    push_u64(&mut out, uploads.len() as u64);
    for upload in uploads {
        push_u64(&mut out, upload.client_id as u64);
        let bytes = serialize_committee_ciphertext(&upload.encrypted_aux_shares[committee_index]);
        push_blob(&mut out, &bytes);
    }
    out
}

fn deserialize_route_batch(bytes: &[u8]) -> (u64, BTreeSet<usize>, Vec<RoutedAuxShare>) {
    let mut offset = 0;
    let iteration = read_u64(bytes, &mut offset);
    let active_count = read_u64(bytes, &mut offset) as usize;
    let active_set = (0..active_count)
        .map(|_| read_u64(bytes, &mut offset) as usize)
        .collect::<BTreeSet<_>>();
    let share_count = read_u64(bytes, &mut offset) as usize;
    let routed = (0..share_count)
        .map(|_| {
            let client_id = read_u64(bytes, &mut offset) as usize;
            let ciphertext = deserialize_committee_ciphertext(read_blob(bytes, &mut offset));
            RoutedAuxShare { client_id, ciphertext }
        })
        .collect::<Vec<_>>();
    assert_eq!(offset, bytes.len());
    (iteration, active_set, routed)
}

fn serialize_committee_output(output: &CommitteeAggregate) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, output.committee_member_id as u64);
    push_u64(&mut out, output.summed_seed_share.len() as u64);
    for &value in &output.summed_seed_share {
        push_u128(&mut out, value);
    }
    push_u64(&mut out, output.digest_shares.len() as u64);
    for (&client_id, &value) in &output.digest_shares {
        push_u64(&mut out, client_id as u64);
        push_u128(&mut out, value);
    }
    out
}

fn deserialize_committee_output(bytes: &[u8]) -> CommitteeAggregate {
    let mut offset = 0;
    let committee_member_id = read_u64(bytes, &mut offset) as usize;
    let seed_len = read_u64(bytes, &mut offset) as usize;
    let summed_seed_share = (0..seed_len)
        .map(|_| read_u128(bytes, &mut offset))
        .collect::<Vec<_>>();
    let digest_count = read_u64(bytes, &mut offset) as usize;
    let digest_shares = (0..digest_count)
        .map(|_| {
            let client_id = read_u64(bytes, &mut offset) as usize;
            let value = read_u128(bytes, &mut offset);
            (client_id, value)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(offset, bytes.len());
    CommitteeAggregate { committee_member_id, summed_seed_share, digest_shares }
}

fn serialize_committee_ciphertext(ciphertext: &CommitteeCiphertext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ciphertext.ephemeral_public);
    push_blob(&mut out, &ciphertext.body);
    out
}

fn deserialize_committee_ciphertext(bytes: &[u8]) -> CommitteeCiphertext {
    assert!(bytes.len() >= 32);
    let mut ephemeral_public = [0_u8; 32];
    ephemeral_public.copy_from_slice(&bytes[..32]);
    let mut offset = 32;
    let body = read_blob(bytes, &mut offset).to_vec();
    assert_eq!(offset, bytes.len());
    CommitteeCiphertext { ephemeral_public, body }
}

fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn read_blob<'a>(bytes: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let len = read_u64(bytes, offset) as usize;
    let end = offset.checked_add(len).expect("message offset overflow");
    assert!(end <= bytes.len(), "truncated message blob");
    let result = &bytes[*offset..end];
    *offset = end;
    result
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let end = offset.checked_add(8).expect("message offset overflow");
    assert!(end <= bytes.len(), "truncated u64 field");
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    u64::from_le_bytes(value)
}

fn read_u128(bytes: &[u8], offset: &mut usize) -> u128 {
    let end = offset.checked_add(16).expect("message offset overflow");
    assert!(end <= bytes.len(), "truncated u128 field");
    let mut value = [0_u8; 16];
    value.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    u128::from_le_bytes(value)
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn default_thread_count() -> usize {
    thread::available_parallelism().map(usize::from).unwrap_or(1)
}

fn env_usize_any(names: &[&str], default_value: usize) -> usize {
    names
        .iter()
        .find_map(|name| env::var(name).ok().and_then(|value| value.parse::<usize>().ok()))
        .unwrap_or(default_value)
}
