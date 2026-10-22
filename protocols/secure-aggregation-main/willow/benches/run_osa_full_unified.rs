use std::collections::{BTreeSet, HashMap};
use std::env;
use std::rc::Rc;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use kahe_traits::KaheBase;
use osa_shell_kahe::{
    pack_rss_field_elements_for_mode, rss_packed_byte_len_for_mode,
    unpack_rss_field_elements_for_mode, CommitteeAggregateShare, CommitteeCiphertext,
    OsaAuxEncryptionMode, OsaDigestMaskMode, OsaDigestSharingMode, OsaRssFieldMode,
    OsaShellKaheClient, OsaShellKaheClientUpload, OsaShellKaheCommitteeMember,
    OsaShellKaheParameters, OsaShellKaheRngMode, OsaShellKaheServer, RampSecretSharing,
    RoutedCommitteeShare,
};
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use shell_ciphertexts_rust_proto::ShellKaheCiphertext;
use shell_kahe::{Ciphertext as KaheCiphertext, ShellKahe};
use shell_parameters::create_shell_configs;

const DEFAULT_ID: &str = "default";
const CONTEXT_STRING: &[u8] = b"osa_full_unified_benchmark_v1";
const SHELL_SECRET_KEY_ABS_TAIL_BOUND: u64 = 37;

struct ClientBatch {
    messages: Vec<Vec<u8>>,
    operation_seconds: Vec<f64>,
    wall_seconds: f64,
    worker_setup_seconds: f64,
}

fn main() {
    let n_clients = env_usize("BENCH_N_CLIENTS", 1_000);
    let active_clients = env_usize("BENCH_ACTIVE_CLIENTS", 800);
    let committee_size = env_usize("BENCH_COMMITTEE_SIZE", 50);
    let threshold_t = env_usize("BENCH_THRESHOLD", 40);
    let rss_secret_dim = env_usize("BENCH_RSS_SECRET_DIM", 30);
    let vector_len = env_usize("BENCH_VECTOR_LEN", 10_000);
    let bench_threads = env_usize("BENCH_THREADS", default_thread_count()).max(1);
    let benchmark_profile = env::var("BENCH_OSA_PROFILE").unwrap_or_else(|_| {
        option_env!("OSA_BENCH_DEFAULT_PROFILE").unwrap_or("faithful").to_string()
    });
    let (default_rss_field_mode, default_digest_sharing_mode) = match benchmark_profile.as_str() {
        "faithful" => ("paper61", "full_ring_digest"),
        "compact_seeded" => ("compact31", "seeded_prg_digest"),
        _ => panic!("unsupported BENCH_OSA_PROFILE"),
    };
    let rss_field_mode = OsaRssFieldMode::from_str(
        &env::var("BENCH_OSA_RSS_FIELD_MODE")
            .unwrap_or_else(|_| default_rss_field_mode.to_string()),
    )
    .unwrap();
    let digest_sharing_mode = OsaDigestSharingMode::from_str(
        &env::var("BENCH_OSA_DIGEST_SHARING_MODE")
            .unwrap_or_else(|_| default_digest_sharing_mode.to_string()),
    )
    .unwrap();
    let digest_mask_mode = OsaDigestMaskMode::from_str(
        &env::var("BENCH_OSA_DIGEST_MASK_MODE").unwrap_or_else(|_| "shake256_xof".to_string()),
    )
    .unwrap();
    let aux_encryption_mode = OsaAuxEncryptionMode::from_str(
        &env::var("BENCH_OSA_AUX_ENCRYPTION_MODE")
            .unwrap_or_else(|_| "ind_cpa_shake256".to_string()),
    )
    .unwrap();
    let iteration = 1_u64;
    assert!(active_clients <= n_clients);
    assert!(threshold_t <= committee_size);
    let aggregate_key_abs_bound = (active_clients as u64)
        .checked_mul(SHELL_SECRET_KEY_ABS_TAIL_BOUND)
        .expect("aggregate key bound overflow");
    assert!(
        aggregate_key_abs_bound < rss_field_mode.modulus() / 2,
        "RSS field is too small for the worst-case aggregate ShellKahe key"
    );

    let setup_start = Instant::now();
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            DEFAULT_ID.to_string(),
            (vector_len as isize, 2_i64),
        )]),
        max_number_of_decryptors: committee_size as i64,
        max_number_of_clients: n_clients as i64,
        max_decryptor_dropouts: (committee_size - threshold_t) as i64,
        key_id: b"osa-full-unified".to_vec(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config).unwrap();
    let kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let params = OsaShellKaheParameters { committee_size, threshold_t, rss_secret_dim };
    let rss = RampSecretSharing::new_with_field_mode(params.clone(), rss_field_mode).unwrap();
    let server = OsaShellKaheServer { kahe: Rc::clone(&kahe), rss: rss.clone() };
    let committees = (1..=committee_size)
        .map(|id| OsaShellKaheCommitteeMember::new_for_iteration(iteration, id))
        .collect::<Vec<_>>();
    let committee_public_keys = committees
        .iter()
        .map(|member| member.key_pair.public())
        .collect::<Vec<_>>();
    let one_input = vec![1_u64; vector_len];
    let zero_input = vec![0_u64; vector_len];

    // Measure one complete uncontended online client operation. Context setup is
    // reusable system setup and is deliberately outside this timer.
    let sample_kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let sample_plaintext = HashMap::from([(DEFAULT_ID, one_input.as_slice())]);
    let setup_before_workers_seconds = setup_start.elapsed().as_secs_f64();
    let sample_start = Instant::now();
    let sample_upload = OsaShellKaheClient { client_id: 1 }
        .upload_with_protocol_modes(
            iteration,
            &sample_plaintext,
            &sample_kahe,
            &rss,
            &committee_public_keys,
            OsaShellKaheRngMode::DeterministicBenchmark,
            digest_mask_mode,
            aux_encryption_mode,
            digest_sharing_mode,
        )
        .unwrap();
    let sample_bytes = serialize_upload(&sample_upload, &sample_kahe);
    std::hint::black_box(&sample_bytes);
    let client_single_seconds = sample_start.elapsed().as_secs_f64();
    let online_start = Instant::now();
    let client_batch = parallel_clients(
        active_clients,
        bench_threads,
        &kahe_config,
        &rss,
        &committee_public_keys,
        &one_input,
        &zero_input,
        iteration,
        digest_mask_mode,
        aux_encryption_mode,
        digest_sharing_mode,
    );
    let client_to_server_bytes = client_batch.messages.iter().map(Vec::len).sum::<usize>();

    let initial_server_start = Instant::now();
    let uploads = client_batch
        .messages
        .iter()
        .map(|bytes| deserialize_upload(bytes, &kahe))
        .collect::<Vec<_>>();
    let active_set = uploads.iter().map(|upload| upload.client_id).collect::<BTreeSet<_>>();
    assert_eq!(active_set.len(), active_clients, "duplicate OSA client identifiers");
    assert!(active_set.iter().all(|&id| id > 0 && id <= n_clients));
    let route_messages = (0..threshold_t)
        .map(|committee_index| {
            serialize_route_batch(iteration, &active_set, &uploads, committee_index)
        })
        .collect::<Vec<_>>();
    let mut server_seconds = initial_server_start.elapsed().as_secs_f64();
    let server_to_committee_bytes = route_messages.iter().map(Vec::len).sum::<usize>();

    let mut committee_operation_seconds = Vec::with_capacity(threshold_t);
    let mut committee_route_parse_seconds = Vec::with_capacity(threshold_t);
    let mut committee_aux_decrypt_seconds = Vec::with_capacity(threshold_t);
    let mut committee_payload_decode_seconds = Vec::with_capacity(threshold_t);
    let mut committee_key_accumulation_seconds = Vec::with_capacity(threshold_t);
    let mut committee_serialize_seconds = Vec::with_capacity(threshold_t);
    let mut committee_messages = Vec::with_capacity(threshold_t);
    for (member, route_bytes) in committees.iter().take(threshold_t).zip(&route_messages) {
        let member_start = Instant::now();
        let phase_start = Instant::now();
        let (local_iteration, local_active_set, routed) = deserialize_route_batch(route_bytes);
        committee_route_parse_seconds.push(phase_start.elapsed().as_secs_f64());
        assert_eq!(local_iteration, iteration);
        let (output, phase_timings) = member
            .combine_routed_with_timings_and_modes(
                local_iteration,
                &local_active_set,
                &routed,
                aux_encryption_mode,
                rss_field_mode,
            )
            .unwrap();
        committee_aux_decrypt_seconds.push(phase_timings.auxiliary_decryption_s);
        committee_payload_decode_seconds.push(phase_timings.payload_decode_s);
        committee_key_accumulation_seconds.push(phase_timings.key_share_accumulation_s);
        let phase_start = Instant::now();
        let bytes = serialize_committee_output(&output, rss_field_mode);
        committee_serialize_seconds.push(phase_start.elapsed().as_secs_f64());
        committee_operation_seconds.push(member_start.elapsed().as_secs_f64());
        committee_messages.push(bytes);
    }
    let committee_to_server_bytes = committee_messages.iter().map(Vec::len).sum::<usize>();

    let final_server_start = Instant::now();
    let committee_outputs = committee_messages
        .iter()
        .map(|bytes| deserialize_committee_output(bytes, rss_field_mode))
        .collect::<Vec<_>>();
    let (aggregate, server_phase_timings) = server
        .aggregate_with_timings_and_modes(
            iteration,
            &uploads,
            &committee_outputs,
            digest_mask_mode,
            digest_sharing_mode,
        )
        .unwrap();
    server_seconds += final_server_start.elapsed().as_secs_f64();
    let online_wall_seconds = online_start.elapsed().as_secs_f64();

    let expected = active_clients.min(7) as u64;
    let output = aggregate.get(DEFAULT_ID).expect("missing OSA aggregate output");
    assert_eq!(output.len(), vector_len);
    assert!(
        output.iter().all(|&value| value == expected),
        "OSA aggregate mismatch: expected {}, first values {:?}",
        expected,
        &output[..output.len().min(8)]
    );

    let committee_single_seconds = mean(&committee_operation_seconds);
    let client_observed_mean_seconds = mean(&client_batch.operation_seconds);
    let total_bytes = client_to_server_bytes + server_to_committee_bytes + committee_to_server_bytes;
    let setup_seconds = setup_before_workers_seconds + client_batch.worker_setup_seconds;
    let (protocol_name, implementation_scope, security_delta) =
        match (rss_field_mode, digest_sharing_mode) {
            (OsaRssFieldMode::Paper61, OsaDigestSharingMode::FullRingDigest) => (
                "OSA-ShellKahe-full-online",
                "paper_flow_full_ring_digest_rss_pke",
                "none",
            ),
            (OsaRssFieldMode::Compact31, OsaDigestSharingMode::SeededPrgDigest) => (
                "OSA-SeededDigest-RSS31-full-online",
                "paper_flow_with_compact_seeded_digest_extension",
                "hkdf_prg_seeded_digest_and_bounded_rss31",
            ),
            _ => (
                "OSA-Custom-full-online",
                "mixed_nonstandard_profile",
                "explicit_mode_combination",
            ),
        };
    println!(
        "protocol={} implementation_scope={} benchmark_profile={} rng_mode=deterministic_benchmark rss_field_mode={} rss_modulus={} rss_bits={} digest_sharing_mode={} security_delta={} aggregate_key_abs_bound={} digest_mask_mode={} aux_encryption_mode={} n_clients={} active_clients={} vector_len={} committee_size={} threshold_t={} rss_secret_dim={} bench_threads={} setup_s={:.6} client_compute_s={:.6} client_observed_mean_s={:.6} client_batch_wall_s={:.6} committee_compute_s={:.6} committee_route_parse_s={:.6} committee_aux_decrypt_s={:.6} committee_payload_decode_s={:.6} committee_key_accumulation_s={:.6} committee_serialize_s={:.6} verifier_compute_s=0.000000 server_compute_s={:.6} server_interpolation_s={:.6} server_key_reconstruction_s={:.6} server_ciphertext_aggregation_s={:.6} server_digest_share_collection_s={:.6} server_digest_reconstruction_s={:.6} server_digest_mask_expansion_s={:.6} server_mask_accumulation_s={:.6} server_final_decryption_s={:.6} online_wall_s={:.6} client_to_server_bytes={} server_to_committee_bytes={} committee_to_server_bytes={} client_bytes_mean={:.3} committee_receive_bytes_mean={:.3} committee_send_bytes_mean={:.3} committee_bytes_mean={:.3} server_receive_bytes={} server_send_bytes={} total_bytes={} correctness=pass",
        protocol_name,
        implementation_scope,
        benchmark_profile,
        rss_field_mode.as_str(),
        rss_field_mode.modulus(),
        rss_field_mode.bits(),
        digest_sharing_mode.as_str(),
        security_delta,
        aggregate_key_abs_bound,
        digest_mask_mode.as_str(),
        aux_encryption_mode.as_str(),
        n_clients,
        active_clients,
        vector_len,
        committee_size,
        threshold_t,
        rss_secret_dim,
        bench_threads,
        setup_seconds,
        client_single_seconds,
        client_observed_mean_seconds,
        client_batch.wall_seconds,
        committee_single_seconds,
        mean(&committee_route_parse_seconds),
        mean(&committee_aux_decrypt_seconds),
        mean(&committee_payload_decode_seconds),
        mean(&committee_key_accumulation_seconds),
        mean(&committee_serialize_seconds),
        server_seconds,
        server_phase_timings.interpolation_s,
        server_phase_timings.key_reconstruction_s,
        server_phase_timings.ciphertext_aggregation_s,
        server_phase_timings.digest_share_collection_s,
        server_phase_timings.digest_reconstruction_s,
        server_phase_timings.digest_mask_expansion_s,
        server_phase_timings.mask_accumulation_s,
        server_phase_timings.final_decryption_s,
        online_wall_seconds,
        client_to_server_bytes,
        server_to_committee_bytes,
        committee_to_server_bytes,
        client_to_server_bytes as f64 / active_clients as f64,
        server_to_committee_bytes as f64 / threshold_t as f64,
        committee_to_server_bytes as f64 / threshold_t as f64,
        (server_to_committee_bytes + committee_to_server_bytes) as f64 / threshold_t as f64,
        client_to_server_bytes + committee_to_server_bytes,
        server_to_committee_bytes,
        total_bytes,
    );
}

#[allow(clippy::too_many_arguments)]
fn parallel_clients(
    active_clients: usize,
    thread_count: usize,
    kahe_config: &<ShellKahe as kahe_traits::KaheBase>::Config,
    rss: &RampSecretSharing,
    committee_public_keys: &[curve25519_dalek::ristretto::RistrettoPoint],
    one_input: &[u64],
    zero_input: &[u64],
    iteration: u64,
    digest_mask_mode: OsaDigestMaskMode,
    aux_encryption_mode: OsaAuxEncryptionMode,
    digest_sharing_mode: OsaDigestSharingMode,
) -> ClientBatch {
    let workers = thread_count.min(active_clients).max(1);
    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let (wall_seconds, results) = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * active_clients / workers;
            let end = (worker + 1) * active_clients / workers;
            let local_config = kahe_config.clone();
            let local_rss = rss.clone();
            let local_public_keys = committee_public_keys.to_vec();
            let local_ready = Arc::clone(&ready);
            let local_go = Arc::clone(&go);
            handles.push(scope.spawn(move || {
                let setup_start = Instant::now();
                let local_kahe = Rc::new(ShellKahe::new(local_config, CONTEXT_STRING).unwrap());
                let setup_seconds = setup_start.elapsed().as_secs_f64();
                local_ready.wait();
                local_go.wait();
                let mut output = Vec::with_capacity(end - start);
                for client_index in start..end {
                    let client_id = client_index + 1;
                    let values = if client_id <= 7 { one_input } else { zero_input };
                    let plaintext = HashMap::from([(DEFAULT_ID, values)]);
                    let operation_start = Instant::now();
                    let upload = OsaShellKaheClient { client_id }
                        .upload_with_protocol_modes(
                            iteration,
                            &plaintext,
                            &local_kahe,
                            &local_rss,
                            &local_public_keys,
                            OsaShellKaheRngMode::DeterministicBenchmark,
                            digest_mask_mode,
                            aux_encryption_mode,
                            digest_sharing_mode,
                        )
                        .unwrap();
                    let bytes = serialize_upload(&upload, &local_kahe);
                    output.push((bytes, operation_start.elapsed().as_secs_f64()));
                }
                (setup_seconds, output)
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
    let worker_setup_seconds = results.iter().map(|(seconds, _)| *seconds).fold(0.0, f64::max);
    let mut messages = Vec::with_capacity(active_clients);
    let mut operation_seconds = Vec::with_capacity(active_clients);
    for (_, worker_output) in results {
        for (message, seconds) in worker_output {
            messages.push(message);
            operation_seconds.push(seconds);
        }
    }
    ClientBatch { messages, operation_seconds, wall_seconds, worker_setup_seconds }
}

fn serialize_upload(upload: &OsaShellKaheClientUpload, kahe: &ShellKahe) -> Vec<u8> {
    let ciphertext = upload.ciphertext.to_proto(kahe).unwrap().serialize().unwrap();
    let mut out = Vec::new();
    push_u64(&mut out, upload.client_id as u64);
    push_u64(&mut out, upload.iteration);
    push_u64(&mut out, upload.serialized_key_len as u64);
    push_u64(&mut out, upload.serialized_digest_len as u64);
    push_blob(&mut out, &ciphertext);
    push_u64(&mut out, upload.encrypted_key_shares.len() as u64);
    for share in &upload.encrypted_key_shares {
        let bytes = serialize_committee_ciphertext(share);
        push_blob(&mut out, &bytes);
    }
    out
}

fn deserialize_upload(bytes: &[u8], kahe: &ShellKahe) -> OsaShellKaheClientUpload {
    let mut offset = 0;
    let client_id = read_u64(bytes, &mut offset) as usize;
    let iteration = read_u64(bytes, &mut offset);
    let serialized_key_len = read_u64(bytes, &mut offset) as usize;
    let serialized_digest_len = read_u64(bytes, &mut offset) as usize;
    let ciphertext_bytes = read_blob(bytes, &mut offset);
    let proto = ShellKaheCiphertext::parse(ciphertext_bytes).unwrap();
    let ciphertext = KaheCiphertext::from_proto(proto, kahe).unwrap();
    let share_count = read_u64(bytes, &mut offset) as usize;
    let encrypted_key_shares = (0..share_count)
        .map(|_| deserialize_committee_ciphertext(read_blob(bytes, &mut offset)))
        .collect::<Vec<_>>();
    assert_eq!(offset, bytes.len());
    OsaShellKaheClientUpload {
        client_id,
        iteration,
        ciphertext,
        encrypted_key_shares,
        serialized_key_len,
        serialized_digest_len,
    }
}

fn serialize_route_batch(
    iteration: u64,
    active_set: &BTreeSet<usize>,
    uploads: &[OsaShellKaheClientUpload],
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
        let bytes = serialize_committee_ciphertext(&upload.encrypted_key_shares[committee_index]);
        push_blob(&mut out, &bytes);
    }
    out
}

fn deserialize_route_batch(bytes: &[u8]) -> (u64, BTreeSet<usize>, Vec<RoutedCommitteeShare>) {
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
            RoutedCommitteeShare { client_id, ciphertext }
        })
        .collect::<Vec<_>>();
    assert_eq!(offset, bytes.len());
    (iteration, active_set, routed)
}

fn serialize_committee_output(
    output: &CommitteeAggregateShare,
    rss_field_mode: OsaRssFieldMode,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_u64(&mut out, output.committee_member_id as u64);
    push_u64(&mut out, output.summed_key_share.len() as u64);
    out.extend_from_slice(
        &pack_rss_field_elements_for_mode(&output.summed_key_share, rss_field_mode).unwrap(),
    );
    push_u64(&mut out, output.digest_shares_by_client.len() as u64);
    for (client_id, values) in &output.digest_shares_by_client {
        push_u64(&mut out, *client_id as u64);
        push_u64(&mut out, values.len() as u64);
        out.extend_from_slice(&pack_rss_field_elements_for_mode(values, rss_field_mode).unwrap());
    }
    out
}

fn deserialize_committee_output(
    bytes: &[u8],
    rss_field_mode: OsaRssFieldMode,
) -> CommitteeAggregateShare {
    let mut offset = 0;
    let committee_member_id = read_u64(bytes, &mut offset) as usize;
    let key_len = read_u64(bytes, &mut offset) as usize;
    let key_end = offset + rss_packed_byte_len_for_mode(key_len, rss_field_mode).unwrap();
    assert!(key_end <= bytes.len(), "truncated packed key share");
    let summed_key_share =
        unpack_rss_field_elements_for_mode(&bytes[offset..key_end], key_len, rss_field_mode)
            .unwrap();
    offset = key_end;
    let digest_count = read_u64(bytes, &mut offset) as usize;
    let digest_shares_by_client = (0..digest_count)
        .map(|_| {
            let client_id = read_u64(bytes, &mut offset) as usize;
            let digest_len = read_u64(bytes, &mut offset) as usize;
            let digest_end =
                offset + rss_packed_byte_len_for_mode(digest_len, rss_field_mode).unwrap();
            assert!(digest_end <= bytes.len(), "truncated packed digest share");
            let values = unpack_rss_field_elements_for_mode(
                &bytes[offset..digest_end],
                digest_len,
                rss_field_mode,
            )
            .unwrap();
            offset = digest_end;
            (client_id, values)
        })
        .collect::<Vec<_>>();
    assert_eq!(offset, bytes.len());
    CommitteeAggregateShare { committee_member_id, summed_key_share, digest_shares_by_client }
}

fn serialize_committee_ciphertext(ciphertext: &CommitteeCiphertext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ciphertext.ephemeral_public);
    push_blob(&mut out, &ciphertext.body);
    push_blob(&mut out, &ciphertext.tag);
    out
}

fn deserialize_committee_ciphertext(bytes: &[u8]) -> CommitteeCiphertext {
    assert!(bytes.len() >= 32);
    let mut ephemeral_public = [0_u8; 32];
    ephemeral_public.copy_from_slice(&bytes[..32]);
    let mut offset = 32;
    let body = read_blob(bytes, &mut offset).to_vec();
    let tag = read_blob(bytes, &mut offset).to_vec();
    assert_eq!(offset, bytes.len());
    CommitteeCiphertext { ephemeral_public, body, tag }
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

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let end = offset.checked_add(8).expect("message offset overflow");
    assert!(end <= bytes.len(), "truncated u64 field");
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    u64::from_le_bytes(value)
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

fn env_usize(name: &str, default_value: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_value)
}
