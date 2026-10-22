use aggregation_config::AggregationConfig;
use kahe_traits::{KaheBase, KaheKeygen, TrySecretKeyInto};
use osa_shell_kahe::{
    add_vosa_digest_sums_in_place, expand_digest_ring_mask, OsaDigestMaskMode,
};
use prng_traits::SecurePrng;
use shell_kahe::{ShellKahe, ShellKaheConfig};
use shell_parameters::create_shell_configs;
use single_thread_hkdf::SingleThreadHkdfPrng;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;
use vosa_verification::{
    create_client_messages, create_server_opening, verify_server_opening, VosaClientMessages,
};

const VECTOR_ID: &str = "default";
const CONTEXT: &[u8] = b"vosa_verification_only_formal_v1";
const ITERATION: u64 = 1;
const INPUT_BOUND: i64 = 1_i64 << 32;
const RANDOMNESS_TAIL_BOUND: u64 = 37;

struct ClientRecord {
    client_id: u64,
    messages: VosaClientMessages,
    ring_mask_limbs: Vec<u64>,
    compute_seconds: f64,
}

struct ClientBatch {
    records: Vec<ClientRecord>,
    wall_seconds: f64,
    setup_seconds: f64,
}

fn main() {
    let n_clients = env_usize("VOSA_N_CLIENTS", 1_000);
    let active_clients = env_usize("VOSA_ACTIVE_CLIENTS", 800);
    let vector_len = env_usize("VOSA_VECTOR_LEN", 10_000);
    let committee_size = env_usize("VOSA_COMMITTEE_SIZE", 50);
    let threshold_t = env_usize("VOSA_THRESHOLD", 40);
    let threads = env_usize("VOSA_THREADS", default_thread_count())
        .max(1)
        .min(active_clients);
    assert!(active_clients > 0 && active_clients <= n_clients);
    assert!(threshold_t > 0 && threshold_t <= committee_size);

    let setup_start = Instant::now();
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            VECTOR_ID.to_string(),
            (vector_len as isize, INPUT_BOUND),
        )]),
        max_number_of_decryptors: committee_size as i64,
        max_number_of_clients: n_clients as i64,
        max_decryptor_dropouts: (committee_size - threshold_t) as i64,
        key_id: b"vosa-verification-only".to_vec(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config).unwrap();
    let rns_moduli = kahe_config.moduli.len();
    let verifier_kahe = ShellKahe::new(kahe_config.clone(), CONTEXT).unwrap();
    let input = Arc::new(vec![1_u64; vector_len]);
    let fixed_setup_seconds = setup_start.elapsed().as_secs_f64();

    let client_batch = run_clients(
        kahe_config,
        Arc::clone(&input),
        active_clients,
        threads,
    );
    let mut records = client_batch.records;
    records.sort_by_key(|record| record.client_id);
    let active_ids = records.iter().map(|record| record.client_id).collect::<Vec<_>>();

    // These aggregates are outputs of common secure aggregation and therefore
    // remain outside the verification-increment role timers.
    let aggregate_input = vec![active_clients as u64; vector_len];
    let mut aggregate_ring_mask =
        vec![0_u64; verifier_kahe.packed_coefficient_count() * 4];
    for record in &records {
        add_vosa_digest_sums_in_place(&mut aggregate_ring_mask, &record.ring_mask_limbs).unwrap();
    }

    let client_to_server =
        records.iter().map(|record| record.messages.to_server.clone()).collect::<Vec<_>>();
    let client_to_verifier = records
        .iter()
        .map(|record| record.messages.to_verifier.clone())
        .collect::<Vec<_>>();

    let server_start = Instant::now();
    let server_opening = create_server_opening(
        ITERATION,
        &active_ids,
        &client_to_server,
        &aggregate_input,
        &aggregate_ring_mask,
        verifier_kahe.public_polynomial_count(),
        verifier_kahe.ring_coefficient_count(),
    )
    .unwrap();
    let server_compute_seconds = server_start.elapsed().as_secs_f64();

    let aggregate_randomness_abs_bound = active_clients as u64 * RANDOMNESS_TAIL_BOUND;
    let verifier_start = Instant::now();
    verify_server_opening(
        ITERATION,
        VECTOR_ID,
        &client_to_verifier,
        &server_opening,
        aggregate_randomness_abs_bound,
        &verifier_kahe,
    )
    .unwrap();
    let verifier_compute_seconds = verifier_start.elapsed().as_secs_f64();

    // Malicious-server check is executed, but deliberately excluded from the
    // honest online timing reported above.
    let mut forged_aggregate_input = aggregate_input.clone();
    forged_aggregate_input[0] += 1;
    let forged_opening = create_server_opening(
        ITERATION,
        &active_ids,
        &client_to_server,
        &forged_aggregate_input,
        &aggregate_ring_mask,
        verifier_kahe.public_polynomial_count(),
        verifier_kahe.ring_coefficient_count(),
    )
    .unwrap();
    assert!(
        verify_server_opening(
            ITERATION,
            VECTOR_ID,
            &client_to_verifier,
            &forged_opening,
            aggregate_randomness_abs_bound,
            &verifier_kahe,
        )
        .is_err(),
        "forged aggregate unexpectedly passed VOSA verification"
    );

    let client_compute_mean_seconds = records
        .iter()
        .map(|record| record.compute_seconds)
        .sum::<f64>()
        / active_clients as f64;
    let client_compute_total_seconds =
        records.iter().map(|record| record.compute_seconds).sum::<f64>();
    let client_to_server_bytes = records
        .iter()
        .map(|record| record.messages.to_server.len() as u64)
        .sum::<u64>();
    let client_to_verifier_bytes = records
        .iter()
        .map(|record| record.messages.to_verifier.len() as u64)
        .sum::<u64>();
    let server_to_verifier_bytes = server_opening.len() as u64;
    let total_bytes =
        client_to_server_bytes + client_to_verifier_bytes + server_to_verifier_bytes;
    let client_bytes_mean =
        (client_to_server_bytes + client_to_verifier_bytes) as f64 / active_clients as f64;

    println!(
        "protocol=VOSA-verification-only-faithful wire=protobuf-rns-plus-canonical-small-r n_clients={} active_clients={} dropout_rate={:.6} vector_len={} committee_size={} threshold_t={} ring_n={} log_t={} rns_moduli={} public_polynomials={} threads={} warmup_per_worker=1 repetitions=1 fixed_setup_s={:.6} client_common_precompute_setup_s={:.6} client_compute_mean_s={:.9} client_compute_total_s={:.6} client_batch_wall_s={:.6} committee_compute_s=0.000000000 server_compute_s={:.9} verifier_compute_s={:.9} client_to_server_bytes={} client_to_verifier_bytes={} server_to_verifier_bytes={} committee_bytes=0 client_bytes_mean={:.3} server_receive_bytes={} server_send_bytes={} verifier_receive_bytes={} total_bytes={} honest_correctness=pass forged_server_rejection=pass timing_scope=verification_increment_only",
        n_clients,
        active_clients,
        1.0 - active_clients as f64 / n_clients as f64,
        vector_len,
        committee_size,
        threshold_t,
        verifier_kahe.ring_coefficient_count(),
        verifier_kahe.plaintext_modulus_bits(),
        rns_moduli,
        verifier_kahe.public_polynomial_count(),
        threads,
        fixed_setup_seconds,
        client_batch.setup_seconds,
        client_compute_mean_seconds,
        client_compute_total_seconds,
        client_batch.wall_seconds,
        server_compute_seconds,
        verifier_compute_seconds,
        client_to_server_bytes,
        client_to_verifier_bytes,
        server_to_verifier_bytes,
        client_bytes_mean,
        client_to_server_bytes,
        server_to_verifier_bytes,
        client_to_verifier_bytes + server_to_verifier_bytes,
        total_bytes,
    );
}

fn run_clients(
    kahe_config: ShellKaheConfig,
    input: Arc<Vec<u64>>,
    active_clients: usize,
    threads: usize,
) -> ClientBatch {
    let ready_barrier = Arc::new(Barrier::new(threads + 1));
    let start_barrier = Arc::new(Barrier::new(threads + 1));
    let setup_start = Instant::now();
    let (records, wall_seconds, setup_seconds) = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for worker_index in 0..threads {
            let worker_config = kahe_config.clone();
            let worker_input = Arc::clone(&input);
            let worker_ready_barrier = Arc::clone(&ready_barrier);
            let worker_start_barrier = Arc::clone(&start_barrier);
            handles.push(scope.spawn(move || {
                let kahe = ShellKahe::new(worker_config, CONTEXT).unwrap();
                let client_ids = (worker_index..active_clients)
                    .step_by(threads)
                    .map(|index| index as u64 + 1)
                    .collect::<Vec<_>>();
                let mut prepared = Vec::with_capacity(client_ids.len());
                for client_id in client_ids {
                    let digest_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
                    let mut digest_rng = SingleThreadHkdfPrng::create(&digest_seed).unwrap();
                    let digest = kahe.key_gen(&mut digest_rng).unwrap();
                    let digest_buffer: Vec<i64> = kahe.try_secret_key_into(digest).unwrap();
                    let ring_mask = expand_digest_ring_mask(
                        &digest_buffer,
                        kahe.packed_coefficient_count(),
                        kahe.plaintext_modulus_bits(),
                        ITERATION,
                        OsaDigestMaskMode::Shake256Xof,
                    );
                    let commit_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
                    let commit_rng = SingleThreadHkdfPrng::create(&commit_seed).unwrap();
                    prepared.push((client_id, ring_mask, commit_rng));
                }

                if let Some((_, ring_mask, _)) = prepared.first() {
                    let warmup_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
                    let mut warmup_rng = SingleThreadHkdfPrng::create(&warmup_seed).unwrap();
                    let plaintext = HashMap::from([(VECTOR_ID, worker_input.as_slice())]);
                    let warmup = create_client_messages(
                        ITERATION,
                        0,
                        &plaintext,
                        ring_mask,
                        &kahe,
                        &mut warmup_rng,
                    )
                    .unwrap();
                    std::hint::black_box(warmup);
                }
                worker_ready_barrier.wait();
                worker_start_barrier.wait();

                let mut output = Vec::with_capacity(prepared.len());
                for (client_id, ring_mask, mut commit_rng) in prepared {
                    let plaintext = HashMap::from([(VECTOR_ID, worker_input.as_slice())]);
                    let start = Instant::now();
                    let messages = create_client_messages(
                        ITERATION,
                        client_id,
                        &plaintext,
                        &ring_mask,
                        &kahe,
                        &mut commit_rng,
                    )
                    .unwrap();
                    let compute_seconds = start.elapsed().as_secs_f64();
                    output.push(ClientRecord {
                        client_id,
                        messages,
                        ring_mask_limbs: ring_mask,
                        compute_seconds,
                    });
                }
                output
            }));
        }
        ready_barrier.wait();
        let setup_seconds = setup_start.elapsed().as_secs_f64();
        let wall_start = Instant::now();
        start_barrier.wait();
        let mut records = Vec::with_capacity(active_clients);
        for handle in handles {
            records.extend(handle.join().unwrap());
        }
        let wall_seconds = wall_start.elapsed().as_secs_f64();
        (records, wall_seconds, setup_seconds)
    });
    ClientBatch {
        records,
        wall_seconds,
        setup_seconds,
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

fn default_thread_count() -> usize {
    thread::available_parallelism().map_or(1, usize::from)
}
