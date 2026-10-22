use std::env;
use std::time::Instant;

use testing_utils::generate_random_unsigned_vector;

fn main() {
    let n_clients = env_usize("BENCH_N_CLIENTS", 128);
    let active_clients = env_usize("BENCH_ACTIVE_CLIENTS", 113);
    let committee_size = env_usize("BENCH_COMMITTEE_SIZE", 50);
    let threshold_t = env_usize("BENCH_THRESHOLD", 40);
    let rss_secret_dim = env_usize("BENCH_RSS_SECRET_DIM", threshold_t.saturating_sub(10));
    let input_length = env_usize("BENCH_VECTOR_LEN", 10_000);
    let bench_threads = env_usize("BENCH_THREADS", default_thread_count()).max(1);
    let input_domain = 255_u64;

    let mut plain_inputs = Vec::with_capacity(active_clients);
    for _ in 0..active_clients {
        plain_inputs.push(generate_random_unsigned_vector(input_length, input_domain));
    }

    let plain_server_compute_s = measure_plain_server_aggregate(&plain_inputs);
    let client_to_server_bytes = active_clients * input_length * 8;

    println!(
        "protocol=Plain-FedAvg n_clients={} active_clients={} vector_len={} committee_size={} threshold_t={} rss_secret_dim={} bench_threads={} client_compute_s={:.6} committee_compute_s={:.6} server_compute_s={:.6} plain_server_compute_s={:.6} server_compute_with_plain_s={:.6} client_to_server_bytes={} server_to_committee_bytes={} committee_to_server_bytes={} total_bytes={} output_len={}",
        n_clients,
        active_clients,
        input_length,
        committee_size,
        threshold_t,
        rss_secret_dim,
        bench_threads,
        0.0_f64,
        0.0_f64,
        plain_server_compute_s,
        plain_server_compute_s,
        plain_server_compute_s,
        client_to_server_bytes,
        0,
        0,
        client_to_server_bytes,
        input_length
    );
}

fn default_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

fn measure_plain_server_aggregate(inputs: &[Vec<u64>]) -> f64 {
    let vector_len = inputs.first().map_or(0, Vec::len);
    let mut aggregate = vec![0_u64; vector_len];
    let start = Instant::now();
    for input in inputs {
        for (dst, value) in aggregate.iter_mut().zip(input) {
            *dst = dst.wrapping_add(*value);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(aggregate);
    elapsed
}

fn env_usize(name: &str, default_value: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_value)
}
