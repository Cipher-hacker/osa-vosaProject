use std::collections::{BTreeSet, HashMap};
use std::env;
use std::rc::Rc;
use std::thread;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use kahe_traits::KaheBase;
use osa_shell_kahe::{
    CommitteeAggregateShare, CommitteeCiphertext, OsaShellKaheClient, OsaShellKaheCommitteeMember,
    OsaShellKaheParameters, OsaShellKaheRngMode, OsaShellKaheServer, RampSecretSharing,
};
use proto_serialization_traits::ToProto;
use protobuf::prelude::*;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use testing_utils::generate_random_unsigned_vector;

const DEFAULT_ID: &str = "default";
const CONTEXT_STRING: &[u8] = b"osa_shell_kahe_compare_context";

fn main() {
    let n_clients = env_usize("BENCH_N_CLIENTS", 128);
    let active_clients = env_usize("BENCH_ACTIVE_CLIENTS", 113);
    let committee_size = env_usize("BENCH_COMMITTEE_SIZE", 50);
    let threshold_t = env_usize("BENCH_THRESHOLD", 40);
    let rss_secret_dim = env_usize("BENCH_RSS_SECRET_DIM", threshold_t.saturating_sub(10));
    let input_length = env_usize("BENCH_VECTOR_LEN", 10_000);
    let bench_threads = env_usize("BENCH_THREADS", default_thread_count()).max(1);
    let input_domain = 255_u64;
    let iteration = 1_u64;

    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            DEFAULT_ID.to_string(),
            (input_length as isize, input_domain as i64),
        )]),
        max_number_of_decryptors: committee_size as i64,
        max_number_of_clients: n_clients as i64,
        max_decryptor_dropouts: (committee_size - threshold_t) as i64,
        key_id: b"osa-shell-kahe-compare".to_vec(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config).unwrap();
    let kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let params = OsaShellKaheParameters { committee_size, threshold_t, rss_secret_dim };
    let rss = RampSecretSharing::new(params.clone()).unwrap();
    let server = OsaShellKaheServer { kahe: Rc::clone(&kahe), rss: rss.clone() };

    let committees: Vec<OsaShellKaheCommitteeMember> =
        (1..=committee_size).map(OsaShellKaheCommitteeMember::new).collect();
    let committee_public_keys = committees.iter().map(|member| member.key_pair.public()).collect::<Vec<_>>();

    let mut plain_inputs = Vec::with_capacity(active_clients);
    for _ in 0..active_clients {
        plain_inputs.push(generate_random_unsigned_vector(input_length, input_domain));
    }
    let plain_server_compute_s = measure_plain_server_aggregate(&plain_inputs);

    let t0 = Instant::now();
    let _parallel_client_bytes = parallel_collect(active_clients, bench_threads, |client_index| {
        let client_id = client_index + 1;
        let local_kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
        let input_values = &plain_inputs[client_index];
        let plaintext_owned = HashMap::from([(DEFAULT_ID.to_string(), input_values.clone())]);
        let plaintext = ShellKahe::plaintext_as_slice(&plaintext_owned);
        let upload = OsaShellKaheClient { client_id }.upload(
            iteration,
            &plaintext,
            &local_kahe,
            &rss,
            &committee_public_keys,
            OsaShellKaheRngMode::DeterministicBenchmark,
        ).unwrap();
        let ciphertext_bytes = upload.ciphertext.to_proto(&*local_kahe).unwrap().serialize().unwrap().len();
        let aux_bytes = upload.encrypted_key_shares.iter().map(committee_ciphertext_bytes).sum::<usize>();
        ciphertext_bytes + aux_bytes + 24
    });
    let client_compute_s = t0.elapsed().as_secs_f64();

    let mut uploads = Vec::with_capacity(active_clients);
    for (client_id, input_values) in (1..=active_clients).zip(&plain_inputs) {
        let plaintext_owned = HashMap::from([(DEFAULT_ID.to_string(), input_values.clone())]);
        let plaintext = ShellKahe::plaintext_as_slice(&plaintext_owned);
        let upload = OsaShellKaheClient { client_id }.upload(
            iteration,
            &plaintext,
            &kahe,
            &rss,
            &committee_public_keys,
            OsaShellKaheRngMode::DeterministicBenchmark,
        ).unwrap();
        uploads.push(upload);
    }

    let mut client_to_server_bytes = 0_usize;
    let mut server_to_committee_bytes = 0_usize;
    for upload in &uploads {
        let ciphertext_bytes = upload.ciphertext.to_proto(&*kahe).unwrap().serialize().unwrap().len();
        let aux_bytes = upload.encrypted_key_shares.iter().map(committee_ciphertext_bytes).sum::<usize>();
        client_to_server_bytes += ciphertext_bytes + aux_bytes + 24;
        server_to_committee_bytes += aux_bytes;
    }

    let active_set: BTreeSet<usize> = uploads.iter().map(|upload| upload.client_id).collect();
    let t1 = Instant::now();
    let committee_outputs = committees
        .iter()
        .take(threshold_t)
        .map(|member| member.combine(iteration, &active_set, &uploads, &params).unwrap())
        .collect::<Vec<_>>();
    let committee_compute_s = t1.elapsed().as_secs_f64();
    let committee_to_server_bytes = committee_outputs.iter().map(committee_aggregate_share_bytes).sum::<usize>();

    let t2 = Instant::now();
    let aggregate = server.aggregate(iteration, &uploads, &committee_outputs).unwrap();
    let server_compute_s = t2.elapsed().as_secs_f64();
    let server_compute_with_plain_s = server_compute_s + plain_server_compute_s;

    let output = aggregate.get(DEFAULT_ID).expect("missing aggregate output");
    assert_eq!(output.len(), input_length);

    println!(
        "protocol=OSA-ShellKahe n_clients={} active_clients={} vector_len={} committee_size={} threshold_t={} rss_secret_dim={} bench_threads={} client_compute_s={:.6} committee_compute_s={:.6} server_compute_s={:.6} plain_server_compute_s={:.6} server_compute_with_plain_s={:.6} client_to_server_bytes={} server_to_committee_bytes={} committee_to_server_bytes={} total_bytes={} output_len={}",
        n_clients,
        active_clients,
        input_length,
        committee_size,
        threshold_t,
        rss_secret_dim,
        bench_threads,
        client_compute_s,
        committee_compute_s,
        server_compute_s,
        plain_server_compute_s,
        server_compute_with_plain_s,
        client_to_server_bytes,
        server_to_committee_bytes,
        committee_to_server_bytes,
        client_to_server_bytes + server_to_committee_bytes + committee_to_server_bytes,
        output.len()
    );
}

fn default_thread_count() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

fn parallel_collect<T, F>(item_count: usize, thread_count: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    if item_count == 0 {
        return Vec::new();
    }
    let workers = thread_count.min(item_count).max(1);
    let chunk_size = item_count.div_ceil(workers);
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * chunk_size;
            let end = (start + chunk_size).min(item_count);
            if start >= end {
                continue;
            }
            let f_ref = &f;
            handles.push(scope.spawn(move || {
                (start..end).map(f_ref).collect::<Vec<_>>()
            }));
        }
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    })
}

fn committee_ciphertext_bytes(ciphertext: &CommitteeCiphertext) -> usize {
    32 + ciphertext.body.len() + ciphertext.tag.len()
}

fn committee_aggregate_share_bytes(share: &CommitteeAggregateShare) -> usize {
    16 + share.summed_key_share.len() * 8
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
