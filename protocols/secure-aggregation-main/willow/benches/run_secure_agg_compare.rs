use std::collections::HashMap;
use std::rc::Rc;
use std::env;
use std::thread;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use ahe_traits::AheBase;
use client_traits::SecureAggregationClient;
use decryptor_traits::SecureAggregationDecryptor;
use kahe_traits::KaheBase;
use messages::{ClientMessage, PartialDecryptionRequest};
use messages_rust_proto::ClientMessage as ClientMessageProto;
use proto_serialization_traits::ToProto;
use proto_serialization_traits::FromProto;
use protobuf::prelude::*;
use server_traits::SecureAggregationServer;
use shell_ciphertexts_rust_proto::ShellAhePublicKey;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use testing_utils::{generate_random_nonce, generate_random_unsigned_vector};
use willow_v1_client::WillowV1Client;
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
use willow_v1_server::{ServerState, WillowV1Server};

const DEFAULT_ID: &str = "default";
const CONTEXT_STRING: &[u8] = b"compare_benchmark_context_string";

fn main() {
    let n_clients = env_usize("BENCH_N_CLIENTS", 128);
    let active_clients = env_usize("BENCH_ACTIVE_CLIENTS", 113);
    let committee_size = env_usize("BENCH_COMMITTEE_SIZE", 50);
    let threshold_t = env_usize("BENCH_THRESHOLD", 40);
    let input_length = env_usize("BENCH_VECTOR_LEN", 10_000);
    let bench_threads = env_usize("BENCH_THREADS", default_thread_count()).max(1);
    let input_domain = 255_u64;

    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            DEFAULT_ID.to_string(),
            (input_length as isize, input_domain as i64),
        )]),
        max_number_of_decryptors: committee_size as i64,
        max_number_of_clients: n_clients as i64,
        max_decryptor_dropouts: (committee_size - threshold_t) as i64,
        key_id: b"compare".to_vec(),
    };
    let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config).unwrap();
    let kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let vahe = Rc::new(ShellVahe::new(ahe_config.clone(), CONTEXT_STRING).unwrap());
    let server = WillowV1Server { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };

    let mut decryptor_states = Vec::with_capacity(committee_size);
    let mut decryptors = Vec::with_capacity(committee_size);
    for _ in 0..committee_size {
        decryptor_states.push(DecryptorState::default());
        decryptors.push(WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe)).unwrap());
    }
    let mut server_state = ServerState::default();
    for (i, decryptor) in decryptors.iter().enumerate() {
        let public_key_share = decryptor.create_public_key_share(&mut decryptor_states[i]).unwrap();
        server
            .handle_decryptor_public_key_share(public_key_share, format!("Decryptor {i}").as_str(), &mut server_state)
            .unwrap();
    }
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();
    let public_key_bytes = public_key.to_proto(&*vahe).unwrap().serialize().unwrap();

    let mut plain_inputs = Vec::with_capacity(active_clients);
    for _ in 0..active_clients {
        plain_inputs.push(generate_random_unsigned_vector(input_length, input_domain));
    }

    let plain_server_compute_s = measure_plain_server_aggregate(&plain_inputs);

    let t0 = Instant::now();
    let client_message_bytes: Vec<Vec<u8>> =
        parallel_collect(active_clients, bench_threads, |client_index| {
        let local_kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
        let local_vahe = Rc::new(ShellVahe::new(ahe_config.clone(), CONTEXT_STRING).unwrap());
        let local_client =
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&local_kahe), Rc::clone(&local_vahe))
                .unwrap();
        let public_key_proto = ShellAhePublicKey::parse(public_key_bytes.as_slice()).unwrap();
        let local_public_key = <ShellVahe as AheBase>::PublicKey::from_proto(public_key_proto, &*local_vahe).unwrap();
        let input_values = &plain_inputs[client_index];
        let plaintext_owned = HashMap::from([(DEFAULT_ID.to_string(), input_values.clone())]);
        let plaintext = ShellKahe::plaintext_as_slice(&plaintext_owned);
        let nonce = generate_random_nonce();
        let message = local_client.create_client_message(&plaintext, &local_public_key, &nonce).unwrap();
        message.to_proto(&local_client).unwrap().serialize().unwrap()
    });
    let client_compute_s = t0.elapsed().as_secs_f64();

    let client_to_server_bytes = client_message_bytes.iter().map(Vec::len).sum::<usize>();
    let client_messages = client_message_bytes
        .into_iter()
        .map(|bytes| {
            let proto = ClientMessageProto::parse(bytes.as_slice()).unwrap();
            ClientMessage::from_proto(proto, &server).unwrap()
        })
        .collect::<Vec<ClientMessage<ShellKahe, ShellVahe>>>();

    let t1 = Instant::now();
    let mut summed_partial_dec_ct = None;
    for msg in client_messages {
        let (ciphertext_contribution, dec_req_contribution) = server.split_client_message(msg).unwrap();
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state).unwrap();
        if let Some(acc) = &mut summed_partial_dec_ct {
            server
                .vahe
                .add_pd_ciphertexts_in_place(&dec_req_contribution.partial_dec_ciphertext, acc)
                .unwrap();
        } else {
            summed_partial_dec_ct = Some(dec_req_contribution.partial_dec_ciphertext);
        }
    }
    let server_handle_s = t1.elapsed().as_secs_f64();

    let partial_decryption_request =
        PartialDecryptionRequest { partial_dec_ciphertext: summed_partial_dec_ct.unwrap() };
    let request_proto = partial_decryption_request.to_proto(&decryptors[0]).unwrap();
    let request_bytes = request_proto.serialize().unwrap().len();
    let server_to_committee_bytes = request_bytes * committee_size;

    let t2 = Instant::now();
    let mut committee_to_server_bytes = 0_usize;
    for i in 0..threshold_t {
        let response = decryptors[i]
            .handle_partial_decryption_request(partial_decryption_request.clone(), &decryptor_states[i])
            .unwrap();
        let response_proto = response.to_proto(&server).unwrap();
        committee_to_server_bytes += response_proto.serialize().unwrap().len();
        server.handle_partial_decryption(response, &mut server_state).unwrap();
    }
    let decryptor_compute_s = t2.elapsed().as_secs_f64();

    let t3 = Instant::now();
    let _ = server.recover_aggregation_result(&server_state).unwrap();
    let server_recover_s = t3.elapsed().as_secs_f64();

    let secure_server_compute_s = server_handle_s + server_recover_s;
    let server_compute_with_plain_s = secure_server_compute_s + plain_server_compute_s;

    println!(
        "protocol=Willow n_clients={} active_clients={} vector_len={} committee_size={} threshold_t={} bench_threads={} client_compute_s={:.6} committee_compute_s={:.6} server_compute_s={:.6} plain_server_compute_s={:.6} server_compute_with_plain_s={:.6} client_to_server_bytes={} server_to_committee_bytes={} committee_to_server_bytes={} total_bytes={}",
        n_clients,
        active_clients,
        input_length,
        committee_size,
        threshold_t,
        bench_threads,
        client_compute_s,
        decryptor_compute_s,
        secure_server_compute_s,
        plain_server_compute_s,
        server_compute_with_plain_s,
        client_to_server_bytes,
        server_to_committee_bytes,
        committee_to_server_bytes,
        client_to_server_bytes + server_to_committee_bytes + committee_to_server_bytes
    );
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

fn env_usize(name: &str, default_value: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_value)
}

