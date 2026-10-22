use std::collections::HashMap;
use std::env;
use std::rc::Rc;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use ahe_traits::AheBase;
use client_traits::SecureAggregationClient;
use decryptor_traits::SecureAggregationDecryptor;
use kahe_traits::KaheBase;
use messages::{
    ClientMessage, DecryptionRequestContribution, PartialDecryptionRequest,
    PartialDecryptionResponse,
};
use messages_rust_proto::{
    ClientMessage as ClientMessageProto,
    DecryptionRequestContribution as DecryptionRequestContributionProto,
    PartialDecryptionRequest as PartialDecryptionRequestProto,
    PartialDecryptionResponse as PartialDecryptionResponseProto,
};
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use server_traits::SecureAggregationServer;
use shell_ciphertexts_rust_proto::ShellAhePublicKey;
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
const CONTEXT_STRING: &[u8] = b"willow_full_unified_benchmark_v1";

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
    let vector_len = env_usize("BENCH_VECTOR_LEN", 10_000);
    let bench_threads = env_usize("BENCH_THREADS", default_thread_count()).max(1);
    assert!(active_clients <= n_clients);
    assert!(threshold_t <= committee_size);

    let total_setup_start = Instant::now();
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(
            DEFAULT_ID.to_string(),
            (vector_len as isize, 2_i64),
        )]),
        max_number_of_decryptors: committee_size as i64,
        max_number_of_clients: n_clients as i64,
        max_decryptor_dropouts: (committee_size - threshold_t) as i64,
        key_id: b"willow-full-unified".to_vec(),
    };
    let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config).unwrap();
    let kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let vahe = Rc::new(ShellVahe::new(ahe_config.clone(), CONTEXT_STRING).unwrap());
    let server = WillowV1Server { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();
    let mut server_state = ServerState::default();

    // The released AHE uses additive key shares rather than threshold shares.
    // Build the round public key from the members that are online for this
    // round; every share included in this public key must later decrypt.
    let mut decryptors = Vec::with_capacity(threshold_t);
    let mut decryptor_states = Vec::with_capacity(threshold_t);
    for id in 0..threshold_t {
        let mut state = DecryptorState::default();
        let decryptor =
            WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe)).unwrap();
        let public_key_share = decryptor.create_public_key_share(&mut state).unwrap();
        server
            .handle_decryptor_public_key_share(
                public_key_share,
                &format!("Decryptor {id}"),
                &mut server_state,
            )
            .unwrap();
        decryptors.push(decryptor);
        decryptor_states.push(state);
    }
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();
    let public_key_bytes = public_key.to_proto(&*vahe).unwrap().serialize().unwrap();
    let inputs = common_low_value_inputs(active_clients, vector_len);

    let sample_kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let sample_vahe = Rc::new(ShellVahe::new(ahe_config.clone(), CONTEXT_STRING).unwrap());
    let sample_client = WillowV1Client::new_with_randomly_generated_seed(
        Rc::clone(&sample_kahe),
        Rc::clone(&sample_vahe),
    )
    .unwrap();
    let sample_public_key_proto = ShellAhePublicKey::parse(public_key_bytes.as_slice()).unwrap();
    let sample_public_key =
        <ShellVahe as AheBase>::PublicKey::from_proto(sample_public_key_proto, &*sample_vahe)
            .unwrap();
    let sample_plaintext = HashMap::from([(DEFAULT_ID, inputs[0].as_slice())]);
    let setup_before_workers_seconds = total_setup_start.elapsed().as_secs_f64();
    let sample_start = Instant::now();
    let sample_message = sample_client
        .create_client_message(&sample_plaintext, &sample_public_key, &generate_random_nonce())
        .unwrap();
    let sample_bytes = sample_message
        .to_proto(&sample_client)
        .unwrap()
        .serialize()
        .unwrap();
    std::hint::black_box(&sample_bytes);
    let client_single_seconds = sample_start.elapsed().as_secs_f64();

    let online_start = Instant::now();
    let client_batch = parallel_clients(
        &inputs,
        bench_threads,
        &kahe_config,
        &ahe_config,
        &public_key_bytes,
    );

    let client_to_server_bytes = client_batch.messages.iter().map(Vec::len).sum::<usize>();
    let initial_server_start = Instant::now();
    let mut verifier_messages = Vec::with_capacity(active_clients);
    for bytes in &client_batch.messages {
        let proto = ClientMessageProto::parse(bytes.as_slice()).unwrap();
        let message: ClientMessage<ShellKahe, ShellVahe> =
            ClientMessage::from_proto(proto, &server).unwrap();
        let (ciphertext_contribution, verifier_contribution) =
            server.split_client_message(message).unwrap();
        server
            .handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)
            .unwrap();
        let nonce = verifier_contribution.nonce.clone();
        verifier_messages.push((
            nonce,
            verifier_contribution
                .to_proto(&verifier)
                .unwrap()
                .serialize()
                .unwrap(),
        ));
    }
    verifier_messages.sort_by(|left, right| left.0.cmp(&right.0));
    let mut server_seconds = initial_server_start.elapsed().as_secs_f64();
    let server_to_verifier_bytes =
        verifier_messages.iter().map(|(_, bytes)| bytes.len()).sum::<usize>();

    let verifier_start = Instant::now();
    for (_, bytes) in &verifier_messages {
        let proto = DecryptionRequestContributionProto::parse(bytes.as_slice()).unwrap();
        let contribution: DecryptionRequestContribution<ShellVahe> =
            DecryptionRequestContribution::from_proto(proto, &verifier).unwrap();
        verifier.verify_and_include(contribution, &mut verifier_state).unwrap();
    }
    let request = verifier.create_partial_decryption_request(verifier_state).unwrap();
    let request_bytes = request.to_proto(&verifier).unwrap().serialize().unwrap();
    let verifier_seconds = verifier_start.elapsed().as_secs_f64();
    let verifier_to_committee_bytes = request_bytes.len() * threshold_t;

    let mut committee_operation_seconds = Vec::with_capacity(threshold_t);
    let mut response_bytes = Vec::with_capacity(threshold_t);
    for id in 0..threshold_t {
        let operation_start = Instant::now();
        let request_proto = PartialDecryptionRequestProto::parse(request_bytes.as_slice()).unwrap();
        let local_request: PartialDecryptionRequest<ShellVahe> =
            PartialDecryptionRequest::from_proto(request_proto, &decryptors[id]).unwrap();
        let response = decryptors[id]
            .handle_partial_decryption_request(local_request, &decryptor_states[id])
            .unwrap();
        let bytes = response.to_proto(&server).unwrap().serialize().unwrap();
        committee_operation_seconds.push(operation_start.elapsed().as_secs_f64());
        response_bytes.push(bytes);
    }
    let committee_to_server_bytes = response_bytes.iter().map(Vec::len).sum::<usize>();

    let final_server_start = Instant::now();
    for bytes in &response_bytes {
        let proto = PartialDecryptionResponseProto::parse(bytes.as_slice()).unwrap();
        let response: PartialDecryptionResponse<ShellVahe> =
            PartialDecryptionResponse::from_proto(proto, &server).unwrap();
        server.handle_partial_decryption(response, &mut server_state).unwrap();
    }
    let result = server.recover_aggregation_result(&server_state).unwrap();
    server_seconds += final_server_start.elapsed().as_secs_f64();
    let online_wall_seconds = online_start.elapsed().as_secs_f64();

    let expected = active_clients.min(7) as u64;
    let output = result.get(DEFAULT_ID).expect("missing Willow output");
    assert_eq!(output.len(), vector_len);
    assert!(
        output.iter().all(|&value| value == expected),
        "Willow aggregate mismatch: expected {}, first values {:?}",
        expected,
        &output[..output.len().min(8)]
    );

    let committee_single_seconds = mean(&committee_operation_seconds);
    let client_observed_mean_seconds = mean(&client_batch.operation_seconds);
    let total_bytes = client_to_server_bytes
        + server_to_verifier_bytes
        + verifier_to_committee_bytes
        + committee_to_server_bytes;
    let setup_seconds = setup_before_workers_seconds + client_batch.worker_setup_seconds;

    println!(
        "protocol=Willow-released-full-online implementation_scope=released_api_no_verifiable_partial_decryption_proof_no_post_keygen_decryptor_dropout n_clients={} active_clients={} vector_len={} committee_size={} threshold_t={} bench_threads={} setup_s={:.6} client_compute_s={:.6} client_observed_mean_s={:.6} client_batch_wall_s={:.6} committee_compute_s={:.6} verifier_compute_s={:.6} server_compute_s={:.6} online_wall_s={:.6} client_to_server_bytes={} server_to_verifier_bytes={} verifier_to_committee_bytes={} committee_to_server_bytes={} client_bytes_mean={:.3} committee_bytes_mean={:.3} server_receive_bytes={} server_send_bytes={} verifier_receive_bytes={} verifier_send_bytes={} total_bytes={} correctness=pass",
        n_clients,
        active_clients,
        vector_len,
        committee_size,
        threshold_t,
        bench_threads,
        setup_seconds,
        client_single_seconds,
        client_observed_mean_seconds,
        client_batch.wall_seconds,
        committee_single_seconds,
        verifier_seconds,
        server_seconds,
        online_wall_seconds,
        client_to_server_bytes,
        server_to_verifier_bytes,
        verifier_to_committee_bytes,
        committee_to_server_bytes,
        client_to_server_bytes as f64 / active_clients as f64,
        (verifier_to_committee_bytes + committee_to_server_bytes) as f64 / threshold_t as f64,
        client_to_server_bytes + committee_to_server_bytes,
        server_to_verifier_bytes,
        server_to_verifier_bytes,
        verifier_to_committee_bytes,
        total_bytes,
    );
}

fn parallel_clients(
    inputs: &[Vec<u64>],
    thread_count: usize,
    kahe_config: &<ShellKahe as KaheBase>::Config,
    ahe_config: &<ShellVahe as AheBase>::Config,
    public_key_bytes: &[u8],
) -> ClientBatch {
    let workers = thread_count.min(inputs.len()).max(1);
    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let mut worker_setup_seconds = 0.0_f64;
    let (wall_seconds, results) = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let start = worker * inputs.len() / workers;
            let end = (worker + 1) * inputs.len() / workers;
            let local_kahe_config = kahe_config.clone();
            let local_ahe_config = ahe_config.clone();
            let local_public_key_bytes = public_key_bytes.to_vec();
            let local_ready = Arc::clone(&ready);
            let local_go = Arc::clone(&go);
            handles.push(scope.spawn(move || {
                let setup_start = Instant::now();
                let local_kahe =
                    Rc::new(ShellKahe::new(local_kahe_config, CONTEXT_STRING).unwrap());
                let local_vahe =
                    Rc::new(ShellVahe::new(local_ahe_config, CONTEXT_STRING).unwrap());
                let public_key_proto =
                    ShellAhePublicKey::parse(local_public_key_bytes.as_slice()).unwrap();
                let local_public_key = <ShellVahe as AheBase>::PublicKey::from_proto(
                    public_key_proto,
                    &*local_vahe,
                )
                .unwrap();
                let clients = (start..end)
                    .map(|_| {
                        WillowV1Client::new_with_randomly_generated_seed(
                            Rc::clone(&local_kahe),
                            Rc::clone(&local_vahe),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();
                let setup_seconds = setup_start.elapsed().as_secs_f64();
                local_ready.wait();
                local_go.wait();
                let mut output = Vec::with_capacity(end - start);
                for (client, input) in clients.iter().zip(&inputs[start..end]) {
                    let plaintext = HashMap::from([(DEFAULT_ID, input.as_slice())]);
                    let operation_start = Instant::now();
                    let message = client
                        .create_client_message(
                            &plaintext,
                            &local_public_key,
                            &generate_random_nonce(),
                        )
                        .unwrap();
                    let bytes = message.to_proto(client).unwrap().serialize().unwrap();
                    output.push((bytes, operation_start.elapsed().as_secs_f64()));
                }
                (setup_seconds, output)
            }));
        }
        ready.wait();
        let wall_start = Instant::now();
        go.wait();
        let results =
            handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
        (wall_start.elapsed().as_secs_f64(), results)
    });
    let mut messages = Vec::with_capacity(inputs.len());
    let mut operation_seconds = Vec::with_capacity(inputs.len());
    for (setup_seconds, values) in results {
        worker_setup_seconds = worker_setup_seconds.max(setup_seconds);
        for (bytes, seconds) in values {
            messages.push(bytes);
            operation_seconds.push(seconds);
        }
    }
    ClientBatch { messages, operation_seconds, wall_seconds, worker_setup_seconds }
}

fn common_low_value_inputs(client_count: usize, vector_len: usize) -> Vec<Vec<u64>> {
    (0..client_count)
        .map(|client| vec![u64::from(client < 7); vector_len])
        .collect()
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
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
