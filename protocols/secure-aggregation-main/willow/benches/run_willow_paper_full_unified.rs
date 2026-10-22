use std::collections::{BTreeSet, HashMap};
use std::env;
use std::rc::Rc;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use aggregation_config::AggregationConfig;
use ahe_traits::AheBase;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use decryptor_traits::SecureAggregationDecryptor;
use kahe_traits::{KaheBase, KaheKeygen, TrySecretKeyInto};
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
use prng_traits::SecurePrng;
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use server_traits::SecureAggregationServer;
use shell_ciphertexts_rust_proto::ShellAhePublicKey;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use shell_vahe::ShellVahe;
use single_thread_hkdf::SingleThreadHkdfPrng;
use testing_utils::generate_random_nonce;
use vahe_traits::VerifiableEncrypt;
use verifier_traits::SecureAggregationVerifier;
use willow_full_aux::{
    add_ring_masks_in_place, encrypt_seed, expand_seed_ring_mask, recover_aux_secret_key,
    setup_aux_threshold_keys, willow_seed_aad, WillowAuxRecoveryShare, WillowSeedCiphertext,
    WILLOW_AUX_CIPHERTEXT_BYTES, WILLOW_SEED_BYTES,
};
use willow_v1_client::WillowV1Client;
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
use willow_v1_server::{ServerState, WillowV1Server};
use willow_v1_verifier::{VerifierState, WillowV1Verifier};

const DEFAULT_ID: &str = "default";
const CONTEXT_STRING: &[u8] = b"willow_paper_full_unified_benchmark_v1";
const ITERATION: u64 = 1;

struct ClientBatch {
    messages: Vec<Vec<u8>>,
    operation_seconds: Vec<f64>,
    wall_seconds: f64,
    worker_setup_seconds: f64,
}

struct FullClientMessage {
    client_id: usize,
    iteration: u64,
    core: ClientMessage<ShellKahe, ShellVahe>,
    encrypted_seed: WillowSeedCiphertext,
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
        key_id: b"willow-paper-full-unified".to_vec(),
    };
    let (kahe_config, ahe_config) = create_shell_configs(&aggregation_config).unwrap();
    let kahe = Rc::new(ShellKahe::new(kahe_config.clone(), CONTEXT_STRING).unwrap());
    let vahe = Rc::new(ShellVahe::new(ahe_config.clone(), CONTEXT_STRING).unwrap());
    let server = WillowV1Server { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
    let verifier = WillowV1Verifier { vahe: Rc::clone(&vahe) };
    let mut verifier_state = VerifierState::default();
    let mut server_state = ServerState::default();

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

    // Figure 3 setup is reusable and outside the online timer. The online
    // committee response still carries the threshold recovery shares.
    let mut aux_setup_rng = StdRng::seed_from_u64(0x5749_4c4c_4f57_4655);
    let aux_setup =
        setup_aux_threshold_keys(committee_size, threshold_t, &mut aux_setup_rng).unwrap();
    let aux_public_key_bytes =
        aux_setup.public_parameters.aggregate_public_key().compress().to_bytes();
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
    let sample_aux_public_key =
        CompressedRistretto(aux_public_key_bytes).decompress().unwrap();
    let setup_before_workers_seconds = total_setup_start.elapsed().as_secs_f64();
    let sample_start = Instant::now();
    let sample_message = create_full_client_message(
        &sample_client,
        1,
        ITERATION,
        &sample_plaintext,
        &sample_public_key,
        &sample_aux_public_key,
        &generate_random_nonce(),
    )
    .unwrap();
    let sample_bytes = serialize_full_client_message(&sample_message, &sample_client);
    std::hint::black_box(&sample_bytes);
    let client_single_seconds = sample_start.elapsed().as_secs_f64();

    let online_start = Instant::now();
    let client_batch = parallel_clients(
        &inputs,
        bench_threads,
        &kahe_config,
        &ahe_config,
        &public_key_bytes,
        aux_public_key_bytes,
    );
    let client_to_server_bytes = client_batch.messages.iter().map(Vec::len).sum::<usize>();

    let initial_server_start = Instant::now();
    let mut verifier_messages = Vec::with_capacity(active_clients);
    let mut encrypted_seeds = Vec::with_capacity(active_clients);
    let mut client_ids = BTreeSet::new();
    for bytes in &client_batch.messages {
        let message = deserialize_full_client_message(bytes, &server);
        assert_eq!(message.iteration, ITERATION);
        assert!(client_ids.insert(message.client_id), "duplicate Willow client id");
        encrypted_seeds.push((message.client_id, message.encrypted_seed));
        let (ciphertext_contribution, verifier_contribution) =
            server.split_client_message(message.core).unwrap();
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
    assert_eq!(client_ids.len(), active_clients);
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
    let mut committee_aux_share_serialize_seconds = Vec::with_capacity(threshold_t);
    let mut response_bytes = Vec::with_capacity(threshold_t);
    for id in 0..threshold_t {
        let operation_start = Instant::now();
        let request_proto = PartialDecryptionRequestProto::parse(request_bytes.as_slice()).unwrap();
        let local_request: PartialDecryptionRequest<ShellVahe> =
            PartialDecryptionRequest::from_proto(request_proto, &decryptors[id]).unwrap();
        let response = decryptors[id]
            .handle_partial_decryption_request(local_request, &decryptor_states[id])
            .unwrap();
        let partial_bytes = response.to_proto(&server).unwrap().serialize().unwrap();
        let aux_start = Instant::now();
        let aux_bytes = aux_setup.committee_recovery_shares[id].to_bytes();
        let bytes = serialize_committee_response(&partial_bytes, &aux_bytes);
        committee_aux_share_serialize_seconds.push(aux_start.elapsed().as_secs_f64());
        committee_operation_seconds.push(operation_start.elapsed().as_secs_f64());
        response_bytes.push(bytes);
    }
    let committee_to_server_bytes = response_bytes.iter().map(Vec::len).sum::<usize>();

    let final_server_start = Instant::now();
    let mut aux_recovery_shares = Vec::with_capacity(threshold_t);
    for bytes in &response_bytes {
        let (partial_bytes, aux_bytes) = deserialize_committee_response(bytes);
        let proto = PartialDecryptionResponseProto::parse(partial_bytes).unwrap();
        let response: PartialDecryptionResponse<ShellVahe> =
            PartialDecryptionResponse::from_proto(proto, &server).unwrap();
        server.handle_partial_decryption(response, &mut server_state).unwrap();
        aux_recovery_shares.push(WillowAuxRecoveryShare::from_bytes(aux_bytes).unwrap());
    }

    let aux_key_start = Instant::now();
    let aux_secret_key =
        recover_aux_secret_key(&aux_setup.public_parameters, &aux_recovery_shares).unwrap();
    let server_aux_key_reconstruction_seconds = aux_key_start.elapsed().as_secs_f64();
    let mask_limb_count = kahe.packed_coefficient_count() * 4;
    let modulus_bits = kahe.plaintext_modulus_bits();
    let mut aggregate_mask = vec![0_u64; mask_limb_count];
    let mut server_seed_decryption_seconds = 0.0_f64;
    let mut server_mask_expansion_seconds = 0.0_f64;
    let mut server_mask_accumulation_seconds = 0.0_f64;
    for (client_id, encrypted_seed) in &encrypted_seeds {
        let phase_start = Instant::now();
        let seed = aux_secret_key
            .decrypt_seed(encrypted_seed, &willow_seed_aad(ITERATION, *client_id))
            .unwrap();
        server_seed_decryption_seconds += phase_start.elapsed().as_secs_f64();

        let phase_start = Instant::now();
        let mask = expand_seed_ring_mask(
            &seed,
            kahe.packed_coefficient_count(),
            modulus_bits,
            ITERATION,
        );
        server_mask_expansion_seconds += phase_start.elapsed().as_secs_f64();

        let phase_start = Instant::now();
        add_ring_masks_in_place(&mut aggregate_mask, &mask, modulus_bits);
        server_mask_accumulation_seconds += phase_start.elapsed().as_secs_f64();
    }
    let final_recovery_start = Instant::now();
    let result = server
        .recover_aggregation_result_with_ring_mask(&server_state, &aggregate_mask)
        .unwrap();
    let server_final_recovery_seconds = final_recovery_start.elapsed().as_secs_f64();
    server_seconds += final_server_start.elapsed().as_secs_f64();
    let online_wall_seconds = online_start.elapsed().as_secs_f64();

    let expected = active_clients.min(7) as u64;
    let output = result.get(DEFAULT_ID).expect("missing Willow output");
    assert_eq!(output.len(), vector_len);
    assert!(
        output.iter().all(|&value| value == expected),
        "Willow paper-full aggregate mismatch: expected {}, first values {:?}",
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
        "protocol=Willow-paper-full-online implementation_scope=fig3_fig4_fig5_prg_seed_aux_threshold_key_recovery n_clients={} active_clients={} vector_len={} committee_size={} threshold_t={} bench_threads={} setup_s={:.6} client_compute_s={:.6} client_observed_mean_s={:.6} client_batch_wall_s={:.6} committee_compute_s={:.6} committee_aux_share_serialize_s={:.6} verifier_compute_s={:.6} server_compute_s={:.6} server_aux_key_reconstruction_s={:.6} server_seed_decryption_s={:.6} server_mask_expansion_s={:.6} server_mask_accumulation_s={:.6} server_final_recovery_s={:.6} online_wall_s={:.6} client_to_server_bytes={} server_to_verifier_bytes={} verifier_to_committee_bytes={} committee_to_server_bytes={} client_bytes_mean={:.3} committee_bytes_mean={:.3} server_receive_bytes={} server_send_bytes={} verifier_receive_bytes={} verifier_send_bytes={} total_bytes={} correctness=pass",
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
        mean(&committee_aux_share_serialize_seconds),
        verifier_seconds,
        server_seconds,
        server_aux_key_reconstruction_seconds,
        server_seed_decryption_seconds,
        server_mask_expansion_seconds,
        server_mask_accumulation_seconds,
        server_final_recovery_seconds,
        online_wall_seconds,
        client_to_server_bytes,
        server_to_verifier_bytes,
        verifier_to_committee_bytes,
        committee_to_server_bytes,
        client_to_server_bytes as f64 / active_clients as f64,
        (verifier_to_committee_bytes + committee_to_server_bytes) as f64 / threshold_t as f64,
        client_to_server_bytes + committee_to_server_bytes,
        server_to_verifier_bytes + verifier_to_committee_bytes,
        server_to_verifier_bytes,
        verifier_to_committee_bytes,
        total_bytes,
    );
}

fn create_full_client_message(
    client: &WillowV1Client<ShellKahe, ShellVahe>,
    client_id: usize,
    iteration: u64,
    plaintext: &HashMap<&str, &[u64]>,
    public_key: &<ShellVahe as AheBase>::PublicKey,
    aux_public_key: &RistrettoPoint,
    nonce: &[u8],
) -> Result<FullClientMessage, status::StatusError> {
    let mut prng = client.prng.borrow_mut();
    let kahe_secret_key = client.kahe.key_gen(&mut prng)?;
    let mut seed = [0_u8; WILLOW_SEED_BYTES];
    fill_prng(&mut prng, &mut seed)?;
    let ring_mask = expand_seed_ring_mask(
        &seed,
        client.kahe.packed_coefficient_count(),
        client.kahe.plaintext_modulus_bits(),
        iteration,
    );
    let kahe_ciphertext =
        client.kahe.encrypt_with_ring_mask(plaintext, &kahe_secret_key, &ring_mask, &mut prng)?;
    let ahe_plaintext: Vec<i64> = client.kahe.try_secret_key_into(kahe_secret_key)?;
    let (ahe_ciphertext, proof) =
        client.vahe.verifiable_encrypt(&ahe_plaintext, public_key, nonce, &mut prng)?;
    let mut ephemeral_randomness = [0_u8; 64];
    fill_prng(&mut prng, &mut ephemeral_randomness)?;
    let encrypted_seed = encrypt_seed(
        aux_public_key.clone(),
        &seed,
        &willow_seed_aad(iteration, client_id),
        &ephemeral_randomness,
    );
    Ok(FullClientMessage {
        client_id,
        iteration,
        core: ClientMessage {
            kahe_ciphertext,
            ahe_ciphertext,
            proof,
            nonce: nonce.to_vec(),
        },
        encrypted_seed,
    })
}

fn parallel_clients(
    inputs: &[Vec<u64>],
    thread_count: usize,
    kahe_config: &<ShellKahe as KaheBase>::Config,
    ahe_config: &<ShellVahe as AheBase>::Config,
    public_key_bytes: &[u8],
    aux_public_key_bytes: [u8; 32],
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
                let local_aux_public_key =
                    CompressedRistretto(aux_public_key_bytes).decompress().unwrap();
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
                for (offset, (client, input)) in
                    clients.iter().zip(&inputs[start..end]).enumerate()
                {
                    let client_id = start + offset + 1;
                    let plaintext = HashMap::from([(DEFAULT_ID, input.as_slice())]);
                    let operation_start = Instant::now();
                    let message = create_full_client_message(
                        client,
                        client_id,
                        ITERATION,
                        &plaintext,
                        &local_public_key,
                        &local_aux_public_key,
                        &generate_random_nonce(),
                    )
                    .unwrap();
                    let bytes = serialize_full_client_message(&message, client);
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

fn serialize_full_client_message(
    message: &FullClientMessage,
    context: &WillowV1Client<ShellKahe, ShellVahe>,
) -> Vec<u8> {
    let core_bytes = message.core.to_proto(context).unwrap().serialize().unwrap();
    let mut out = Vec::with_capacity(24 + core_bytes.len() + WILLOW_AUX_CIPHERTEXT_BYTES);
    push_u64(&mut out, message.client_id as u64);
    push_u64(&mut out, message.iteration);
    push_blob(&mut out, &core_bytes);
    out.extend_from_slice(&message.encrypted_seed.to_bytes());
    out
}

fn deserialize_full_client_message(
    bytes: &[u8],
    context: &WillowV1Server<ShellKahe, ShellVahe>,
) -> FullClientMessage {
    let mut offset = 0;
    let client_id = read_u64(bytes, &mut offset) as usize;
    let iteration = read_u64(bytes, &mut offset);
    let core_bytes = read_blob(bytes, &mut offset);
    let core_proto = ClientMessageProto::parse(core_bytes).unwrap();
    let core = ClientMessage::from_proto(core_proto, context).unwrap();
    let encrypted_seed = WillowSeedCiphertext::from_bytes(&bytes[offset..]).unwrap();
    FullClientMessage { client_id, iteration, core, encrypted_seed }
}

fn serialize_committee_response(partial_response: &[u8], aux_share: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + partial_response.len() + aux_share.len());
    push_blob(&mut out, partial_response);
    push_blob(&mut out, aux_share);
    out
}

fn deserialize_committee_response(bytes: &[u8]) -> (&[u8], &[u8]) {
    let mut offset = 0;
    let partial_response = read_blob(bytes, &mut offset);
    let aux_share = read_blob(bytes, &mut offset);
    assert_eq!(offset, bytes.len());
    (partial_response, aux_share)
}

fn fill_prng(
    prng: &mut SingleThreadHkdfPrng,
    output: &mut [u8],
) -> Result<(), status::StatusError> {
    for byte in output {
        *byte = prng.rand8()?;
    }
    Ok(())
}

fn common_low_value_inputs(client_count: usize, vector_len: usize) -> Vec<Vec<u64>> {
    (0..client_count)
        .map(|client| vec![u64::from(client < 7); vector_len])
        .collect()
}

fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn read_blob<'a>(bytes: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length = read_u64(bytes, offset) as usize;
    let end = offset.checked_add(length).expect("message offset overflow");
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
