use googletest::prelude::*;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use aggregation_config::AggregationConfig;
use curve25519_dalek::ristretto::RistrettoPoint;
use osa_shell_kahe::{
    OsaAuxEncryptionMode, OsaDigestMaskMode, OsaDigestSharingMode, OsaRssFieldMode,
    OsaShellKaheClient, OsaShellKaheCommitteeMember, OsaShellKaheParameters, OsaShellKaheServer,
    OsaShellKaheRngMode, RampSecretSharing, RoutedCommitteeShare,
};
use kahe_traits::{KaheBase, KaheKeygen, TrySecretKeyInto};
use prng_traits::SecurePrng;
use shell_kahe::ShellKahe;
use shell_parameters::create_shell_configs;
use single_thread_hkdf::SingleThreadHkdfPrng;

const CONTEXT_STRING: &[u8] = b"osa_shell_kahe_test_context";
const DEFAULT_ID: &str = "default";

#[gtest]
fn osa_shell_kahe_end_to_end() -> googletest::Result<()> {
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(DEFAULT_ID.to_string(), (10_000, 255))]),
        max_number_of_decryptors: 50,
        max_number_of_clients: 4,
        max_decryptor_dropouts: 10,
        key_id: b"osa-shell-kahe".to_vec(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config)?;
    let kahe = Rc::new(ShellKahe::new(kahe_config, CONTEXT_STRING)?);
    let params = OsaShellKaheParameters { committee_size: 50, threshold_t: 40, rss_secret_dim: 30 };
    let rss = RampSecretSharing::new(params.clone())?;
    let server = OsaShellKaheServer { kahe: Rc::clone(&kahe), rss: rss.clone() };

    let mut rng = SingleThreadHkdfPrng::create(&SingleThreadHkdfPrng::generate_seed()?)?;
    let sample_buffer = kahe.try_secret_key_into(kahe.key_gen(&mut rng)?)?;
    verify_eq!(sample_buffer.len(), 1 << 13)?;

    let committees: Vec<OsaShellKaheCommitteeMember> = (1..=params.committee_size)
        .map(|id| OsaShellKaheCommitteeMember::new(id))
        .collect();
    let committee_pks: Vec<RistrettoPoint> = committees.iter().map(|member| member.key_pair.public()).collect();

    let inputs = [
        vec![1_u64; 10_000],
        vec![2_u64; 10_000],
        vec![3_u64; 10_000],
        vec![4_u64; 10_000],
    ];
    let dropped_client = 2_usize;
    let mut uploads = Vec::new();
    for (idx, input) in inputs.iter().enumerate() {
        if idx == dropped_client {
            continue;
        }
        let owned = HashMap::from([(DEFAULT_ID.to_string(), input.clone())]);
        let slices = ShellKahe::plaintext_as_slice(&owned);
        uploads.push(OsaShellKaheClient { client_id: idx + 1 }.upload(
            7,
            &slices,
            &kahe,
            &rss,
            &committee_pks,
            OsaShellKaheRngMode::DeterministicBenchmark,
        )?);
    }

    let active_clients: BTreeSet<usize> = uploads.iter().map(|upload| upload.client_id).collect();
    let mut committee_outputs = Vec::new();
    for member in committees.iter().take(params.threshold_t) {
        committee_outputs.push(member.combine(7, &active_clients, &uploads, &params)?);
    }

    let aggregate = server.aggregate(7, &uploads, &committee_outputs)?;
    let output = aggregate.get(DEFAULT_ID).expect("missing output vector");
    verify_eq!(output.len(), 10_000)?;
    verify_eq!(output[0], 7_u64)?;
    verify_eq!(output[9_999], 7_u64)
}

#[gtest]
fn osa_shell_kahe_rejects_tampered_committee_ciphertext() -> googletest::Result<()> {
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(DEFAULT_ID.to_string(), (8, 255))]),
        max_number_of_decryptors: 5,
        max_number_of_clients: 1,
        max_decryptor_dropouts: 1,
        key_id: b"osa-shell-kahe-aead".to_vec(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config)?;
    let kahe = Rc::new(ShellKahe::new(kahe_config, CONTEXT_STRING)?);
    let params = OsaShellKaheParameters { committee_size: 5, threshold_t: 4, rss_secret_dim: 2 };
    let rss = RampSecretSharing::new(params.clone())?;
    let committees: Vec<OsaShellKaheCommitteeMember> = (1..=params.committee_size)
        .map(|id| OsaShellKaheCommitteeMember::new(id))
        .collect();
    let committee_pks: Vec<RistrettoPoint> = committees.iter().map(|member| member.key_pair.public()).collect();
    let owned = HashMap::from([(DEFAULT_ID.to_string(), vec![1_u64; 8])]);
    let slices = ShellKahe::plaintext_as_slice(&owned);
    let upload = OsaShellKaheClient { client_id: 1 }.upload(
        11,
        &slices,
        &kahe,
        &rss,
        &committee_pks,
        OsaShellKaheRngMode::DeterministicBenchmark,
    )?;
    let active_clients = BTreeSet::from([1_usize]);

    let mut bitflip_upload = upload.clone();
    bitflip_upload.encrypted_key_shares[0].body[0] ^= 1;
    let bitflip_result = committees[0].combine(11, &active_clients, &[bitflip_upload], &params);
    assert!(bitflip_result.is_err());

    let mut aad_upload = upload.clone();
    aad_upload.client_id = 2;
    let aad_clients = BTreeSet::from([2_usize]);
    let aad_result = committees[0].combine(11, &aad_clients, &[aad_upload], &params);
    assert!(aad_result.is_err());
    Ok(())
}

#[gtest]
fn osa_compact_seeded_variant_end_to_end() -> googletest::Result<()> {
    let aggregation_config = AggregationConfig {
        vector_lengths_and_bounds: HashMap::from([(DEFAULT_ID.to_string(), (32, 255))]),
        max_number_of_decryptors: 5,
        max_number_of_clients: 4,
        max_decryptor_dropouts: 1,
        key_id: b"osa-compact-seeded".to_vec(),
    };
    let (kahe_config, _) = create_shell_configs(&aggregation_config)?;
    let kahe = Rc::new(ShellKahe::new(kahe_config, CONTEXT_STRING)?);
    let params = OsaShellKaheParameters { committee_size: 5, threshold_t: 4, rss_secret_dim: 2 };
    let rss = RampSecretSharing::new_with_field_mode(params.clone(), OsaRssFieldMode::Compact31)?;
    let server = OsaShellKaheServer { kahe: Rc::clone(&kahe), rss: rss.clone() };
    let committees: Vec<OsaShellKaheCommitteeMember> = (1..=params.committee_size)
        .map(|id| OsaShellKaheCommitteeMember::new_for_iteration(19, id))
        .collect();
    let committee_pks: Vec<RistrettoPoint> =
        committees.iter().map(|member| member.key_pair.public()).collect();

    let mut uploads = Vec::new();
    for client_id in 1..=4 {
        let owned = HashMap::from([(
            DEFAULT_ID.to_string(),
            vec![client_id as u64; 32],
        )]);
        uploads.push(OsaShellKaheClient { client_id }.upload_with_protocol_modes(
            19,
            &ShellKahe::plaintext_as_slice(&owned),
            &kahe,
            &rss,
            &committee_pks,
            OsaShellKaheRngMode::DeterministicBenchmark,
            OsaDigestMaskMode::Shake256Xof,
            OsaAuxEncryptionMode::IndCpaShake256,
            OsaDigestSharingMode::SeededPrgDigest,
        )?);
    }
    let active_clients = uploads.iter().map(|upload| upload.client_id).collect::<BTreeSet<_>>();
    let mut committee_outputs = Vec::new();
    for member in committees.iter().take(params.threshold_t) {
        let routed = uploads
            .iter()
            .map(|upload| RoutedCommitteeShare {
                client_id: upload.client_id,
                ciphertext: upload.encrypted_key_shares[member.committee_member_id - 1].clone(),
            })
            .collect::<Vec<_>>();
        committee_outputs.push(
            member
                .combine_routed_with_timings_and_modes(
                    19,
                    &active_clients,
                    &routed,
                    OsaAuxEncryptionMode::IndCpaShake256,
                    OsaRssFieldMode::Compact31,
                )?
                .0,
        );
    }
    let aggregate = server
        .aggregate_with_timings_and_modes(
            19,
            &uploads,
            &committee_outputs,
            OsaDigestMaskMode::Shake256Xof,
            OsaDigestSharingMode::SeededPrgDigest,
        )?
        .0;
    let output = aggregate.get(DEFAULT_ID).expect("missing compact OSA output");
    verify_eq!(output.len(), 32)?;
    verify_true!(output.iter().all(|&value| value == 10))
}
