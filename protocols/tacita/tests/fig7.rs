use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{pairing::PairingOutput, PrimeGroup};
use ark_std::Zero;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use tacita_ste_comparison::{
    benchmark::{Config, Fixture},
    fig7::*,
    fig7_benchmark,
    ste::{encode, wire},
};

#[test]
fn whole_key_seed_recovery_threshold_padding_and_negative_cases() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    pool.install(|| {
        let mut rng = StdRng::seed_from_u64(501);
        let (ctx, mut members) = BatchedContext::setup(5, 3, 33, b"round-1", &mut rng).unwrap();
        assert_eq!(ctx.domain(), 8);
        let a = (0..33).map(|j| j as i64 - 16).collect::<Vec<_>>();
        let b = (0..33).map(|j| 37 - j as i64).collect::<Vec<_>>();
        let ca = ctx.encrypt_key(&a, &mut rng).unwrap();
        let cb = ctx.encrypt_key(&b, &mut rng).unwrap();
        assert_ne!(ca.inner.sa1, cb.inner.sa1);
        let sum = ctx.aggregate(&[ca.clone(), cb]).unwrap();
        let responses = members
            .iter_mut()
            .map(|m| ctx.answer(m, &sum, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let selected = [
            responses[4].clone(),
            responses[1].clone(),
            responses[3].clone(),
        ];
        let expected = vec![encode(21); 33];
        assert_eq!(ctx.decrypt_key(&sum, &selected).unwrap(), expected);
        assert_eq!(ctx.decrypt_key(&sum, &responses).unwrap(), expected);
        assert!(ctx.answer(&mut members[0], &sum, &mut rng).is_err());
        assert!(ctx.decrypt_key(&sum, &selected[..2]).is_err());
        assert!(ctx
            .decrypt_key(
                &sum,
                &[
                    selected[0].clone(),
                    selected[0].clone(),
                    selected[1].clone()
                ]
            )
            .is_err());
        assert!(ctx.decrypt_key(&ca, &selected).is_err());
        let mut bad = selected.to_vec();
        bad[0].bound.pd += G1Projective::generator();
        assert!(ctx.decrypt_key(&sum, &bad).is_err());
        let mut bad = selected.to_vec();
        bad[0].bound.id = 5;
        assert!(ctx.decrypt_key(&sum, &bad).is_err());
        let mut foreign = sum.clone();
        foreign.context_id[0] ^= 1;
        assert!(ctx.decrypt_key(&foreign, &selected).is_err());
        let mut truncated = sum.clone();
        truncated.inner.ct.pop();
        assert!(ctx.aggregate(&[truncated]).is_err());
        let mut wrong_t = sum.clone();
        wrong_t.inner.t = 2;
        assert!(ctx.decrypt_key(&wrong_t, &selected).is_err());
        assert!(ctx.aggregate(&[]).is_err());

        let mut s0 = [0; 32];
        let mut s1 = [0; 32];
        rng.fill_bytes(&mut s1);
        for (i, x) in s0.iter_mut().enumerate() {
            *x = [0, 1, 127, 128, 255][i % 5];
        }
        let seeds = [
            ctx.encrypt_seed(&s0, &mut rng),
            ctx.encrypt_seed(&s1, &mut rng),
        ];
        assert_eq!(
            ctx.decrypt_seeds(&seeds, &selected).unwrap(),
            vec![s0.to_vec(), s1.to_vec()]
        );
        let mut bad = selected.to_vec();
        bad[0].tag.response += Fr::from(1);
        assert!(ctx.decrypt_seeds(&seeds, &bad).is_err());
        let mut wrong_seeds = seeds.to_vec();
        wrong_seeds[0].context_id[0] ^= 1;
        assert!(ctx.decrypt_seeds(&wrong_seeds, &selected).is_err());
        let mut wrong_seeds = seeds.to_vec();
        wrong_seeds[0].bytes.pop();
        assert!(ctx.decrypt_seeds(&wrong_seeds, &selected).is_err());
        // Original tag shares must not decrypt modified/key ciphertexts.
        let mut wrong_seeds = seeds.to_vec();
        wrong_seeds[0].bytes[0] = ca.inner.clone();
        wrong_seeds[0].bytes[0].ct.truncate(1);
        assert!(ctx.decrypt_seeds(&wrong_seeds, &selected).is_err());
        assert_eq!(read_key(&wire(&sum)).unwrap().inner, sum.inner);
        let mut trailing = wire(&sum);
        trailing.push(0);
        assert!(read_key(&trailing).is_err());
        let mut invalid = sum.clone();
        invalid.inner.ct[0] =
            PairingOutput::<ark_bls12_381::Bls12_381>(ark_bls12_381::Fq12::zero());
        assert!(read_key(&wire(&invalid)).is_err());
        assert_eq!(selected[0].tag.pd.len(), 1);

        // The proof transcript binds the full payload, not just the shared head.
        let mut altered = sum.clone();
        altered.inner.ct[0] += encode(1);
        assert!(ctx.decrypt_key(&altered, &selected).is_err());
    });
}

#[test]
fn two_share_response_size_does_not_depend_on_key_payload_length() {
    let mut rng = StdRng::seed_from_u64(20);
    let mut sizes = Vec::new();
    for dimensions in [1, 7, 65] {
        let (ctx, mut members) =
            BatchedContext::setup(2, 2, dimensions, b"size-test", &mut rng).unwrap();
        let ct = ctx.encrypt_key(&vec![-37; dimensions], &mut rng).unwrap();
        let responses = members
            .iter_mut()
            .map(|m| ctx.answer(m, &ct, &mut rng).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            ctx.decrypt_key(&ct, &responses).unwrap(),
            vec![encode(-37); dimensions]
        );
        sizes.push(wire(&responses[0]).len());
    }
    assert!(sizes.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn benchmark_version_traffic_and_exact_signed_recovery() {
    let config = Config {
        n_clients: 4,
        active_clients: 3,
        committee_size: 3,
        threshold: 2,
        slots: 1,
        threads: 2,
        input_bound: 37,
        mask_inputs: false,
    };
    let fixture = Fixture {
        values: vec![vec![-37, 37, 0], vec![1, -2, 3], vec![-4, 5, 6]],
        seeds: Some(vec![vec![0; 32], vec![255; 32], vec![128; 32]]),
    };
    let r = fig7_benchmark::run(config, fixture).unwrap();
    assert_eq!(r.common.decoded_sum, vec![-40, 40, 9]);
    assert_eq!(r.common.config.slots, 3);
    assert_eq!(r.implementation_version, VERSION);
    assert_eq!(r.main_headers_per_client, 1);
    assert_eq!(r.bound_shares_per_member, 1);
    assert_eq!(r.tag_shares_per_member, 1);
    assert!(!r.common.mklhts_enabled && !r.common.input_soundness);
    assert_eq!(
        r.common.total_bytes,
        r.common.client_to_server_bytes
            + r.common.server_to_committee_bytes
            + r.common.committee_to_server_bytes
    );
}

#[test]
#[ignore = "full 8192-coordinate STE core check; not a KAHE end-to-end test"]
fn full_fixed_profile_key_dimension() {
    let config = Config {
        n_clients: 4,
        active_clients: 3,
        committee_size: 3,
        threshold: 2,
        slots: 1,
        threads: 4,
        input_bound: 37,
        mask_inputs: false,
    };
    let fixture = Fixture {
        values: (0..3)
            .map(|i| (0..8192).map(|j| ((i + j) % 75) as i64 - 37).collect())
            .collect(),
        seeds: Some(vec![vec![0; 32], vec![255; 32], vec![128; 32]]),
    };
    let r = fig7_benchmark::run(config, fixture).unwrap();
    assert_eq!(r.key_coordinates, 8192);
    assert_eq!(r.common.decoded_sum.len(), 8192);
    println!("FULL_KEY_CORE_PASS key_coordinates={} setup_s={:.3} online_s={:.3} main_headers={} bound_shares={} tag_shares={} total_bytes={}",
        r.key_coordinates,r.common.setup_s,r.common.online_wall_s,r.main_headers_per_client,
        r.bound_shares_per_member,r.tag_shares_per_member,r.common.total_bytes);
}
