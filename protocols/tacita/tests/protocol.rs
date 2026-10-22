use ark_ec::PrimeGroup;
use rand::{rngs::StdRng, SeedableRng};
use tacita_ste_comparison::{
    benchmark::{run, Config, Fixture},
    ste::*,
};

#[test]
fn threshold_proofs_dropout_padding_and_auxiliary_separation() {
    let mut rng = StdRng::seed_from_u64(17);
    let (ctx, members) = Context::setup(5, 3, 2, b"round-one", &mut rng).unwrap();
    assert_eq!(ctx.crs.n, 8);
    let a = ctx.encrypt(&[encode(-7), encode(8)], &mut rng).unwrap();
    let b = ctx.encrypt(&[encode(9), encode(12)], &mut rng).unwrap();
    let ct = ctx.aggregate(&[a.clone(), b]).unwrap();
    let shares: Vec<_> = [4, 1, 3]
        .iter()
        .map(|i| ctx.bound_share(&members[*i], &ct, &mut rng).unwrap())
        .collect();
    assert_eq!(
        ctx.decrypt_bound(&ct, &shares).unwrap(),
        vec![encode(2), encode(20)]
    );
    assert!(ctx.decrypt_bound(&ct, &shares[..2]).is_err());
    assert!(ctx
        .decrypt_bound(
            &ct,
            &[shares[0].clone(), shares[0].clone(), shares[1].clone()]
        )
        .is_err());
    let mut corrupt = shares.clone();
    corrupt[0].pd += ark_bls12_381::G1Projective::generator();
    assert!(ctx.decrypt_bound(&ct, &corrupt).is_err());
    assert!(ctx.decrypt_bound(&a, &shares).is_err());
    let more: Vec<_> = members
        .iter()
        .map(|m| ctx.bound_share(m, &ct, &mut rng).unwrap())
        .collect();
    assert_eq!(
        ctx.decrypt_bound(&ct, &more).unwrap(),
        vec![encode(2), encode(20)]
    );
    let tags: Vec<_> = [4, 1, 3]
        .iter()
        .map(|i| ctx.tag_share(&members[*i], &mut rng).unwrap())
        .collect();
    for seed in [encode(33), encode(74)] {
        let aux = ctx.encrypt_seed(seed, &mut rng);
        assert_eq!(ctx.decrypt_tag(&aux, &tags).unwrap()[0], seed);
        assert_eq!(read::<Ciphertext>(&wire(&aux)).unwrap(), aux);
    }
    assert_ne!(
        ctx.decrypt_tag(&ct, &tags).unwrap(),
        vec![encode(2), encode(20)]
    );
    let mut bad_tag = tags.clone();
    bad_tag[0].response += ark_bls12_381::Fr::from(1u64);
    assert!(ctx
        .decrypt_tag(&ctx.encrypt_seed(encode(33), &mut rng), &bad_tag)
        .is_err());
    assert!(ctx.aggregate(&[]).is_err());
    let mut bad_length = a.clone();
    bad_length.ct.pop();
    assert!(ctx.aggregate(&[bad_length]).is_err());
    let mut bytes = wire(&a);
    bytes.push(0);
    assert!(read::<Ciphertext>(&bytes).is_err());
}
#[test]
fn signed_dlog_checks_both_bounds() {
    let table = Dlog::new(-64, 96).unwrap();
    for n in [-64, -15, 0, 1, 65, 96] {
        assert_eq!(table.solve(encode(n)).unwrap(), n);
    }
    assert!(table.solve(encode(-65)).is_err());
    assert!(table.solve(encode(97)).is_err());
}
#[test]
fn masked_end_to_end_and_multi_block_key_reconstruction() {
    for masked in [true, false] {
        let cfg = Config {
            n_clients: 4,
            active_clients: 3,
            committee_size: 3,
            threshold: 2,
            slots: 2,
            threads: 2,
            input_bound: 16,
            mask_inputs: masked,
        };
        let report = run(
            cfg,
            Some(Fixture {
                values: vec![vec![-3, 5, 0], vec![7, -2, 16], vec![8, 1, -6]],
                seeds: None,
            }),
        )
        .unwrap();
        assert_eq!(report.decoded_sum, vec![12, 4, 10]);
        assert!(!report.mklhts_enabled);
        assert!(report.ste_share_proofs);
        assert_eq!(
            report.total_bytes,
            report.client_to_server_bytes
                + report.server_to_committee_bytes
                + report.committee_to_server_bytes
        );
    }
}
