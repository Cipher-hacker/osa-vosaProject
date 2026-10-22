use opalwr::{paper_benchmark_params, packed_share_count_for_committee};

#[test]
fn paper_params_match_documented_lwr_choice() {
    let params = paper_benchmark_params(10_000);
    assert_eq!(params.seed_dim, 2048);
    assert_eq!(params.committee_size, 50);
    assert_eq!(params.threshold_r, 34);
    assert_eq!(packed_share_count_for_committee(&params), 128);
    assert_eq!(params.p, 1_u128 << 53);
    assert_eq!(params.max_safe_aggregate_coordinate(1_000).unwrap(), 7);
    assert!(params.q > params.p);
    assert_eq!(128, 128 - params.q.leading_zeros() as u32);
}
