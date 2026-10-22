use opalwr::paper_fl_benchmark_params;

#[test]
fn fl_parameters_retain_the_paper_security_dimensions() {
    let params = paper_fl_benchmark_params(64);
    assert_eq!(params.p, 1_u128 << 85);
    assert_eq!(params.q, 340_282_366_920_938_463_463_374_607_431_768_211_297);
    assert_eq!(params.seed_dim, 2048);
    assert_eq!(params.packed_secret_dim, 16);
    assert_eq!(params.committee_size, 50);
    assert_eq!(params.threshold_r, 34);
    assert_eq!(params.stat_sec_bits, 40);
    assert!(params.max_safe_aggregate_coordinate(800).unwrap() > 9_600_000_000);
}
