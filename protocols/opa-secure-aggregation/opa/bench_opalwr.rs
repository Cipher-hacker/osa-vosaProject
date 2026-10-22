extern crate opalwr as protocol;

mod bench_opalwr_common;

fn main() {
    bench_opalwr_common::run("generic_u256_reference");
}
