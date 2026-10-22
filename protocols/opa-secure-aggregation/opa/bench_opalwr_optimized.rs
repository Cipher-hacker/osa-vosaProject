extern crate opalwr_optimized as protocol;

mod bench_opalwr_common;

fn main() {
    bench_opalwr_common::run("fixed_q_optimized");
}
