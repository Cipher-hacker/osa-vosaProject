load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

package(
    default_applicable_licenses = [],
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "opalwr",
    srcs = ["opalwr.rs"],
    deps = [
        "@crate_index//:crypto-bigint",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:rand",
        "@crate_index//:sha3",
        "@crate_index//:thiserror",
    ],
)

rust_library(
    name = "opalwr_optimized",
    crate_name = "opalwr_optimized",
    srcs = ["opalwr.rs"],
    rustc_flags = ["--cfg=opa_fixed_q_optimized"],
    deps = [
        "@crate_index//:crypto-bigint",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:rand",
        "@crate_index//:sha3",
        "@crate_index//:thiserror",
    ],
)

rust_library(
    name = "opalwr_fixed_q",
    srcs = ["opalwr_optimized.rs"],
    deps = [
        "@crate_index//:crypto-bigint",
    ],
)

rust_test(
    name = "opalwr_test",
    crate = ":opalwr",
)

rust_test(
    name = "opalwr_optimized_protocol_test",
    crate = ":opalwr_optimized",
)

rust_binary(
    name = "bench_opalwr",
    srcs = [
        "bench_opalwr.rs",
        "bench_opalwr_common.rs",
    ],
    deps = [
        ":opalwr",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:rand",
    ],
)

rust_binary(
    name = "bench_opalwr_optimized",
    srcs = [
        "bench_opalwr_common.rs",
        "bench_opalwr_optimized.rs",
    ],
    deps = [
        ":opalwr_optimized",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:rand",
    ],
)

rust_binary(
    name = "real_fl_bridge_optimized",
    testonly = 1,
    srcs = ["real_fl_bridge_optimized.rs"],
    deps = [
        ":opalwr_optimized",
        "@crate_index//:curve25519-dalek",
        "@crate_index//:rand",
        "@crate_index//:sha3",
    ],
)

rust_test(
    name = "opalwr_paper_params_test",
    srcs = ["opalwr_paper_params_test.rs"],
    deps = [
        ":opalwr",
    ],
)

rust_test(
    name = "opalwr_fl_params_test",
    srcs = ["opalwr_fl_params_test.rs"],
    deps = [":opalwr"],
)

rust_test(
    name = "opalwr_optimized_test",
    srcs = ["opalwr_optimized_test.rs"],
    deps = [
        ":opalwr",
        ":opalwr_fixed_q",
        "@crate_index//:crypto-bigint",
    ],
)
