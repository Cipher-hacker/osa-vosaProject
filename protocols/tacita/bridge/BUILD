load("@rules_rust//rust:defs.bzl", "rust_binary")
rust_binary(
    name = "kahe_stage",
    srcs = ["kahe_stage.rs"],
    deps = [
        "@crate_index//:sha3",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_parameters_generation",
        "//willow/crypto:single_thread_hkdf",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "@protobuf//rust:protobuf",
    ],
)
