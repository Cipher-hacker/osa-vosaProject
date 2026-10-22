# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load(
    "@rules_rust//rust:defs.bzl",
    "rust_binary",
    "rust_library",
)

package(default_applicable_licenses = [
])

rust_library(
    name = "shell_benchmarks",
    testonly = 1,
    srcs = ["shell_benchmarks.rs"],
    deps = [
        "@crate_index//:clap",
        "//willow/api:aggregation_config",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:client_traits",
        "//willow/protocol:decryptor_traits",
        "//willow/protocol:messages",
        "//willow/protocol:server_traits",
        "//willow/protocol:verifier_traits",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_server",
        "//willow/protocol:willow_v1_verifier",
        "//willow/testing_utils",
    ],
)

rust_binary(
    name = "run_shell_benchmark",
    testonly = 1,
    srcs = ["run_shell_benchmark.rs"],
    deps = [
        ":shell_benchmarks",
        "@crate_index//:clap",
    ],
)

rust_binary(
    name = "run_secure_agg_compare",
    testonly = 1,
    srcs = ["run_secure_agg_compare.rs"],
    deps = [
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:client_traits",
        "//willow/protocol:decryptor_traits",
        "//willow/protocol:messages",
        "//willow/protocol:server_traits",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_server",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/testing_utils",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_willow_full_unified",
    testonly = 1,
    srcs = ["run_willow_full_unified.rs"],
    deps = [
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/protocol:client_traits",
        "//willow/protocol:decryptor_traits",
        "//willow/protocol:messages",
        "//willow/protocol:server_traits",
        "//willow/protocol:verifier_traits",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_server",
        "//willow/protocol:willow_v1_verifier",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/testing_utils",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_willow_paper_full_unified",
    testonly = 1,
    srcs = ["run_willow_paper_full_unified.rs"],
    deps = [
        "@crate_index//:curve25519-dalek",
        "@crate_index//:rand",
        "//ffi_utils:status",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:single_thread_hkdf",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:decryptor_traits",
        "//willow/protocol:messages",
        "//willow/protocol:server_traits",
        "//willow/protocol:verifier_traits",
        "//willow/protocol:willow_full_aux",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_server",
        "//willow/protocol:willow_v1_verifier",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/testing_utils",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_osa_full_unified",
    testonly = 1,
    srcs = ["run_osa_full_unified.rs"],
    deps = [
        "@crate_index//:curve25519-dalek",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/protocol:osa_shell_kahe",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_osa_compact_seeded_unified",
    testonly = 1,
    srcs = ["run_osa_full_unified.rs"],
    rustc_env = {"OSA_BENCH_DEFAULT_PROFILE": "compact_seeded"},
    deps = [
        "@crate_index//:curve25519-dalek",
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/protocol:osa_shell_kahe",
        "//willow/proto/shell:shell_ciphertexts_rust_proto",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_plain_fedavg_compare",
    testonly = 1,
    srcs = ["run_plain_fedavg_compare.rs"],
    deps = [
        "//willow/testing_utils",
    ],
)

rust_binary(
    name = "real_fl_bridge",
    testonly = 1,
    srcs = ["real_fl_bridge.rs"],
    deps = [
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:ahe_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:shell_vahe",
        "//willow/crypto:vahe_traits",
        "//willow/protocol:client_traits",
        "//willow/protocol:decryptor_traits",
        "//willow/protocol:messages",
        "//willow/protocol:server_traits",
        "//willow/protocol:verifier_traits",
        "//willow/protocol:willow_v1_client",
        "//willow/protocol:willow_v1_decryptor",
        "//willow/protocol:willow_v1_server",
        "//willow/protocol:willow_v1_verifier",
        "//willow/proto/willow:messages_rust_proto",
        "//willow/testing_utils",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_osa_shell_kahe_compare",
    testonly = 1,
    srcs = ["run_osa_shell_kahe_compare.rs"],
    deps = [
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/protocol:osa_shell_kahe",
        "//willow/testing_utils",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "osa_vosa_shell_kahe_real_fl_bridge",
    testonly = 1,
    srcs = ["osa_vosa_shell_kahe_real_fl_bridge.rs"],
    deps = [
        "//willow/api:aggregation_config",
        "//willow/api:proto_serialization_traits",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/protocol:osa_shell_kahe",
        "@crate_index//:sha3",
        "@protobuf//rust:protobuf",
    ],
)

rust_binary(
    name = "run_vosa_verification_only",
    testonly = 1,
    srcs = ["run_vosa_verification_only.rs"],
    deps = [
        "//willow/api:aggregation_config",
        "//willow/crypto:kahe_traits",
        "//willow/crypto:prng_traits",
        "//willow/crypto:shell_kahe",
        "//willow/crypto:shell_parameters",
        "//willow/crypto:single_thread_hkdf",
        "//willow/protocol:osa_shell_kahe",
        "//willow/protocol:vosa_verification",
    ],
)
