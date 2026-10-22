/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_SHELL_ALIASES_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_SHELL_ALIASES_H_

#include "shell_encryption/int256.h"
#include "shell_encryption/integral_types.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/rns/rns_context.h"
#include "shell_encryption/rns/rns_integer.h"
#include "shell_encryption/rns/rns_modulus.h"
#include "shell_encryption/rns/rns_polynomial.h"

// Common aliases we need for the cxx bindings.
namespace secure_aggregation {
using Integer = rlwe::Uint64;
using ModularInt = rlwe::MontgomeryInt<Integer>;
using RnsInt = rlwe::RnsInt<ModularInt>;
using RnsPolynomial = rlwe::RnsPolynomial<ModularInt>;
using Prng = rlwe::SingleThreadHkdfPrng;
using RnsContext = rlwe::RnsContext<ModularInt>;
using BigInteger = rlwe::uint256;
using PrimeModulus = rlwe::PrimeModulus<ModularInt>;
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_SHELL_ALIASES_H_
