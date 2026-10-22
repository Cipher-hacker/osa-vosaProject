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

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_AHE_ALIASES_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_AHE_ALIASES_H_

#include "shell_encryption/multi_party/public_parameter.h"
#include "shell_encryption/rns/coefficient_encoder.h"
#include "shell_encryption/rns/rns_error_params.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/shell_aliases.h"

namespace secure_aggregation {
using ConstModularIntPublicParameter =
    const rlwe::multi_party::PublicParameter<secure_aggregation::ModularInt>;

using ConstModularIntCoefficientEncoder =
    const rlwe::CoefficientEncoder<secure_aggregation::ModularInt>;

using ConstModularIntRnsErrorParams =
    const rlwe::RnsErrorParams<secure_aggregation::ModularInt>;
using IntegerDiscreteGaussianSampler =
    rlwe::DiscreteGaussianSampler<secure_aggregation::Integer>;

using ConstRnsContext = const RnsContext;
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_AHE_ALIASES_H_
