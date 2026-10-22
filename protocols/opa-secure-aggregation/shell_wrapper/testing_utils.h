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

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_TESTING_UTILS_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_TESTING_UTILS_H_

#include <vector>

#include "absl/numeric/int128.h"
#include "absl/random/random.h"
#include "shell_encryption/int256.h"

namespace secure_aggregation {
namespace testing {

// Returns a vector of `num_messages` random u256 integers in [0, max_value).
inline std::vector<rlwe::uint256> SampleUint256Messages(
    int num_messages, rlwe::uint256 max_value) {
  absl::BitGen bitgen;
  std::vector<rlwe::uint256> messages;
  messages.reserve(num_messages);

  // Sample high/low order bits uniformly at random and independently.
  absl::uint128 max_value_high = Uint256High128(max_value);
  absl::uint128 max_value_low = Uint256Low128(max_value);

  for (int i = 0; i < num_messages; ++i) {
    auto high = absl::Uniform<absl::uint128>(bitgen, 0, max_value_high);
    auto low = absl::Uniform<absl::uint128>(bitgen, 0, max_value_low);
    messages.push_back(rlwe::uint256(high, low));
  }
  return messages;
}

}  // namespace testing
}  // namespace secure_aggregation

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_TESTING_UTILS_H_
