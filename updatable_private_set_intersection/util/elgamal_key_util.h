/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef updatable_private_set_intersection_UTIL_ELGAMAL_KEY_UTIL_H_
#define updatable_private_set_intersection_UTIL_ELGAMAL_KEY_UTIL_H_

#include <memory>
#include <string>
#include <vector>

#include "updatable_private_set_intersection/crypto/elgamal.pb.h"
#include "updatable_private_set_intersection/util/status.inc"

namespace updatable_private_set_intersection::elgamal_key_util {

// Generates a pair of public, private ElGamal keys and writes them to the
// provided files as ::updatable_private_set_intersection::ElGamalPublicKey and
// ::updatable_private_set_intersection::ElGamalPrivateKey proto messages.
Status GenerateElGamalKeyPair(int curve_id, absl::string_view pub_key_filename,
                              absl::string_view prv_key_filename);

// Joins the shares of ElGamal public keys into a joint key.
// The shares and joint keys are encoded as
// ::updatable_private_set_intersection::ElGamalPublicKey proto messages.
Status ComputeJointElGamalPublicKey(
    int curve_id, const std::vector<std::string>& shares_filenames,
    absl::string_view join_pub_key_key_filename);

}  // namespace updatable_private_set_intersection::elgamal_key_util

#endif  // updatable_private_set_intersection_UTIL_ELGAMAL_KEY_UTIL_H_
