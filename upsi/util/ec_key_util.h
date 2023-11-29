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

#ifndef upsi_UTIL_EC_KEY_UTIL_H_
#define upsi_UTIL_EC_KEY_UTIL_H_

#include "upsi/crypto/big_num.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_key.pb.h"
#include "upsi/util/status.inc"

namespace upsi::ec_key_util {

// Generates an EC key and writes it to the provided files as
// EcKeyProto message.
Status GenerateEcKey(int curve_id, absl::string_view ec_key_filename);

// Converts the given EC key proto to a BigNum. It fails if the curve_id of key
// doesn't match the given curve id value.
StatusOr<BigNum> DeserializeEcKey(Context* context, int curve_id,
                                  EcKeyProto ec_key_proto);

}  // namespace upsi::ec_key_util

#endif  // upsi_UTIL_EC_KEY_UTIL_H_
