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

#ifndef updatable_private_set_intersection_DATA_UTIL_H_
#define updatable_private_set_intersection_DATA_UTIL_H_

// Contains utility functions to generate dummy input data for the server and
// client, and also to write the data to file and parse it back.

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/match.pb.h"
#include "updatable_private_set_intersection/util/status.inc"
#include "updatable_private_set_intersection/utils.h"

namespace updatable_private_set_intersection {

// Random Identifiers generated by this library will be this many bytes long.
static const int64_t kRandomIdentifierLengthBytes = 32;

// Generates random datasets for the server and client. The server data contains
// the server_data_size identifiers, while the client data contains
// client_data_size identifiers, each paired with randomly selected associated
// values between 0 and the max_associated_value. The two generated datasets
// will have intersection_size identifiers in common. The function also returns
// the value of the real intersection sum. Each identifier consists of random
// alphanumeric strings.
//
// The output is a tuple with the following interpretation:
// First element: server's data.
// Second element: client's data (identifiers and associated values).
// Third element: the sum of values associated with common identifiers ( the
// "true" intersection-sum)
//
// Client and server identifiers are kRandomIdentifierLengthBytes-long random
// strings.
//
// The identifiers are generated and permuted with a
// non-cryptographically-secure PRNG. This is fine for dummy data.
//
// Fails with INVALID_ARGUMENT if the intersection size given is larger than
// either server or client data size, if max_associated_value is negative, or if
// max_associated_value * intersection_size is larger than the max value of
// int64_t.


auto GenerateRandomDatabases(int64_t server_data_size, int64_t client_data_size,
                             int64_t intersection_size,
                             int64_t max_associated_value)
    -> StatusOr<std::tuple<
        std::vector<std::string>,
        std::pair<std::vector<std::string>, std::vector<int64_t>>, int64_t>>;

// Write Server Dataset to the specified file in CSV format.
Status WriteServerDatasetToFile(const std::vector<std::string>& server_data,
                                absl::string_view server_data_filename);

// Write Client Dataset to the specified file in CSV format.
Status WriteClientDatasetToFile(
    const std::vector<std::string>& client_identifiers,
    const std::vector<int64_t>& client_associated_values,
    absl::string_view client_data_filename);

// Read Server Dataset from the specified file, which should be in CSV format.
StatusOr<std::vector<std::string>> ReadServerDatasetFromFile(
    absl::string_view server_data_filename);

// Read Client Dataset (identifiers and associated values) from the specified
// file, which should be in CSV format. Automatically packages the parsed
// associated values as BigNums for convenience.
StatusOr<std::pair<std::vector<std::string>, std::vector<BigNum>>>
ReadClientDatasetFromFile(absl::string_view client_data_filename,
                          Context* context);

// Splits a CSV line using ',' as a delimiter, and returns a vector of
// associated strings.
std::vector<std::string> SplitCsvLine(const std::string& line);

}  // namespace updatable_private_set_intersection
#endif  // updatable_private_set_intersection_DATA_UTIL_H_
