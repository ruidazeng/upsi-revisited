# Copyright 2019 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "crypto_node",
    srcs = ["crypto_node.cc"],
    hdrs = ["crypto_node.h"],
    deps = [
        "//private_join_and_compute/crypto:ec_commutative_cipher",
        "//private_join_and_compute/crypto:paillier",
    ],
)

cc_library(
    name = "crypto_tree",
    srcs = ["crypto_tree.cc"],
    hdrs = ["crypto_tree.h"],
    deps = [
        ":crypto_node",
        "//private_join_and_compute/crypto:ec_commutative_cipher",
        "//private_join_and_compute/crypto:paillier",
    ],
)