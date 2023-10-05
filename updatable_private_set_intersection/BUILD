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

grpc_proto_library(
    name = "match_proto",
    srcs = ["match.proto"],
)

grpc_proto_library(
    name = "private_intersection_sum_proto",
    srcs = ["private_intersection_sum.proto"],
    deps = [
        ":match_proto",
    ],
)

grpc_proto_library(
    name = "updatable_private_set_intersection_proto",
    srcs = ["updatable_private_set_intersection.proto"],
    deps = [
        ":private_intersection_sum_proto",
    ],
)

cc_library(
    name = "message_sink",
    hdrs = ["message_sink.h"],
    deps = [
        ":updatable_private_set_intersection_proto",
        "//updatable_private_set_intersection/util:status_includes",
        "@com_google_absl//absl/memory",
    ],
)

cc_library(
    name = "protocol_client",
    hdrs = ["protocol_client.h"],
    deps = [
        ":message_sink",
        ":updatable_private_set_intersection_proto",
        "//updatable_private_set_intersection/util:status_includes",
    ],
)

cc_library(
    name = "party_zero_impl",
    srcs = ["party_zero_impl.cc"],
    hdrs = ["party_zero_impl.h"],
    deps = [
        ":crypto_tree",
        ":utils",
        ":match_proto",
        ":message_sink",
        ":private_intersection_sum_proto",
        ":updatable_private_set_intersection_proto",
        ":protocol_client",
        "//updatable_private_set_intersection/crypto:bn_util",
        "//updatable_private_set_intersection/crypto:ec_commutative_cipher",
        "//updatable_private_set_intersection/crypto:paillier",
        "//updatable_private_set_intersection/util:status_includes",
    ],
)

cc_library(
    name = "protocol_server",
    hdrs = ["protocol_server.h"],
    deps = [
        ":message_sink",
        ":updatable_private_set_intersection_proto",
        "//updatable_private_set_intersection/util:status_includes",
    ],
)

cc_library(
    name = "party_one_impl",
    srcs = ["party_one_impl.cc"],
    hdrs = ["party_one_impl.h"],
    deps = [
        ":crypto_tree",
        ":utils",
        ":match_proto",
        ":message_sink",
        ":private_intersection_sum_proto",
        ":updatable_private_set_intersection_proto",
        ":protocol_server",
        "//updatable_private_set_intersection/crypto:bn_util",
        "//updatable_private_set_intersection/crypto:ec_commutative_cipher",
        "//updatable_private_set_intersection/crypto:paillier",
        "//updatable_private_set_intersection/util:status_includes",
    ],
)

cc_library(
    name = "data_util",
    srcs = ["data_util.cc"],
    hdrs = ["data_util.h"],
    deps = [
        ":match_proto",
        "//updatable_private_set_intersection/crypto:bn_util",
        "//updatable_private_set_intersection/util:status_includes",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "updatable_private_set_intersection_rpc_impl",
    srcs = ["updatable_private_set_intersection_rpc_impl.cc"],
    hdrs = ["updatable_private_set_intersection_rpc_impl.h"],
    deps = [
        ":message_sink",
        ":updatable_private_set_intersection_proto",
        ":protocol_server",
        "//updatable_private_set_intersection/util:status_includes",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_binary(
    name = "party_one",
    srcs = ["party_one.cc"],
    deps = [
        ":data_util",
        ":updatable_private_set_intersection_proto",
        ":updatable_private_set_intersection_rpc_impl",
        ":protocol_server",
        ":party_one_impl",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_binary(
    name = "party_zero",
    srcs = ["party_zero.cc"],
    deps = [
        ":party_zero_impl",
        ":data_util",
        ":updatable_private_set_intersection_proto",
        ":protocol_client",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "test",
    srcs = ["test.cc"],
    deps = [
        ":data_util",
        ":updatable_private_set_intersection_proto",
        ":updatable_private_set_intersection_rpc_impl",
        ":protocol_server",
        ":party_one_impl",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "utils",
    srcs = ["utils.cc"],
    hdrs = ["utils.h"],
    deps = [
        "//updatable_private_set_intersection/crypto:ec_commutative_cipher",
        "//updatable_private_set_intersection/crypto:paillier",
    ],
)

cc_library(
    name = "crypto_node",
    srcs = ["crypto_node.cc"],
    hdrs = ["crypto_node.h"],
    deps = [
        ":utils",
        "//updatable_private_set_intersection/crypto:ec_commutative_cipher",
        "//updatable_private_set_intersection/crypto:paillier",
    ],
)

cc_library(
    name = "crypto_tree",
    srcs = ["crypto_tree.cc"],
    hdrs = ["crypto_tree.h"],
    deps = [
        ":crypto_node",
        ":utils",
        "//updatable_private_set_intersection/crypto:ec_commutative_cipher",
        "//updatable_private_set_intersection/crypto:paillier",
    ],
)
