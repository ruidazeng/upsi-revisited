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
    deps = [
        "//upsi/crypto:elgamal_proto"
    ],
)

grpc_proto_library(
    name = "private_intersection_proto",
    srcs = ["private_intersection.proto"],
    deps = [
        ":match_proto",
    ],
)

grpc_proto_library(
    name = "upsi_proto",
    srcs = ["upsi.proto"],
    deps = [
        ":private_intersection_proto",
    ],
)

cc_library(
    name = "message_sink",
    hdrs = ["message_sink.h"],
    deps = [
        ":upsi_proto",
        "//upsi/util:status_includes",
        "@com_google_absl//absl/memory",
    ],
)

cc_library(
    name = "connection",
    hdrs = ["connection.h"],
    deps = [
        ":upsi_proto",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "party",
    hdrs = ["party.h"],
    deps = [
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_key_util",
    ],
)


cc_library(
    name = "party_zero",
    srcs = ["party_zero.cc"],
    hdrs = ["party_zero.h"],
    deps = [
        ":connection",
        ":crypto_tree",
        ":data_util",
        ":match_proto",
        ":message_sink",
        ":party",
        ":private_intersection_proto",
        ":upsi_proto",
        ":utils",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_commutative_cipher",
        "//upsi/crypto:ec_point_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:status_includes",
    ],
)

cc_library(
    name = "party_one",
    srcs = ["party_one.cc"],
    hdrs = ["party_one.h"],
    deps = [
        ":crypto_tree",
        ":data_util",
        ":match_proto",
        ":message_sink",
        ":party",
        ":private_intersection_proto",
        ":upsi_proto",
        ":utils",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_commutative_cipher",
        "//upsi/crypto:ec_point_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:status_includes",
    ],
)

cc_library(
    name = "data_util",
    srcs = ["data_util.cc"],
    hdrs = ["data_util.h"],
    deps = [
        ":match_proto",
    	":utils",
        "//upsi/crypto:bn_util",
        "//upsi/util:status_includes",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "upsi_rpc_impl",
    srcs = ["upsi_rpc_impl.cc"],
    hdrs = ["upsi_rpc_impl.h"],
    deps = [
        ":message_sink",
        ":upsi_proto",
        ":party_one",
        "//upsi/util:status_includes",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_binary(
    name = "run",
    srcs = ["run.cc"],
    deps = [
        ":connection",
        ":data_util",
        ":party_one",
        ":party_zero",
        ":upsi_proto",
        ":upsi_rpc_impl",
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
        ":upsi_proto",
        ":upsi_rpc_impl",
        ":party_one",
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
        "//upsi/crypto:ec_commutative_cipher",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_proto_util",
    ],
)

cc_library(
    name = "crypto_node",
    srcs = ["crypto_node.cc"],
    hdrs = ["crypto_node.h"],
    deps = [
        ":utils",
        ":match_proto",
        "//upsi/crypto:ec_commutative_cipher",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_proto_util",
    ],
)

cc_library(
    name = "crypto_tree",
    srcs = ["crypto_tree.cc"],
    hdrs = ["crypto_tree.h"],
    deps = [
        ":crypto_node",
        ":utils",
        "//upsi/crypto:ec_commutative_cipher",
        "//upsi/crypto:paillier",
    ],
)

cc_binary(
    name = "setup",
    srcs = ["setup.cc"],
    deps = [
        ":data_util",
        ":utils",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:proto_util",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)
