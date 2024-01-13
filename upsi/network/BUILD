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
    name = "upsi_proto",
    srcs = ["upsi.proto"],
    deps = [
        "//upsi/crypto:elgamal_proto"
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
    name = "service",
    srcs = ["service.cc"],
    hdrs = ["service.h"],
    deps = [
        ":message_sink",
        ":upsi_proto",
        "//upsi:roles",
        "//upsi/util:status_includes",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/strings",
    ],
)
