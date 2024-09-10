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
