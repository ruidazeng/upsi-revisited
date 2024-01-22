load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "party",
    hdrs = ["party.h"],
    deps = [
        "//upsi:params",
        "//upsi:roles",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_point_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:status_includes",
    ],
)

cc_library(
    name = "party_zero",
    srcs = ["party_zero.cc"],
    hdrs = ["party_zero.h"],
    deps = [
        ":party",
        "//upsi:crypto_tree",
        "//upsi/util:data_util",
        "//upsi:params",
        "//upsi:roles",
        "//upsi:utils",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_point_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/network:connection",
        "//upsi/network:message_sink",
        "//upsi/network:upsi_proto",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:status_includes",
    ],
)

cc_library(
    name = "party_one",
    srcs = ["party_one.cc"],
    hdrs = ["party_one.h"],
    deps = [
        ":party",
        "//upsi:crypto_tree",
        "//upsi:params",
        "//upsi:roles",
        "//upsi:utils",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_point_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/network:message_sink",
        "//upsi/network:upsi_proto",
        "//upsi/util:data_util",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:status_includes",
    ],
)

cc_binary(
    name = "run",
    srcs = ["run.cc"],
    deps = [
        ":party_one",
        ":party_zero",
        "//upsi/network:connection",
        "//upsi/network:service",
        "//upsi/network:upsi_proto",
        "//upsi/util:data_util",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "setup",
    srcs = ["setup.cc"],
    deps = [
        "//upsi:crypto_tree",
        "//upsi:utils",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/network:upsi_proto",
        "//upsi/util:data_util",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:proto_util",
        "//upsi/util:setup_util",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)
