load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "params",
    hdrs = ["params.h"],
    deps = [
        ":utils",
        "//upsi/crypto:bn_util",
    ],
)

cc_library(
    name = "roles",
    hdrs = ["roles.h"],
    deps = [
        ":params",
        ":crypto_tree",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_util",
        "//upsi/network:upsi_proto",
        "//upsi/network:connection",
        "//upsi/network:message_sink",
        "//upsi/util:status_includes",
    ],
)

cc_binary(
    name = "test",
    srcs = ["test.cc"],
    deps = [
        ":crypto_tree",
        "//upsi/network:upsi_proto",
        "//upsi/util:data_util",
        "//upsi/util:elgamal_proto_util",
        "//upsi/util:proto_util",
        "@com_google_absl//absl/base",
    ],
)

cc_library(
    name = "utils",
    srcs = ["utils.cc"],
    hdrs = ["utils.h"],
    deps = [
        "//upsi/network:upsi_proto",
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
        "//upsi/crypto:ec_commutative_cipher",
        "//upsi/crypto:paillier",
        "//upsi/network:upsi_proto",
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
        "//upsi/crypto:ec_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/util:elgamal_proto_util",
    ],
)
