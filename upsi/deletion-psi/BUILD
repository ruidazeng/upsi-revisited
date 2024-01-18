load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "party",
    hdrs = ["party.h"],
    copts = ["-maes", "-mssse3", "-fpermissive"],
    linkopts= ["-pthread", "-lssl", "-lcrypto"],
    linkstatic = 1,
    deps = [
        "//upsi/crypto:paillier",
        "//upsi/util:gc_util",
        "//upsi/util:proto_util",
        "@emp-tool//:emptool",
    ],
)


cc_library(
    name = "party_zero",
    srcs = ["party_zero.cc"],
    hdrs = ["party_zero.h"],
    copts = ["-maes", "-mssse3", "-fpermissive"],
    linkopts= ["-pthread", "-lssl", "-lcrypto"],
    linkstatic = 1,
    deps = [
        ":party",
        "//upsi:crypto_tree",
        "//upsi:roles",
        "//upsi:utils",
        "//upsi/crypto:bn_util",
        "//upsi/crypto:ec_point_util",
        "//upsi/crypto:elgamal",
        "//upsi/crypto:paillier",
        "//upsi/network:connection",
        "//upsi/network:message_sink",
        "//upsi/network:upsi_proto",
        "//upsi/util:data_util",
        "//upsi/util:elgamal_key_util",
        "//upsi/util:gc_util",
        "//upsi/util:status_includes",
        "@emp-tool//:emptool",
    ],
)

cc_library(
    name = "party_one",
    srcs = ["party_one.cc"],
    hdrs = ["party_one.h"],
    copts = ["-maes", "-mssse3", "-fpermissive"],
    linkopts= ["-pthread", "-lssl", "-lcrypto"],
    linkstatic = 1,
    deps = [
        ":party",
        "//upsi:crypto_tree",
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
        "//upsi/util:gc_util",
        "//upsi/util:status_includes",
        "@emp-tool//:emptool",
    ],
)

cc_binary(
    name = "run",
    srcs = ["run.cc"],
	copts = ["-maes", "-mssse3", "-fpermissive"],
	linkopts= ["-pthread", "-lssl", "-lcrypto"],
	linkstatic = 1,
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
		"@emp-tool//:emptool",
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
