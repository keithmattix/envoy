load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_mock(
    name = "grpc_mocks",
    srcs = ["mocks.cc"],
    hdrs = ["mocks.h"],
    rbe_pool = "6gig",
    deps = [
        "//envoy/grpc:async_client_interface",
        "//envoy/grpc:async_client_manager_interface",
        "//envoy/stream_info:stream_info_interface",
        "//source/common/grpc:typed_async_client_lib",
        "//test/mocks/http:http_mocks",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
    ],
)
