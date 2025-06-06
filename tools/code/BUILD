load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load("@envoy_repo//:path.bzl", "PATH")
load("@rules_python//python/entry_points:py_console_script_binary.bzl", "py_console_script_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load(
    "//test/extensions/filters/network/common/fuzz:config.bzl",
    "READFILTER_FUZZ_FILTERS",
    "READFILTER_NOFUZZ_FILTERS",
)
load("//tools/python:namespace.bzl", "envoy_py_namespace")

licenses(["notice"])  # Apache 2

envoy_py_namespace()

FUZZ_FILTER_COUNT = (
    len(READFILTER_FUZZ_FILTERS) +
    len(READFILTER_NOFUZZ_FILTERS)
)

jq(
    name = "extensions_build_config",
    srcs = [
        "//contrib:contrib_extensions_build_config",
        "//source/extensions:extensions_build_config",
    ],
    out = "extensions_build_config.json",
    args = ["--slurp"],
    filter = ".[0] * .[1]",
)

py_console_script_binary(
    name = "check",
    args = [
        "--codeowners=$(location //:CODEOWNERS)",
        "--owners=$(location //:OWNERS.md)",
        "--extensions_build_config=$(location :extensions_build_config)",
        "--extensions_fuzzed_count=%s" % FUZZ_FILTER_COUNT,
        "--path=%s" % PATH,
        "-b shellcheck:$(location @com_github_aignas_rules_shellcheck//:shellcheck)",
        "-b gofmt:$(location @go_sdk//:bin/gofmt)",
        "-x bazel/repo.bzl",
    ],
    data = [
        ":extensions_build_config",
        "//:CODEOWNERS",
        "//:OWNERS.md",
        "@com_github_aignas_rules_shellcheck//:shellcheck",
        "@go_sdk//:bin/gofmt",
    ],
    pkg = "@base_pip3//envoy_code_check",
    script = "envoy.code.check",
)

genrule(
    name = "checked",
    outs = ["checked.txt"],
    cmd = """
    $(location :check) \
        --fix \
        -l warn \
        -v warn \
        -x mobile/dist/envoy-pom.xml \
        -x bazel/repo.bzl \
        --codeowners=$(location //:CODEOWNERS) \
        --owners=$(location //:OWNERS.md) \
        --extensions_build_config=$(location :extensions_build_config) \
        --extensions_fuzzed_count=%s \
        --path=%s \
        -b shellcheck:$(location @com_github_aignas_rules_shellcheck//:shellcheck) \
        -b gofmt:$(location @go_sdk//:bin/gofmt) \
      > $@ 2>&1 || :
    """ % (
        FUZZ_FILTER_COUNT,
        PATH,
    ),
    tags = ["no-remote-exec"],
    tools = [
        ":check",
        ":extensions_build_config",
        "//:CODEOWNERS",
        "//:OWNERS.md",
        "//bazel:volatile-scm-hash",
        "@com_github_aignas_rules_shellcheck//:shellcheck",
        "@go_sdk//:bin/gofmt",
    ],
)

sh_test(
    name = "check_test",
    srcs = [":check_test.sh"],
    args = ["$(location :checked)"],
    data = [":checked"],
    tags = ["no-remote-exec"],
)
