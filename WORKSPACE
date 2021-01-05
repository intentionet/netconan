workspace(name = "netconan")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_jar")

git_repository(
    name = "batfish",
    branch = "master",
    remote = "https://github.com/batfish/batfish",
)

http_jar(
    name = "antlr4_tool",
    sha256 = "6852386d7975eff29171dae002cc223251510d35f291ae277948f381a7b380b4",
    url = "https://search.maven.org/remotecontent?filepath=org/antlr/antlr4/4.7.2/antlr4-4.7.2-complete.jar",
)

http_archive(
    name = "rules_python",
    sha256 = "95ee649313caeb410b438b230f632222fb5d2053e801fe4ae0572eb1d71e95b8",
    strip_prefix = "rules_python-c8c79aae9aa1b61d199ad03d5fe06338febd0774",
    # equivalent SHA to that of 0.1.0 release, except the archive has experimental stuff like wheel.bzl
    url = "https://github.com/bazelbuild/rules_python/archive/c8c79aae9aa1b61d199ad03d5fe06338febd0774.tar.gz",
)
