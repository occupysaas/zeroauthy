#!/bin/bash -eu
# ClusterFuzzLite build script. The base image's `compile` runs it after
# .clusterfuzzlite/Dockerfile copied the repository to $SRC/zeroauthy, and
# fuzzes the targets it leaves in $OUT.
#
# compile_native_go_fuzzer turns a native Go fuzz test into a libFuzzer
# target: it copies the file that defines the fuzz test to a non-test file,
# points that file's "testing" import at go-118-fuzz-build's shim, and builds
# it together with the package's non-test files. The shim ignores f.Add, so
# fuzzing starts without the seeds the tests add. Targets are named
# <package>_<fuzz test>.

cd "$SRC/zeroauthy"

# The rewritten fuzz test imports the shim, so the module must require it.
# Use the version the image's go-118-fuzz-build binary was built from, so the
# shim matches the code that binary generates. This only edits the copy of
# go.mod and go.sum in the image.
shim_version=$(go version -m "$(command -v go-118-fuzz-build)" | awk '$1 == "mod" { print $3 }')
go get "github.com/AdamKorcz/go-118-fuzz-build/testing@${shim_version}"

# fuzz_target PACKAGE_DIR FUZZ_TEST
fuzz_target() {
  local name
  name="$(basename "$1")_$2"
  compile_native_go_fuzzer "github.com/zeroauthy/zeroauthy/$1" "$2" "$name"
  # compile_native_go_fuzzer exits 0 without building anything when it can't
  # find the fuzz test. Fail instead of dropping the target unnoticed.
  if [[ ! -f "$OUT/$name" ]]; then
    echo "build.sh: fuzz target $name was not built" >&2
    exit 1
  fi
}

fuzz_target internal/email FuzzRender
fuzz_target internal/hostedlogin FuzzValidateSource
fuzz_target internal/hostedlogin FuzzValidateCSS
fuzz_target internal/logsearch FuzzLogQuery
fuzz_target internal/orgsearch FuzzOrganizationQuery
fuzz_target internal/usersearch FuzzParse
fuzz_target internal/webauthn FuzzDecodeCBOR
fuzz_target internal/webauthn FuzzParseCredentialJSON
fuzz_target internal/webauthn FuzzParseAuthData

# Left out because compile_native_go_fuzzer can't build them: it compiles only
# the file that defines the fuzz test, as part of the package under test.
# - internal/logscrub FuzzScrubContext and FuzzScrub: fuzz_test.go belongs to
#   the external test package logscrub_test ("found packages logscrub and
#   logscrub_test"). Looking for FuzzScrub, the script also matches
#   FuzzScrubContext and builds nothing.
# - internal/webauthn FuzzParseCOSEKey: cose_test.go uses the cmap and enc
#   helpers defined in cbor_test.go ("undefined: cmap").
