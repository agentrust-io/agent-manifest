#!/bin/bash -eu
# Build the fuzz targets for ClusterFuzzLite.
#
# The SDK is installed rather than added to the path so the targets exercise the
# same import surface a consumer gets, including the optional extras the
# attestation parsers need.

cd "$SRC/agent-manifest/python"
pip3 install --no-cache-dir .

for target in "$SRC"/agent-manifest/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$target"
done
