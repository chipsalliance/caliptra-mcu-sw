#!/bin/bash
# Licensed under the Apache-2.0 license

# Cross compile the tests for the FPGA environment.
docker run --rm -t \
  -v "${HOME}/.cargo/registry:/root/.cargo/registry" \
  -v "${HOME}/.cargo/git:/root/.cargo/git"  \
  -v "${PWD}":/work-dir \
  -w "/work-dir" \
  caliptra-fpga:latest \
  /bin/bash \
  -c "./hw/fpga/util/cross-compiling/build-fpga-tests.sh"

# Copy the tests to the FPGA board.
./hw/fpga/util/copy-fpga-tests-to-board.sh
