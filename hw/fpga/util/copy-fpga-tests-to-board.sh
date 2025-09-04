#!/bin/bash
# Licensed under the Apache-2.0 license

rsync -avzP \
  target/all-fw.zip \
  target/aarch64-unknown-linux-gnu/debug/xtask \
  caliptra-test-bins.tar.zst \
  "hw/fpga/util/run-fpga-tests.sh" \
  mcu-host:"$USER"
