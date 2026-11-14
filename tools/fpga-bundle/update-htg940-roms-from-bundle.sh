#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$script_dir/test-htg940-fpga-bundle.sh" "$@" --prepare-only
