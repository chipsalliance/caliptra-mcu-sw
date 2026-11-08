#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pins="$root/fpga/htg940/submodule_pins.json"
rtl="$root/caliptra-ss"

if [[ -e "$rtl" ]]; then
    echo "Error: $rtl already exists; check the prepared sources with prepare_sources.py --check." >&2
    exit 1
fi

ss_commit=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[0]["commit"])' "$pins")
git clone --filter=blob:none --no-checkout https://github.com/faydn23/caliptra-ss.git "$rtl"
git -C "$rtl" fetch --depth=1 origin "$ss_commit"
git -C "$rtl" checkout --detach "$ss_commit"
git -C "$rtl" submodule update --init --recursive --depth=1

while read -r path commit; do
    git -C "$root/$path" fetch --depth=1 origin "$commit"
done < <(python3 -c '
import json, sys
for pin in json.load(open(sys.argv[1])):
    print(pin["path"], pin["commit"])
' "$pins")

python3 "$root/fpga/htg940/prepare_sources.py" --apply
