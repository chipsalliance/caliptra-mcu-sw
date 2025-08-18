#!/bin/bash
# Licensed under the Apache-2.0 license

if [[ -z $1 ]]; then
    echo "launch_openocd.sh [core/mcu/lcc]"
    exit
fi

echo $1
sudo openocd --file $(dirname $0)/openocd_ss.txt -c "connect $1"
