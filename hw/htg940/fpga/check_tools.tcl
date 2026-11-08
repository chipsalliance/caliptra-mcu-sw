# Licensed under the Apache-2.0 license

set part xcvu13p-fhgb2104-3-e
if {[llength [get_parts -quiet $part]] != 1} {
    error "HTG-940 requires Vivado device support for $part"
}
puts "HTG940_VIVADO_READY: [version -short], $part"
exit
