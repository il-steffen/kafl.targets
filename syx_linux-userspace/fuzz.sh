#!/bin/bash

# IP computation
ip_start_addr=0x$(readelf -S $TARGET  | grep ".text" | grep -o -E "[0-9a-f]{4,}" | sed -n '1p')
text_len=0x$(readelf -S build/bin/target  | grep -A 1 ".text" | sed -n "2p" | grep -o -E "[0-9a-f]{4,}" | sed -n "1p" | sed 's/^0//')
ip_end_addr=$(printf "0x%x" $(($ip_start_addr + $text_len)))

kafl_fuzz.py -w $WORKDIR --redqueen --grimoire --purge --kernel $KERNEL -p $NB_WORKERS --syx $NB_SYX_WORKERS --initrd $INITRD -ip0 $ip_start_addr-$ip_end_addr