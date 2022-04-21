#!/bin/bash

mkdir -p $WORKDIR

echo "TEST123" > /tmp/input.txt
kafl_debug.py --action gdb-syx --kernel $KERNEL --initrd $INITRD -p 1 --sharedir $SHAREDIR --work-dir $WORKDIR --purge -ip0 0x402000-0x497000 --input /tmp/input.txt