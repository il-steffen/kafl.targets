#!/bin/bash

KERNEL="vmlinuz-5.10.73-kafl+"
INITRD=build/initrd.cpio.gz
WORKDIR=workdir_output
SHAREDIR=sharedir

cp build/bin/target sharedir
mkdir -p $WORKDIR

kafl_cov.py --kernel $KERNEL --initrd $INITRD -p 1 --sharedir $SHAREDIR --work-dir $WORKDIR --purge -ip0 0x402000-0x497000