#!/bin/sh

function get_lower_range() {
	grep -i "$1" /proc/kallsyms|head -1|cut -d \  -f 1
}

function get_upper_range() {
	grep -i "$1" /proc/kallsyms|tail -1|cut -d \  -f 1
}

# trace FS code?
#IP0_START=$(get_lower_range "t\ _ext4\|t\ mount\|t ioctl")
#IP0_END=$(get_upper_range "t\ _ext4\|t\ mount\|t ioctl")

# trace all kernel code
IP0_START=$(get_lower_range "t\ _stext")
IP0_END=$(get_upper_range "t\ _etext")
IP1_START=$(get_lower_range "t\ _sinittext")
IP1_END=$(get_upper_range "t\ _einittext")

# clean pipes
dmesg -c > /fuzz/boot.log
vmcall hpush /fuzz/boot.log
vmcall hpush /proc/kallsyms
vmcall hpush /proc/cpuinfo
vmcall hpush /proc/filesystems
vmcall hpush /proc/modules

/fuzz/fs_fuzzer ext4
#vmcall habort "return from agent.sh"
