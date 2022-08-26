# Build & Fuzzing Configuration

# Build Configuration
KERNEL_IMG?=/boot/vmlinuz-5.10.73-kafl+
INITRD_PATH?=initrd.fs
NB_WORKERS?=6
NB_SYX_WORKERS?=1
TARGET_LEVEL?=3

# Fuzzing Configuration
#WORKDIR_PATH?=wdir_t$(TARGET_LEVEL)_$(NB_WORKERS)wk_$(NB_SYX_WORKERS)syx
WORKDIR_PATH?=workdir
COV_WORKDIR_PATH?=wdir_cov_t$(TARGET_LEVEL)_$(NB_WORKERS)wk_$(NB_SYX_WORKERS)syx
