include config.mk

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

SRC_FILES=$(wildcard src/*.c)
OBJ_FILES=$(addprefix build/obj/,$(notdir $(patsubst %.c,%.o,$(SRC_FILES))))

HELPERS_ROOT=helpers

CC=gcc

.PHONY: clean deepclean fuzz debug

all: build/bin/target

fuzz: build/initrd.cpio.gz build/bin/target
	@echo "[*] Start Fuzzing"
	@mkdir -p $(WORKDIR_PATH)
	
	NB_SYX_WORKERS=$(NB_SYX_WORKERS) TARGET=build/bin/target KERNEL=$(KERNEL_IMG) INITRD=build/initrd.cpio.gz WORKDIR=$(WORKDIR_PATH) NB_WORKERS=$(NB_WORKERS) ./fuzz.sh

debug: build/initrd.cpio.gz build/bin/target
	@echo "[*] Start Debug"
	KERNEL=$(KERNEL_IMG) INITRD=build/initrd.cpio.gz SHAREDIR=$(SHAREDIR_PATH) WORKDIR=$(WORKDIR_PATH) ./debug.sh

cov: build/initrd.cpio.gz build/bin/target
	@echo "[*] Start Coverage Analysis"
	INPUT_WORKDIR=$(WORKDIR_PATH) TARGET=build/bin/target KERNEL=$(KERNEL_IMG) INITRD=build/initrd.cpio.gz SHAREDIR=$(SHAREDIR_PATH) WORKDIR=$(COV_WORKDIR_PATH) ./cov.sh

build/initrd.cpio.gz: loader.sh build/bin/target | $(INITRD_PATH)
	@echo "[*] Build initrd archive"
	@cp loader.sh $(INITRD_PATH)
	@./scripts/bless_initrd.sh $(INITRD_PATH)
	@cp build/bin/target $(INITRD_PATH)
	@cd $(INITRD_PATH); ./build.sh
	@mv initrd.cpio.gz build

build/bin/target: $(OBJ_FILES)
	@echo "[*] Build Target"
	@mkdir -p build/bin
	@$(CC) -static -DTARGET_LEVEL=$(TARGET_LEVEL) $(OBJ_FILES) -o $@

build/obj/%.o: src/%.c ../nyx_api.h src/syx-api.h config.mk
	@mkdir -p build/obj
	@$(CC) -O3 -DTARGET_LEVEL=$(TARGET_LEVEL) -c $< -o $@

$(INITRD_PATH):
	@echo "[*] Generate initrd"
	@TEMPLATE=$(ROOT_DIR)/templates/initrd_template ./scripts/gen_initrd.sh $(ROOT_DIR)/$(INITRD_PATH)

clean:
	@echo "[*] Clean"
	@rm -rf build $(INITRD_PATH)

deepclean: clean
	@rm -rf workdir_output
