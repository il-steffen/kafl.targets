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
	
	NB_SYX_WORKERS=$(NB_SYX_WORKERS) TARGET=build/bin/target KERNEL=$(KERNEL_IMG) INITRD=build/initrd.cpio.gz SHAREDIR=$(SHAREDIR_PATH) WORKDIR=$(WORKDIR_PATH) NB_WORKERS=$(NB_WORKERS) ./fuzz.sh

debug: build/initrd.cpio.gz build/bin/target
	@echo "[*] Start Debug"
	KERNEL=$(KERNEL_IMG) INITRD=build/initrd.cpio.gz SHAREDIR=$(SHAREDIR_PATH) WORKDIR=$(WORKDIR_PATH) ./debug.sh

cov: build/initrd.cpio.gz build/bin/target
	@echo "[*] Start Coverage Analysis"
	./cov.sh

build/initrd.cpio.gz: loader.sh build/bin/target  $(HELPERS_ROOT)/Makefile | $(INITRD_PATH)
	@echo "[*] Build initrd archive"
	@make -C $(HELPERS_ROOT)
	@SHAREDIR=$(ROOT_DIR)/templates/sharedir_template HTOOLS_ROOT=$(ROOT_DIR)/helpers ./scripts/bless_initrd.sh $(INITRD_PATH)
	@cp loader.sh $(INITRD_PATH)
	@cp build/bin/target $(INITRD_PATH)
	@cp build/bin/target $(SHAREDIR_PATH)
	@cd $(INITRD_PATH); ./build.sh
	@mv initrd.cpio.gz build

$(HELPERS_ROOT)/Makefile:
	@echo "[*] Getting helpers project"
	@git submodule update --recursive
	@git submodule update --init

build/bin/target: $(OBJ_FILES)
	@echo "[*] Build Target"
	@mkdir -p build/bin
	@$(CC) -static $(OBJ_FILES) -o $@

build/obj/%.o: src/%.c ../nyx_api.h src/syx-api.h
	@mkdir -p build/obj
	@$(CC) -O3 -c $< -o $@

$(INITRD_PATH): | $(SHAREDIR_PATH)
	@echo "[*] Generate initrd"
	@TEMPLATE=$(ROOT_DIR)/templates/initrd_template ./scripts/gen_initrd.sh $(ROOT_DIR)/$(INITRD_PATH)

$(SHAREDIR_PATH): $(HELPERS_ROOT)/Makefile
	@echo "[*] Generate Sharedir"
	@make -C $(HELPERS_ROOT)
	@SHAREDIR=$(ROOT_DIR)/templates/sharedir_template HTOOLS_ROOT=$(ROOT_DIR)/helpers ./scripts/gen_sharedir.sh $(SHAREDIR_PATH)

clean:
	@echo "[*] Clean"
	@rm -rf build $(INITRD_PATH) $(SHAREDIR_PATH)
	@make -C $(HELPERS_ROOT) clean

deepclean: clean
	@rm -rf workdir_output
