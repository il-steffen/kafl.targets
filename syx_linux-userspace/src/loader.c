/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../../nyx_api.h"
#include "targets.h"
#include "syx-api.h"

#define PAYLOAD_MAX_SIZE (128*1024)

#ifndef PAYLOAD_ON_HEAP
static uint8_t bss_buffer[PAYLOAD_MAX_SIZE] __attribute__((aligned(4096)));
#endif

#define CALL_TARGET(__lvl, __buf, __size) (glue(target_lvl, __lvl))(__buf, __size)

static inline uint64_t get_address(char* identifier)
{
    FILE * fp;
    char * line = NULL;
    ssize_t read;
    ssize_t len;
    char *tmp;
    uint64_t address = 0x0;
    uint8_t identifier_len = strlen(identifier);

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL){
        return address;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if(strlen(line) > identifier_len && !strcmp(line + strlen(line) - identifier_len, identifier)){
                address = strtoull(strtok(line, " "), NULL, 16);
                break;
        }
    }

    fclose(fp);
    if (line){
        free(line);
    }
    return address;
}

static void agent_init(void* panic_handler, void *kasan_handler)
{
	hprintf("Initiate fuzzer handshake...\n");

	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

	/* submit panic and optionally kasan handlers for qemu override */
	if (panic_handler) {
		// kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uintptr_t)panic_handler);
	} else {
		hprintf("[!] No panic handler used.\n");
	}

	if (kasan_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uintptr_t)kasan_handler);
	} else {
		hprintf("[!] No kasan handler used.\n");
	}

	/* Request information on available (host) capabilites (not optional) */
	volatile host_config_t host_config;
	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
	if (host_config.host_magic != NYX_HOST_MAGIC ||
	    host_config.host_version != NYX_HOST_VERSION) {
		hprintf("host_config magic/version mismatch!\n");
		hprintf("\t- Our Version: %d\n\t- Our Magic: %x\n\n", NYX_HOST_VERSION, NYX_HOST_MAGIC);
		hprintf("\t- Their Version: %d\n\t- Their Magic: %x\n", host_config.host_version, host_config.host_magic);
		habort("GET_HOST_CONFIG magic/version mismatch!\n");
	}
	hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
	hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
	hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

	//uint8_t *trace_buffer = mmap(NULL, MMAP_SIZE(TRACE_BUFFER_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	//memset(trace_buffer, 0, TRACE_BUFFER_SIZE);  // makes sure that the bitmap buffer is already

	/* reserved guest memory must be at least as large as host SHM view */
	if (PAYLOAD_MAX_SIZE < host_config.payload_buffer_size) {
		habort("Insufficient guest payload buffer!\n");
	}

	/* submit agent configuration */
	volatile agent_config_t agent_config = {0};
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;

	agent_config.agent_tracing = 0; // trace by host!
	agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 1; // allow persistent
	agent_config.coverage_bitmap_size = host_config.bitmap_size;

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
}

//#define PAYLOAD_ON_HEAP
static void agent_run(void)
{
	kAFL_payload* payload_buffer;

#ifndef PAYLOAD_ON_HEAP
	payload_buffer = (kAFL_payload*)bss_buffer;
#else
	/* fixme: GET_PAYLOAD requires page-aligned buffer! */
	payload_buffer = k_malloc(PAYLOAD_MAX_SIZE);
	if (!payload_buffer) {
		habort("Failed to allocate payload_buffer!");
		return;
	}
#endif

	/* touch the memory to ensure all pages are present in memory */
	memset(payload_buffer, 0, PAYLOAD_MAX_SIZE);

	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

	hprintf("Running Target %d...\n", TARGET_LEVEL);

	// while (1) {
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
		
		CALL_TARGET(TARGET_LEVEL, payload_buffer->data, payload_buffer->size);
		// target_read(payload_buffer->data, payload_buffer->size);

		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	// }
}

void main(void)
{
    hprintf("kAFL Linux Userspace Fuzzing\n\n");

	// Get panic addresses
	void* panic_handler = panic_target;
	void* kasan_handler = (void*) get_address("t kasan_report_error\n");

	if (kasan_handler){
			hprintf("Kernel KASAN Handler Address:\t%p\n", kasan_handler);
	}

	agent_init(panic_handler, kasan_handler);
	agent_run();
}
