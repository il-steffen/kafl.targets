/*
 * Zephyr TEST fuzzing sample target
 *
 * Based on kAFL kafl_vuln_test module
 *
 * Copyright 2017 Sergej Schumilo
 * Copyright 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <sys/types.h>

#include "target.h"
#include "../../nyx_api.h"
#include "syx-api.h"

#define INPUT_LENGTH 32

char target_input[INPUT_LENGTH] = {0};

void target_init() {};

void panic_target() {
	kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
};

syx_cmd_event_sync_t param = {0};

void target_entry(char *buf, size_t len)
{
	if (len < 8) {
		return;
	}

	param.fuzzer_input_offset = 0;
	param.len = 8;
	param.unique = true;

	SYX_HYPERCALL(SYX_NS_ID_EVENT, SYX_CMD_EVENT_SYNC, &param);
	if (*(uint32_t*)buf == 0xcdef1234) {
		
		// Supposedly difficult to handle for kafl
		uint32_t val = (*(uint32_t*)(buf) & (*(uint32_t*)(buf + 4)));
		if (val == 0xcdef1234) {
			panic_target();
		}

	}
	SYX_HYPERCALL(SYX_NS_ID_SYM, SYX_CMD_SYM_END, NULL);
}