#include <string.h>
#include <sys/types.h>

#include "targets.h"
#include "../../nyx_api.h"
#include "syx-api.h"

void panic_target() {
	hprintf("CRASH\n");
	kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
};

syx_cmd_event_sync_t param = {0};

static inline int target_init(size_t len, size_t min_len) {
	if (len < min_len) {
		return -1;
	}
	
	param.fuzzer_input_offset = 8; // Offset in the fuzzing buffer
	param.len = min_len; // Length to symbolically execute
	param.unique = true; // Patch the VM to remove the hypercall
}

// simple bitwise condition
void target_lvl0(char *buf, size_t len) {
	uint32_t* buf_32 = (uint32_t*)buf;

	if (target_init(len, 8) < 0) {
		return;
	}

	// Symbolic Execution start
	SYX_HYPERCALL(SYX_NS_ID_EVENT, SYX_CMD_EVENT_SYNC, &param);
	if (buf_32[0] == 0xcdef1234) {
		// Constant comparison
		
		uint32_t val = buf_32[0] & buf_32[1];
		if (val == 0xcdef1234) {
			// AND comparison

			panic_target();
		}

	}
	// Symbolic Execution end
	SYX_HYPERCALL(SYX_NS_ID_SYM, SYX_CMD_SYM_END, NULL);
}

// highly input dependent condition
void target_lvl1(char *buf, size_t len) {
	uint32_t* buf_32 = (uint32_t*)buf;

	if (target_init(len, 16) < 0) {
		return;
	}

	SYX_HYPERCALL(SYX_NS_ID_EVENT, SYX_CMD_EVENT_SYNC, &param);
	if ((buf_32[0] + buf_32[2]) == (buf_32[1] + 0x32676d1)) {
		// More input-dependent input comparison

		panic_target();
	}
	SYX_HYPERCALL(SYX_NS_ID_SYM, SYX_CMD_SYM_END, &param);
}

void target_lvl2(char *buf, size_t len) {
	uint32_t* buf_32 = (uint32_t*)buf;
	uint64_t* buf_64 = (uint64_t*)buf;

	if (target_init(len, 20) < 0) {
		return;
	}
	
	SYX_HYPERCALL(SYX_NS_ID_EVENT, SYX_CMD_EVENT_SYNC, &param);
	if (buf_32[0] == 0xcdef1234) {
		// Constant checking

		uint32_t bitwise_and = buf_32[1] & buf_32[2];
		if (bitwise_and == 0xabcd5678) {
			// AND bitwise operation

			uint32_t bitwise_xor = buf_32[3] ^ buf_32[4];
			if (bitwise_xor == 0xaad38753) {
				// XOR bitwise operation

				panic_target();
			}
		}

	}
	SYX_HYPERCALL(SYX_NS_ID_SYM, SYX_CMD_SYM_END, NULL);
}

// Using fuzzing and Symbolic Execution strengths together
void target_lvl3(char *buf, size_t len) {
	uint32_t* buf_32 = (uint32_t*)buf;
	uint64_t* buf_64 = (uint64_t*)buf;
	
	char str[] = "kAFL should easily find this";

	if (target_init(len, 20) < 0) {
		return;
	}

	uint64_t fuzz_str_len = len - 20;
	if (fuzz_str_len < sizeof(str)) {
		return;
	}

	// String comparison check
	if (!strncmp(buf + 20, str, sizeof(str))) {
		SYX_HYPERCALL(SYX_NS_ID_EVENT, SYX_CMD_EVENT_SYNC, &param);

		if (buf_32[0] == 0xcdef1234) {
			// Constant checking

			uint32_t bitwise_and = buf_32[1] & buf_32[2];
			if (bitwise_and == 0xabcd5678) {
				// AND bitwise operation

				uint32_t bitwise_xor = buf_32[3] ^ buf_32[4];
				if (bitwise_xor == 0xaad38753) {
					// XOR bitwise operation

					panic_target();
				}
			}
		}

		SYX_HYPERCALL(SYX_NS_ID_SYM, SYX_CMD_SYM_END, NULL);
	}
}

// Using fuzzing and Symbolic Execution strengths together
void target_lvl4(char *buf, size_t len) {
	uint32_t* buf_32 = (uint32_t*)buf;
	uint64_t* buf_64 = (uint64_t*)buf;

	const static uint64_t magic_table[] = {
		0x12345678abcd4325,
		0xbfd5e8f3a32093b1,
		0xabf3729164fbadec,
		0x26457819b54a3d6f,
		0xb27c6f55a39e8c09
	};

	const uint32_t magic_table_len = sizeof(magic_table) / sizeof(uint64_t);

	if (target_init(len, sizeof(magic_table)) < 0) {
		return;
	}

	uint8_t right_cmp = 0;

	SYX_HYPERCALL(SYX_NS_ID_EVENT, SYX_CMD_EVENT_SYNC, &param);

	for (int i = 0; i < magic_table_len; ++i) {
		if (buf_64[i] == magic_table[i]) {
			right_cmp++;
		}
	}

	if (right_cmp == magic_table_len) {
		panic_target();
	}

	SYX_HYPERCALL(SYX_NS_ID_SYM, SYX_CMD_SYM_END, NULL);
}