/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _KAFL_VULN_TEST_H_
#define _KAFL_VULN_TEST_H_

#include <sys/types.h>
#include "syx-api.h"

void panic_target();

void target_lvl0(char* buf, size_t len);
void target_lvl1(char* buf, size_t len);
void target_lvl2(char* buf, size_t len);
void target_lvl3(char* buf, size_t len);
void target_lvl4(char* buf, size_t len);


#endif /* _KAFL_VULN_TEST_H_ */
