/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PROC_CONTROLLER_H__
#define __PROC_CONTROLLER_H__

#include <stdint.h>

#define INODE_MAX_ENTRIES 256
#define PROC_SB_MAX_ENTRIES 1024

struct key {
	uint32_t dev;
	uint32_t inode;
};

enum {
	ACCESS_ALLOW_LIST = 0,
	ACCESS_DENY_LIST  = 1,
};

#endif /* __PROC_CONTROLLER_H__ */
