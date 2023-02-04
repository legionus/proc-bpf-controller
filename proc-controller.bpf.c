/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/types.h>
#include <linux/magic.h>
#include <linux/limits.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>

#include "proc-controller.h"

#define DNAME_LEN 64

struct super_block {
	long unsigned int	s_magic;
	uint32_t		s_dev;
	struct dentry		*s_root;
} __attribute__((preserve_access_index));

struct inode {
	struct super_block	*i_sb;
	unsigned long		i_ino;
	uint32_t		i_rdev;
} __attribute__((preserve_access_index));

struct qstr {
	uint32_t		len;
	const unsigned char	*name;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry	*d_parent;
	struct qstr	d_name;
} __attribute__((preserve_access_index));

struct path {
	struct dentry	*dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path	f_path;
	struct inode	*f_inode;
} __attribute__((preserve_access_index));

struct callback_ctx {
	struct dentry *root;
	struct dentry *dentry;
};

static long callback(__u32 index __attribute__((unused)), void *data)
{
	struct callback_ctx *ctx = data;
	struct dentry *dentry = ctx->dentry;
	struct dentry *parent;

	if (!dentry || dentry == ctx->root)
		return 1;

	parent = BPF_CORE_READ(dentry, d_parent);

	if (parent == ctx->root)
		return 1;

	ctx->dentry = parent;
	return 0;
}

// See fs/proc/utils.c
static unsigned name_is_int(const char *name, long len)
{
	unsigned n = 0;

	if (len > 1 && *name == '0')
		goto out;
	do {
		unsigned c = *name++ - '0';
		if (c > 9)
			goto out;
		if (n >= (~0U-9)/10)
			goto out;
		n *= 10;
		n += c;
	} while (--len > 0);
	return n;
out:
	return ~0U;
}

struct dev_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROC_SB_MAX_ENTRIES);
	__type(key, uint32_t);
	__type(value, uint32_t);
} dev_map SEC(".maps");

struct inode_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROC_SB_MAX_ENTRIES * INODE_MAX_ENTRIES);
	__type(key, struct key);
	__type(value, uint32_t);
} inode_map SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(proc_access_restrict, struct file *file, int ret)
{
	unsigned long magic_number;
	unsigned long ino;
	uint32_t dev, *is_allow;
	struct dentry *sb_root, *subdir;
	const unsigned char *name;
	char dname[DNAME_LEN];
	long dlen;

	struct path *f_path = &file->f_path;
	struct dentry *dentry = BPF_CORE_READ(f_path, dentry);

	struct callback_ctx data = {};

	if (ret != 0)
		return ret;

	BPF_CORE_READ_INTO(&magic_number, file, f_inode, i_sb, s_magic);

	if (magic_number != PROC_SUPER_MAGIC)
		return 0;

	BPF_CORE_READ_INTO(&ino,     file, f_inode, i_ino);
	BPF_CORE_READ_INTO(&dev,     file, f_inode, i_sb, s_dev);
	BPF_CORE_READ_INTO(&sb_root, file, f_inode, i_sb, s_root);

	data.root = sb_root;
	data.dentry = dentry;

	bpf_loop(3, callback, &data, 0);

	subdir = data.dentry;
	name = BPF_CORE_READ(subdir, d_name.name);
	dlen = bpf_core_read_str(dname, DNAME_LEN, name);

	if (dlen > 0 && name_is_int(dname, dlen - 1) != ~0U)
		return 0;

	if ((is_allow = bpf_map_lookup_elem(&dev_map, &dev)) != NULL) {
		struct key key = {
			.dev   = dev,
			.inode = ino,
		};

		if (*is_allow == ACCESS_ALLOW_LIST) {
			/* Allow-list: Allow access only if magic_number present in inner map */
			if (bpf_map_lookup_elem(&inode_map, &key) == NULL)
				return -EPERM;
		} else {
			/* Deny-list: Allow access only if magic_number is not present in inner map */
			if (bpf_map_lookup_elem(&inode_map, &key) != NULL)
				return -EPERM;
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
