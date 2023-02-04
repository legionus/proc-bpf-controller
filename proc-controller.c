// SPDX-License-Identifier: GPL-2.0-only

#include <sys/param.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
#include <err.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "proc-controller.h"

int main(int argc, char **argv)
{
	int dev_map, inode_map;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[MAXPATHLEN];
	uint32_t access = ACCESS_ALLOW_LIST;

	const struct option long_options[] = {
		{ "policy", required_argument, 0, 'p' },
		{ NULL, 0, 0, 0, }
	};
	const char *short_options = "p:";

	while (1) {
		int c;

		if ((c = getopt_long(argc, argv, short_options, long_options, NULL)) == -1)
			break;

		switch (c) {
			case 'p':
				if (!strcmp(optarg, "allow"))
					access = ACCESS_ALLOW_LIST;
				else if (!strcmp(optarg, "deny"))
					access = ACCESS_DENY_LIST;
				else
					errx(EXIT_FAILURE, "unknown argument: %s", optarg);
				break;
			default:
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		fprintf(stdout, "Usage: %s [options] filename [filename ...]\n", basename(argv[0]));
		return EXIT_SUCCESS;
	}

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		warnx("ERROR: opening BPF object file failed");
		return EXIT_SUCCESS;
	}

	if (bpf_object__load(obj)) {
		warnx("ERROR: loading BPF object file failed");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "proc_access_restrict");
	if (!prog) {
		warnx("ERROR: finding a restrict_filesystems in obj file failed");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		warnx("ERROR: bpf_program__attach failed");
		link = NULL;
		goto cleanup;
	}

	dev_map = bpf_object__find_map_fd_by_name(obj, "dev_map");
	if (dev_map < 0) {
		warnx("ERROR: finding a dev_map in obj file failed");
		goto cleanup;
	}

	inode_map = bpf_object__find_map_fd_by_name(obj, "inode_map");
	if (dev_map < 0) {
		warnx("ERROR: finding a inode_map in obj file failed");
		goto cleanup;
	}

	int n_dev = 0;
	uint32_t devs[PROC_SB_MAX_ENTRIES];

	memset(devs, 0, sizeof(devs));

	for (int i = optind; i < argc; i++) {
		int j, ret;
		uint32_t value = 1;
		struct key key = {};
		struct stat sb = {};

		if (stat(argv[i], &sb) < 0)
			err(EXIT_FAILURE, "%s", argv[i]);

		key.dev   = sb.st_dev;
		key.inode = sb.st_ino;

		errno = 0;
		if (!bpf_map_lookup_elem(inode_map, &key, &value))
			continue;
		if (errno != ENOENT)
			err(EXIT_FAILURE, "lookup failed");

		if (bpf_map_update_elem(inode_map, &key, &value, BPF_ANY) < 0)
			err(EXIT_FAILURE, "%s: unable to add inode to bpf map", argv[i]);

		warnx("file %s added", argv[i]);

		for (j = 0; j <= n_dev; j++) {
			if (devs[j] == sb.st_dev)
				break;
		}
		if (j <= n_dev)
			continue;
		if ((n_dev + 1) == PROC_SB_MAX_ENTRIES)
			errx(EXIT_FAILURE, "too many mount points");

		devs[n_dev++] = sb.st_dev;
	}

	for (int i = 0; i < n_dev; i++) {
		if (bpf_map_update_elem(dev_map, &devs[i], &access, BPF_ANY) < 0)
			err(EXIT_FAILURE, "unable to add dev to bpf map");
	}

	pause();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return EXIT_SUCCESS;
}
