// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../../../../include/uapi/linux/scoped_visibility.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define CONTROL "/sys/kernel/security/scoped_visibility/control"

static void usage(const char *program)
{
	fprintf(stderr,
		"%s: %s status\n"
		"       %s clear EXPECTED_GENERATION\n"
		"       %s replace EXPECTED_GENERATION CONFIG\n"
		"CONFIG: directory<TAB>min-max[,min-max...] per line.\n"
		"Experimental interface only; not a startup coordinator or complete fix.\n",
		"usage", program, program, program);
}

/* Decimal ASCII only: no signs, whitespace, overflow or trailing garbage. */
static int number(const char **text, uint64_t limit, uint64_t *result)
{
	const char *p = *text;
	uint64_t value = 0;

	if (*p < '0' || *p > '9')
		return -1;
	while (*p >= '0' && *p <= '9') {
		unsigned int digit = *p++ - '0';

		if (value > (limit - digit) / 10)
			return -1;
		value = value * 10 + digit;
	}
	*result = value;
	*text = p;
	return 0;
}

static int ranges(const char *p, struct sv_entry *entry)
{
	uint64_t lo, hi;

	for (;;) {
		if (entry->nr_ranges == SV_MAX_RANGES ||
		    number(&p, UINT32_MAX - 1ULL, &lo) || *p++ != '-' ||
		    number(&p, UINT32_MAX - 1ULL, &hi) || lo > hi)
			return -1;
		if (entry->nr_ranges &&
		    lo <= entry->ranges[entry->nr_ranges - 1].max)
			return -1;
		entry->ranges[entry->nr_ranges].min = lo;
		entry->ranges[entry->nr_ranges++].max = hi;
		if (!*p)
			return 0;
		if (*p++ != ',')
			return -1;
	}
}

static int config(const char *path, struct sv_snapshot *snapshot)
{
	FILE *input = fopen(path, "r");
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	unsigned int lineno = 0;
	int ret = -1;

	if (!input) {
		perror(path);
		return -1;
	}
	while ((length = getline(&line, &capacity, input)) >= 0) {
		struct sv_entry *entry;
		char *tab;

		lineno++;
		/* Reject embedded NUL and unbounded records rather than truncating. */
		if (memchr(line, 0, length) || length > PATH_MAX + SV_MAX_RANGES * 24)
			goto invalid;
		if (length && line[length - 1] == '\n')
			line[--length] = 0;
		if (length && line[length - 1] == '\r')
			line[--length] = 0;
		if (!length || line[0] == '#')
			continue;
		tab = strchr(line, '\t');
		if (!tab || tab == line || strchr(tab + 1, '\t') ||
		    snapshot->nr_entries == SV_MAX_ENTRIES)
			goto invalid;
		*tab++ = 0;
		entry = &snapshot->entries[snapshot->nr_entries];
		if (ranges(tab, entry))
			goto invalid;
		entry->fd = open(line, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (entry->fd < 0) {
			fprintf(stderr, "%s:%u: open directory %s: %s\n",
				path, lineno, line, strerror(errno));
			goto out;
		}
		snapshot->nr_entries++;
	}
	if (ferror(input)) {
		fprintf(stderr, "%s: read error\n", path);
		goto out;
	}
	ret = 0;
	goto out;
invalid:
	fprintf(stderr, "%s:%u: invalid or excessive directory/UID record\n",
		path, lineno);
out:
	free(line);
	if (fclose(input)) {
		fprintf(stderr, "%s: %s\n", "close config", strerror(errno));
		ret = -1;
	}
	return ret;
}

int main(int argc, char **argv)
{
	struct sv_snapshot snapshot = { .version = SV_VERSION };
	struct sv_info info = { 0 };
	uint64_t generation;
	const char *end;
	int control, ret = 1, status, clear;
	unsigned int i;

	if (argc < 2)
		goto bad_usage;
	status = !strcmp(argv[1], "status");
	clear = !strcmp(argv[1], "clear");
	if (status) {
		if (argc != 2)
			goto bad_usage;
	} else {
		if ((!clear && strcmp(argv[1], "replace")) ||
		    argc != (clear ? 3 : 4))
			goto bad_usage;
		end = argv[2];
		if (number(&end, UINT64_MAX, &generation) || *end)
			goto bad_usage;
		snapshot.expected_generation = generation;
	}
	control = open(CONTROL, (status ? O_RDONLY : O_RDWR) | O_CLOEXEC);
	if (control < 0) {
		perror(CONTROL);
		return 1;
	}
	if (status) {
		if (ioctl(control, SV_IOC_GET_INFO, &info)) {
			perror("GET_INFO");
			goto out;
		}
		if (info.version != SV_VERSION || info.flags || info.reserved ||
		    info.nr_entries > SV_MAX_ENTRIES) {
			fprintf(stderr, "unsupported status response\n");
			goto out;
		}
		printf("generation=%llu count=%u\n",
		       (unsigned long long)info.generation, info.nr_entries);
		puts("object IDs are diagnostic only; not authorization tokens");
		for (i = 0; i < info.nr_entries; i++)
			printf("%u %u:%u:%llu\n", i, info.objects[i].dev_major,
			       info.objects[i].dev_minor,
			       (unsigned long long)info.objects[i].ino);
	} else {
		if (!clear && config(argv[3], &snapshot))
			goto out;
		if (ioctl(control, SV_IOC_REPLACE, &snapshot)) {
			perror("REPLACE (policy not accepted; no generation retry)");
			goto out;
		}
		puts("snapshot accepted");
	}
	ret = 0;
out:
	for (i = 0; i < snapshot.nr_entries; i++)
		close(snapshot.entries[i].fd);
	close(control);
	return ret;
bad_usage:
	usage(argv[0]);
	return 1;
}
