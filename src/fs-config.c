/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* This file is used to define the properties of the filesystem
** images generated by build tools (mkbootfs and mkyaffs2image) and
** by the device side of adb.
*/
#define LOG_TAG "fs_config"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <stdbool.h>
#else
#include <windows.h>
#endif

#include <private/android_filesystem_config.h>
#include <utils/compat.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* The following structure is stored little endian */
struct fs_path_config_from_file {
	uint16_t len;
	uint16_t mode;
	uint16_t uid;
	uint16_t gid;
	uint64_t capabilities;
	char prefix[];
}
#ifndef WIN32
__attribute__((__aligned__(sizeof(uint64_t))))
#endif
;

/* My kingdom for <endian.h> */
static inline uint16_t get2LE(const uint8_t * src)
{
	return src[0] | (src[1] << 8);
}

static inline uint64_t get8LE(const uint8_t * src)
{
	uint32_t low, high;
	low = src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
	high = src[4] | (src[5] << 8) | (src[6] << 16) | (src[7] << 24);
	return ((uint64_t) high << 32) | (uint64_t) low;
}

#define ALIGN(x, alignment) (((x) + ((alignment)-1)) & ~((alignment)-1))

static const char conf_dir[] = "/system/etc/fs_config_dirs";
static const char conf_file[] = "/system/etc/fs_config_files";

static int fs_config_open(int dir, const char *target_out_path)
{
	int fd = -1;
	if (target_out_path && *target_out_path) {
		/* target_out_path is the path to the directory holding content of
		 * system partition but as we cannot guaranty it ends with '/system'
		 * we need this below skip_len logic */
		char *name = NULL;
		int target_out_path_len = strlen(target_out_path);
		int skip_len = strlen("/system");
		if (target_out_path[target_out_path_len] == '/') {
			skip_len++;
		}
		if (asprintf
		    (&name, "%s%s", target_out_path,
		     (dir ? conf_dir : conf_file) + skip_len) != -1) {
			fd = TEMP_FAILURE_RETRY(open
						(name, O_RDONLY | O_BINARY));
			free(name);
		}
	}
	if (fd < 0) {
		fd = TEMP_FAILURE_RETRY(open
					(dir ? conf_dir : conf_file,
					 O_RDONLY | O_BINARY));
	}
	return fd;
}

static bool fs_config_cmp(bool dir, const char *prefix, size_t len,
			  const char *path, size_t plen)
{
	if (dir) {
		if (plen < len) {
			return false;
		}
	} else {
		/* If name ends in * then allow partial matches. */
		if (prefix[len - 1] == '*') {
			return !strncmp(prefix, path, len - 1);
		}
		if (plen != len) {
			return false;
		}
	}
	return !strncmp(prefix, path, len);
}

void fs_config(const char *path, int dir, const char *target_out_path,
	       unsigned *uid, unsigned *gid, unsigned *mode,
	       uint64_t * capabilities)
{
	const struct fs_path_config *pc;
	size_t plen;
	int fd;

	if (path[0] == '/') {
		path++;
	}

	plen = strlen(path);

	fd = fs_config_open(dir, target_out_path);
	if (fd >= 0) {
		struct fs_path_config_from_file header;

		while (TEMP_FAILURE_RETRY(read(fd, &header, sizeof(header))) ==
		       sizeof(header)) {
			char *prefix;
			uint16_t host_len =
			    get2LE((const uint8_t *)&header.len);
			ssize_t len, remainder = host_len - sizeof(header);
			if (remainder <= 0) {
				printf("%s len is corrupted",
				       dir ? conf_dir : conf_file);
				break;
			}
			prefix = calloc(1, remainder);
			if (!prefix) {
				printf("%s out of memory",
				       dir ? conf_dir : conf_file);
				break;
			}
			if (TEMP_FAILURE_RETRY(read(fd, prefix, remainder)) !=
			    remainder) {
				free(prefix);
				printf("%s prefix is truncated",
				       dir ? conf_dir : conf_file);
				break;
			}
			len = strnlen(prefix, remainder);
			if (len >= remainder) {	/* missing a terminating null */
				free(prefix);
				printf("%s is corrupted",
				       dir ? conf_dir : conf_file);
				break;
			}
			if (fs_config_cmp(dir, prefix, len, path, plen)) {
				free(prefix);
				close(fd);
				*uid = get2LE((const uint8_t *)&(header.uid));
				*gid = get2LE((const uint8_t *)&(header.gid));
				*mode =
				    (*mode & (~07777)) |
				    get2LE((const uint8_t *)&(header.mode));
				*capabilities =
				    get8LE((const uint8_t *)
					   &(header.capabilities));
				return;
			}
			free(prefix);
		}
		close(fd);
	}

	for (pc = dir ? android_dirs : android_files; pc->prefix; pc++) {
		if (fs_config_cmp
		    (dir, pc->prefix, strlen(pc->prefix), path, plen)) {
			break;
		}
	}

	*uid = pc->uid;
	*gid = pc->gid;
	*mode = (*mode & (~07777)) | pc->mode;
	*capabilities = pc->capabilities;
}

ssize_t fs_config_generate(char *buffer, size_t length,
			   const struct fs_path_config *pc)
{
	struct fs_path_config_from_file *p =
	    (struct fs_path_config_from_file *)buffer;
	size_t len =
	    ALIGN(sizeof(*p) + strlen(pc->prefix) + 1, sizeof(uint64_t));

	if ((length < len) || (len > UINT16_MAX)) {
		return -ENOSPC;
	}
	memset(p, 0, len);
	uint16_t host_len = len;
	p->len = get2LE((const uint8_t *)&host_len);
	p->mode = get2LE((const uint8_t *)&(pc->mode));
	p->uid = get2LE((const uint8_t *)&(pc->uid));
	p->gid = get2LE((const uint8_t *)&(pc->gid));
	p->capabilities = get8LE((const uint8_t *)&(pc->capabilities));
	strcpy(p->prefix, pc->prefix);
	return len;
}