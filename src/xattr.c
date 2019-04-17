/* Based on: https://github.com/gburd/walkenfs/blob/master/tests/xattr.c */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int main_xattr(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "xattr [ set | get | list | remove ] [ args... ]\n");
		return 1;
	}

	if (strcmp(argv[1], "set") == 0) {
		if (argc != 6) {
			fprintf(stderr, "xattr set path name value [ create | replace | none ]\n");
			return 1;
		}

		#ifdef __APPLE__
		int rv = setxattr(argv[2], argv[3], argv[4], strlen(argv[4]), 0, 
						(strcmp(argv[5], "create") == 0) ? XATTR_CREATE :
						(strcmp(argv[5], "replace") == 0) ? XATTR_REPLACE : 0);
		#else
		int rv = setxattr(argv[2], argv[3], argv[4], strlen(argv[4]),
						(strcmp(argv[5], "create") == 0) ? XATTR_CREATE :
						(strcmp(argv[5], "replace") == 0) ? XATTR_REPLACE : 0);
		#endif

		fprintf(stderr, "ok %d %s\n", rv, strerror(errno));
		return 0;

	} else if (strcmp(argv[1], "get") == 0) {
		if (argc != 5) {
			fprintf(stderr, "xattr get path name size\n");
			return 1;
		}
		size_t size = atoi(argv[4]);
		unsigned char value[size];

		#ifdef __APPLE__
		ssize_t rv = getxattr(argv[2], argv[3], value, size, 0, 0);
		#else
		ssize_t rv = getxattr(argv[2], argv[3], value, size);
		#endif

		if (rv >= 0) {
			fprintf(stderr, "ok %zd %.*s\n", rv, MIN(rv, size),	value);
		} else {
			fprintf(stderr, "ok %zd %s\n", rv, strerror(errno));
		}
		return 0;

	} else if (strcmp(argv[1], "list") == 0) {
		if (argc != 4) {
			fprintf(stderr, "xattr list path size\n");
			return 1;
		}
		size_t size = atoi(argv[3]);
		char list[size];

		#ifdef __APPLE__
		ssize_t rv = listxattr(argv[2], list, size, 0);
		#else
		ssize_t rv = listxattr(argv[2], list, size);
		#endif

		if (rv >= 0) {
			fprintf(stderr, "ok %zd ", rv);
			fflush(stderr);
			write(2, list, MIN(rv, size));
			write(2, "\n", 1);
		} else {
			fprintf(stderr, "ok %zd %s\n", rv, strerror(errno));
		}
		return 0;

	} else if (strcmp(argv[1], "remove") == 0) {
		if (argc != 4) {
			fprintf(stderr, "xattr remove path name\n");
			return 1;
		}
		#ifdef __APPLE__
		int rv = removexattr(argv[2], argv[3], 0);
		#else
		int rv = removexattr(argv[2], argv[3]);
		#endif

		fprintf(stderr, "ok %d %s\n", rv, strerror(errno));
		return 0;
	}

	fprintf(stderr, "xattr [ set | get | list | remove ] [ args... ]\n");
	return 1;
}
