#ifndef WIN32
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/syscall.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <errno.h>
#include <pthread.h>

#define VG_DARWIN_SYSCALL_CLASS_SHIFT     24
#define VG_DARWIN_SYSCALL_CLASS_MASK      (0xFF << VG_DARWIN_SYSCALL_CLASS_SHIFT)
#define VG_DARWIN_SYSCALL_NUMBER_MASK     (~VG_DARWIN_SYSCALL_CLASS_MASK)

#define VG_DARWIN_SYSCALL_CLASS_UNIX      2       /* Unix/BSD */

#define VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(syscall_number) \
    ((VG_DARWIN_SYSCALL_CLASS_UNIX << VG_DARWIN_SYSCALL_CLASS_SHIFT) | \
     (VG_DARWIN_SYSCALL_NUMBER_MASK & (syscall_number)))

#define	__NR_getxattr       VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(234)
#define	__NR_setxattr       VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(236)
#define	__NR_listxattr      VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(240)
#endif

int main_setxattr(int argc, char **argv)
{
	int		rc;
	
	if (argc != 4) {
		fprintf(stderr, "Usage: setxattr path key value\n\n");
		return 1;
	}
	
	rc = syscall(__NR_setxattr, argv[1], argv[2], argv[3], strlen(argv[3]), 0);
	return rc == 0 ? 0 : errno;
}

int main_listxattr(int argc, char **argv)
{
	int		rc;
	char	*list = NULL;
	char	*val = NULL;
	size_t	key_size, val_size, p;
	
	if (argc != 2) {
		fprintf(stderr, "Usage: listxattr path\n\n");
		return 1;
	}
	
	key_size = syscall(__NR_listxattr, argv[1], NULL, 0);
	if (key_size == -1) {
		rc = errno;
		goto cleanup;
	}
	
	list = malloc(key_size);
	key_size = syscall(__NR_listxattr, argv[1], list, key_size);

	if (key_size == -1) {
		rc = errno;
		goto cleanup;
	}

	for (p=0; p<key_size; p+=strlen(list+p)+1) {
		val_size = syscall(__NR_getxattr, argv[1], list+p, NULL, 0);

		if (val_size == -1) {
			rc = errno;
			goto cleanup;
		}

		val = malloc(val_size);
		val_size = syscall(__NR_getxattr, argv[1], list+p, val, val_size);
		
		if (val_size == -1) {
			rc = errno;
			goto cleanup;
		}
		
		fprintf(stdout, "%s: %s\n", list+p, val);
		free(val);
		val = NULL;
	}
	fprintf(stderr, "\n");
	rc = 0;
	
cleanup:
	if (list)
		free(list);
	
	if (val)
		free(val);
	
	return rc;
}
#endif