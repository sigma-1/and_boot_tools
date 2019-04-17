/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if libinotify is built */
#define BUILD_LIBRARY 1

/* Define to 1 if DIR have dd_fd field */
/* #undef DIR_HAVE_DD_FD */

/* Enable error messages */
/* #undef ENABLE_PERRORS */

/* Allow to use of fchdir to track of watched directory path changes */
/* #undef ENABLE_UNSAFE_FCHDIR */

/* Define to 1 if relative pathname functions detected */
#define HAVE_ATFUNCS 1

/* Define to 1 if the compiler supports atomic operations with
   compat/stdatomic.h */
/* #undef HAVE_COMPAT_STDATOMIC_H */

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `fdopendir' function. */
#define HAVE_FDOPENDIR 1

/* Define to 1 if you have the `fstatat' function. */
#define HAVE_FSTATAT 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `kevent' function. */
#define HAVE_KEVENT 1

/* Define to 1 if you have the `kqueue' function. */
#define HAVE_KQUEUE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if move_from sets NODE_EXTEND flag */
/* #undef HAVE_NOTE_EXTEND_ON_MOVE_FROM */

/* Define to 1 if move_to sets NODE_EXTEND flag */
/* #undef HAVE_NOTE_EXTEND_ON_MOVE_TO */

/* Define to 1 if you have the `openat' function. */
#define HAVE_OPENAT 1

/* Define to 1 if O_EVTONLY defined in fcntl.h */
#define HAVE_O_EVTONLY 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Define to 1 if the system has pthread_barrier */
/* #undef HAVE_PTHREAD_BARRIER */

/* Have PTHREAD_PRIO_INHERIT. */
#define HAVE_PTHREAD_PRIO_INHERIT 1

/* Define to 1 if the system has useable stdatomic.h */
#define HAVE_STDATOMIC_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if `d_type' is a member of `struct dirent'. */
#define HAVE_STRUCT_DIRENT_D_TYPE 1

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/event.h> header file. */
#define HAVE_SYS_EVENT_H 1

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if the system has useable sys/tree.h */
/* #undef HAVE_SYS_TREE_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libinotify"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/libinotify-kqueue/libinotify-kqueue/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libinotify"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libinotify 20180201"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libinotify"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "20180201"

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Define to 1/2 if opendir is necessary for each directory read */
#define READDIR_DOES_OPENDIR 1

/* List of filesystem types where opening of subfiles is not performed */
/* #undef SKIP_SUBFILES */

/* Define to 1 if struct statfs have f_fstypename field */
/* #undef STATFS_HAVE_F_FSTYPENAME */

/* Define to 1 if struct statvfs have f_fstypename field */
/* #undef STATVFS_HAVE_F_FSTYPENAME */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "20180201"
