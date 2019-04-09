#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#ifndef WIN32
#include <unistd.h>
#endif
#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/dyld.h>
#endif

int main_unpackelf(int argc, char** argv);
int main_unpackimg(int argc, char** argv);
int main_mkimg(int argc, char** argv);
int main_unpackinitfs(int argc, char** argv);
int main_mkinitfs(int argc, char** argv);
int main_getarch(int argc, char** argv);
int main_keycheck(int argc, char** argv);
int main_listxattr(int argc, char **argv);
int main_setxattr(int argc, char **argv);
int main_seinject(int argc, char **argv);
int main_fctxinject(int argc, char **argv);
int main_readta(int argc, char **argv);
int main_zip(int argc, char **argv);
int main_dtbinfo(int argc, char **argv);
int main_dtbtool(int argc, char **argv);
int main_offsetof(int argc, char **argv);
int main_replace(int argc, char **argv);
int main_mboot(int argc, char **argv);
int main_magiskpolicy(int argc, char *argv[]);
int main_hexpatch(int argc, char **argv);

typedef struct APPLET {
	char	*name;
	 int	(*func_main)(int, char**);
} APPLET;

static const APPLET applets[] = {
	{ "dtbinfo", main_dtbinfo },
	{ "dtbtool", main_dtbtool},
	{ "fctxinject", main_fctxinject },
	{ "getarch", main_getarch },
	{ "hexpatch", main_hexpatch },
#ifndef WIN32
	{ "keycheck", main_keycheck },
	{ "listxattr", main_listxattr },
#endif
	{ "magiskpolicy", main_magiskpolicy },
	{ "mboot", main_mboot },
	{ "mkimg", main_mkimg },
	{ "mkinitfs", main_mkinitfs },
	{ "offsetof", main_offsetof },
	{ "readta", main_readta },
	{ "replace", main_replace },
	{ "seinject", main_seinject },
#ifndef WIN32
	{ "setxattr", main_setxattr },
#endif
	{ "unpackelf", main_unpackelf },
	{ "unpackimg", main_unpackimg },
	{ "unpackinitfs", main_unpackinitfs },
	{ "zip", main_zip }
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

int usage(char* progname) {
	int i;

    fprintf(stderr, "Usage: %s <command> [ -|--option <argument> ]\n", progname);
	fprintf(stderr, "Available commands:\n\n");
	for (i = 0; i < ARRAY_SIZE(applets); i++) {
		fprintf(stderr, "    %s", applets[i].name);
		if (i != ARRAY_SIZE(applets)-1)
			fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n\n");

	return 200;
}

int main(int argc, char **argv)
{
	unsigned int	i;
	char			*self, *progname;

#ifndef WIN32
	unsigned int	len;
	char			path[256];
#endif

	progname = argv[0];
	for (i=0; argv[0][i] != 0; i++) {
		if (argv[0][i] == '/' || argv[0][i] == '\\')
			progname = argv[0]+i+1;
	}

	self = progname;

#ifndef WIN32
#if defined(__APPLE__) && defined(__MACH__)
	uint32_t size = sizeof(path);
	len = _NSGetExecutablePath(path, &size);
#else
	len = readlink("/proc/self/exe", path, sizeof(path));
#endif
	path[len] = 0;

	for (i=0; i<len; i++) {
		if (path[i] == '/')
			self = path + i + 1;
	}
#endif

	if (0 == strcmp(progname, self)) {
		if (argc == 1)
			return usage(progname);

		argv++;
		--argc;
		progname = argv[0];
	}

	for (i = 0; i < ARRAY_SIZE(applets); i++)
		if (0 == strcmp(progname, applets[i].name))
			return applets[i].func_main(argc, argv);

	return usage(progname);
}