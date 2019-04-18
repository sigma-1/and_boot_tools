#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#ifndef WIN32
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

int main_append2simg(int argc, char *argv[]);
int main_dhtbsign (int argc, char** argv);
int main_dtbinfo(int argc, char **argv);
int main_dtbtool(int argc, char **argv);
int main_elftool(int argc, char **argv);
int main_fctxinject(int argc, char **argv);
int main_getarch(int argc, char **argv);
int main_gunzip(int argc, char **argv);
int main_hexpatch(int argc, char **argv);
int main_img2simg(int argc, char *argv[]);
int main_kerneldump(int argc, char *argv[]);
#ifndef WIN32
int main_keycheck(int argc, char **argv);
#endif
int main_loki(int argc, char** argv);
int main_mboot(int argc, char **argv);
int main_mkbootimg(int argc, char **argv);
int main_mkcpio (int argc, char *argv[]);
int main_mkinitfs(int argc, char **argv);
int main_mkmtkhdr(int argc, char **argv);
int main_offsetof(int argc, char **argv);
int main_pem2mincrypt(int argc, char** argv);
int main_readta(int argc, char **argv);
int main_replace(int argc, char **argv);
int main_sdat2img(int argc, char *argv[]);
int main_seinject(int argc, char **argv);
int main_simg2img(int argc, char *argv[]);
int main_simg2simg(int argc, char *argv[]);
int main_uncpio(int argc, char **argv);
int main_unpackelf(int argc, char **argv);
int main_unpackbootimg(int argc, char **argv);
int main_unpackinitfs(int argc, char **argv);
int main_untar(int argc, char *argv[]);
int main_unzip(int argc, char *argv[]);
#ifndef WIN32
int main_xattr(int argc, char *argv[]);
#endif
int main_zip(int argc, char* argv[]);

typedef struct APPLET {
	char	*name;
	int	(*func_main)(int, char**);
} APPLET;

static const APPLET applets[] = {
	{ "append2simg", main_append2simg },
	{ "dtbinfo", main_dhtbsign },
	{ "dtbinfo", main_dtbinfo },
	{ "dtbtool", main_dtbtool },
	{ "elftool", main_elftool },
	{ "fctxinject", main_fctxinject },
	{ "getarch", main_getarch },
	{ "gunzip", main_gunzip },
	{ "hexpatch", main_hexpatch },
	{ "img2simg", main_img2simg },
	#ifndef WIN32
	{ "kerneldump", main_kerneldump },
	{ "keycheck", main_keycheck },
	#endif
	{ "loki", main_loki },
	{ "mboot", main_mboot },
	{ "mkbootimg", main_mkbootimg },
	{ "mkcpio", main_mkcpio },
	{ "mkinitfs", main_mkinitfs },
	{ "mkmtkhdr", main_mkmtkhdr },
	{ "offsetof", main_offsetof },
	{ "pem2mincrypt", main_pem2mincrypt },
	{ "readta", main_readta },
	{ "replace", main_replace },
	{ "sdat2img", main_sdat2img },
	{ "seinject", main_seinject },
	{ "simg2img", main_simg2img },
	{ "simg2simg", main_simg2simg },
	{ "uncpio", main_uncpio },
	{ "unpackelf", main_unpackelf },
	{ "unpackbootimg", main_unpackbootimg },
	{ "unpackinitfs", main_unpackinitfs },
	{ "untar", main_untar },
	{ "unzip", main_unzip },
	#ifndef WIN32
	{ "xattr", main_xattr },
	#endif
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
	unsigned int i;
	char *self, *progname;

#ifndef WIN32
	unsigned int len;
	char path[256];
#endif

	progname = argv[0];
	for (i = 0; argv[0][i] != 0; i++) {
		if (argv[0][i] == '/' || argv[0][i] == '\\')
			progname = argv[0] + i + 1;
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
