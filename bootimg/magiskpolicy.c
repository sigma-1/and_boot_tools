/* magiskpolicy.c - Main function for policy patching
 *
 * Includes all the parsing logic for the policy statements
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>
#include <unistd.h>
#include <stdarg.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sepol/debug.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/constraint.h>

#include <magisk/magiskpolicy.h>
#include <magisk/magisk.h>
#include <magisk/sepolicy.h>
#include <magisk/vector.h>

#ifdef WIN32
#include <utils/windows-mmap.h>
#endif

#ifdef _WIN32
#define __attribute__(a) /* unused */
#define __attribute(a) /* unused */
#define IPPROTO_DCCP 33  /* Datagram Congestion Control Protocol */
#define PATH_MAX 256
#define ssize_t size_t
#define strncasecmp _strnicmp
#define strcasecmp _stricmp 
#define strtok_r strtok_s
#endif 

/* API */
int sepol_allow(char *s, char *t, char *c, char *p) {
	// printf("allow %s %s %s %s\n", s, t, c, p);
	return add_rule(s, t, c, p, AVTAB_ALLOWED, 0);
}

int sepol_deny(char *s, char *t, char *c, char *p) {
	// printf("deny %s %s %s %s\n", s, t, c, p);
	return add_rule(s, t, c, p, AVTAB_ALLOWED, 1);
}

int sepol_auditallow(char *s, char *t, char *c, char *p) {
	// printf("auditallow %s %s %s %s\n", s, t, c, p);
	return add_rule(s, t, c, p, AVTAB_AUDITALLOW, 0);
}

int sepol_auditdeny(char *s, char *t, char *c, char *p) {
	// printf("auditdeny %s %s %s %s\n", s, t, c, p);
	return add_rule(s, t, c, p, AVTAB_AUDITDENY, 0);
}

int sepol_typetrans(char *s, char *t, char *c, char *d, char *o) {
	if (o == NULL) {
		// printf("add_trans %s %s %s %s\n", s, t, c ,d);
		return add_transition(s, t, c, d);
	} else {
		// printf("add_file_trans %s %s %s %s %s\n", s, t, c ,d, o);
		return add_file_transition(s, t, c, d, o);
	}
}

int sepol_allowxperm(char *s, char *t, char *c, char *range) {
	// printf("allowxperm %s %s %s %s\n", s, t, c, range);
	return add_xperm_rule(s, t, c, range, AVTAB_XPERMS_ALLOWED, 0);
}

int sepol_auditallowxperm(char *s, char *t, char *c, char *range) {
	// printf("auditallowxperm %s %s %s %s\n", s, t, c, range);
	return add_xperm_rule(s, t, c, range, AVTAB_XPERMS_AUDITALLOW, 0);
}

int sepol_dontauditxperm(char *s, char *t, char *c, char *range) {
	// printf("dontauditxperm %s %s %s %s\n", s, t, c, range);
	return add_xperm_rule(s, t, c, range, AVTAB_XPERMS_DONTAUDIT, 0);
}

int sepol_permissive(char *s) {
	// printf("permissive %s\n", s);
	return set_domain_state(s, 1);
}

int sepol_enforce(char *s) {
	// printf("enforce %s\n", s);
	return set_domain_state(s, 0);
}

int sepol_create(char *s) {
	// printf("create %s\n", s);
	return create_domain(s);
}

int sepol_attradd(char *s, char *a) {
	// printf("attradd %s %s\n", s, a);
	return add_typeattribute(s, a);
}

int sepol_exists(char* source) {
	return !! hashtab_search(policydb->p_types.table, source);
}

/* Rules */
static void allowSuClient(char *target) {
	if (!sepol_exists(target))
		return;
	sepol_allow(target, SEPOL_PROC_DOMAIN, "unix_stream_socket", "connectto");
	sepol_allow(target, SEPOL_PROC_DOMAIN, "unix_stream_socket", "getopt");
	sepol_allow(SEPOL_PROC_DOMAIN, target, "fd", "use");
	sepol_allow(SEPOL_PROC_DOMAIN, target, "fifo_file", ALL);

	// Allow access to magisk files
	sepol_allow(target, SEPOL_FILE_DOMAIN, "file", ALL);
	sepol_allow(target, SEPOL_FILE_DOMAIN, "dir", ALL);

	// Allow binder service
	sepol_allow(target, SEPOL_PROC_DOMAIN, "binder", "call");
	sepol_allow(target, SEPOL_PROC_DOMAIN, "binder", "transfer");

	// Allow termios ioctl
	sepol_allow(target, "devpts", "chr_file", "ioctl");
	sepol_allow(target, "untrusted_app_devpts", "chr_file", "ioctl");
	sepol_allow(target, "untrusted_app_25_devpts", "chr_file", "ioctl");
	sepol_allow(target, "untrusted_app_all_devpts", "chr_file", "ioctl");
	if (policydb->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
		sepol_allowxperm(target, "devpts", "chr_file", "0x5400-0x54FF");
		sepol_allowxperm(target, "untrusted_app_devpts", "chr_file", "0x5400-0x54FF");
		sepol_allowxperm(target, "untrusted_app_25_devpts", "chr_file", "0x5400-0x54FF");
		sepol_allowxperm(target, "untrusted_app_all_devpts", "chr_file", "0x5400-0x54FF");
	}
}

void sepol_magisk_rules() {
	// First prevent anything to change sepolicy except ourselves
	sepol_deny(ALL, "kernel", "security", "load_policy");

	if (!sepol_exists(SEPOL_PROC_DOMAIN))
		sepol_create(SEPOL_PROC_DOMAIN);
	if (!sepol_exists(SEPOL_FILE_DOMAIN))
		sepol_create(SEPOL_FILE_DOMAIN);
	sepol_permissive(SEPOL_PROC_DOMAIN);

	sepol_attradd(SEPOL_PROC_DOMAIN, "mlstrustedsubject");
	sepol_attradd(SEPOL_PROC_DOMAIN, "netdomain");
	sepol_attradd(SEPOL_PROC_DOMAIN, "bluetoothdomain");
	sepol_attradd(SEPOL_FILE_DOMAIN, "mlstrustedobject");

	// Let init run stuffs
	sepol_allow("kernel", SEPOL_PROC_DOMAIN, "fd", "use");
	sepol_allow("init", SEPOL_PROC_DOMAIN, "process", ALL);

	// Shell, properties, logs
	if (sepol_exists("default_prop"))
		sepol_allow(SEPOL_PROC_DOMAIN, "default_prop", "property_service", "set");
	sepol_allow(SEPOL_PROC_DOMAIN, "init", "unix_stream_socket", "connectto");
	sepol_allow(SEPOL_PROC_DOMAIN, "rootfs", "filesystem", "remount");
	if (sepol_exists("logd"))
		sepol_allow(SEPOL_PROC_DOMAIN, "logd", "unix_stream_socket", "connectto");
	sepol_allow(SEPOL_PROC_DOMAIN, SEPOL_PROC_DOMAIN, ALL, ALL);

	// For sepolicy live patching
	sepol_allow(SEPOL_PROC_DOMAIN, "kernel", "security", "read_policy");
	sepol_allow(SEPOL_PROC_DOMAIN, "kernel", "security", "load_policy");

	// Allow these processes to access MagiskSU
	allowSuClient("init");
	allowSuClient("shell");
	allowSuClient("system_app");
	allowSuClient("priv_app");
	allowSuClient("platform_app");
	allowSuClient("untrusted_app");
	allowSuClient("untrusted_app_25");
	allowSuClient("untrusted_app_27");
	allowSuClient("update_engine");

	// suRights
	sepol_allow("servicemanager", SEPOL_PROC_DOMAIN, "dir", "search");
	sepol_allow("servicemanager", SEPOL_PROC_DOMAIN, "dir", "read");
	sepol_allow("servicemanager", SEPOL_PROC_DOMAIN, "file", "open");
	sepol_allow("servicemanager", SEPOL_PROC_DOMAIN, "file", "read");
	sepol_allow("servicemanager", SEPOL_PROC_DOMAIN, "process", "getattr");
	sepol_allow("servicemanager", SEPOL_PROC_DOMAIN, "binder", "transfer");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "dir", "search");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "dir", "read");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "file", "open");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "file", "read");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "process", "getattr");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "binder", "transfer");
	sepol_allow(SEPOL_PROC_DOMAIN, "servicemanager", "binder", "call");
	sepol_allow(ALL, SEPOL_PROC_DOMAIN, "process", "sigchld");

	// allowLog
	sepol_allow("logd", SEPOL_PROC_DOMAIN, "dir", "search");
	sepol_allow("logd", SEPOL_PROC_DOMAIN, "file", "read");
	sepol_allow("logd", SEPOL_PROC_DOMAIN, "file", "open");
	sepol_allow("logd", SEPOL_PROC_DOMAIN, "file", "getattr");

	// suBackL0
	sepol_allow("system_server", SEPOL_PROC_DOMAIN, "binder", "call");
	sepol_allow("system_server", SEPOL_PROC_DOMAIN, "binder", "transfer");
	sepol_allow(SEPOL_PROC_DOMAIN, "system_server", "binder", "call");
	sepol_allow(SEPOL_PROC_DOMAIN, "system_server", "binder", "transfer");

	// suBackL6
	sepol_allow("surfaceflinger", "app_data_file", "dir", ALL);
	sepol_allow("surfaceflinger", "app_data_file", "file", ALL);
	sepol_allow("surfaceflinger", "app_data_file", "lnk_file", ALL);
	sepol_attradd("surfaceflinger", "mlstrustedsubject");

	// suMiscL6
	if (sepol_exists("audioserver"))
		sepol_allow("audioserver", "audioserver", "process", "execmem");

	// Liveboot
	sepol_allow("surfaceflinger", SEPOL_PROC_DOMAIN, "process", "ptrace");
	sepol_allow("surfaceflinger", SEPOL_PROC_DOMAIN, "binder", "transfer");
	sepol_allow("surfaceflinger", SEPOL_PROC_DOMAIN, "binder", "call");
	sepol_allow("surfaceflinger", SEPOL_PROC_DOMAIN, "fd", "use");
	sepol_allow("debuggerd", SEPOL_PROC_DOMAIN, "process", "ptrace");

	// dumpsys
	sepol_allow(ALL, SEPOL_PROC_DOMAIN, "fd", "use");
	sepol_allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "write");
	sepol_allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "read");
	sepol_allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "open");
	sepol_allow(ALL, SEPOL_PROC_DOMAIN, "fifo_file", "getattr");

	// bootctl
	sepol_allow("hwservicemanager", SEPOL_PROC_DOMAIN, "dir", "search");
	sepol_allow("hwservicemanager", SEPOL_PROC_DOMAIN, "file", "read");
	sepol_allow("hwservicemanager", SEPOL_PROC_DOMAIN, "file", "open");
	sepol_allow("hwservicemanager", SEPOL_PROC_DOMAIN, "process", "getattr");
	sepol_allow("hwservicemanager", SEPOL_PROC_DOMAIN, "binder", "transfer");

	// For mounting loop devices, mirrors, tmpfs
	sepol_allow(SEPOL_PROC_DOMAIN, "kernel", "process", "setsched");
	sepol_allow(SEPOL_PROC_DOMAIN, "labeledfs", "filesystem", "mount");
	sepol_allow(SEPOL_PROC_DOMAIN, "labeledfs", "filesystem", "unmount");
	sepol_allow(SEPOL_PROC_DOMAIN, "tmpfs", "filesystem", "mount");
	sepol_allow(SEPOL_PROC_DOMAIN, "tmpfs", "filesystem", "unmount");
	sepol_allow("kernel", ALL, "file", "read");

	// Allow su to do anything to any files/dir/links
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "file", ALL);
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "dir", ALL);
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "lnk_file", ALL);
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "blk_file", ALL);
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "sock_file", ALL);
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "chr_file", ALL);
	sepol_allow(SEPOL_PROC_DOMAIN, ALL, "fifo_file", ALL);

	// For changing attributes
	sepol_allow("rootfs", "tmpfs", "filesystem", "associate");
	sepol_allow(SEPOL_FILE_DOMAIN, "labeledfs", "filesystem", "associate");
	sepol_allow(SEPOL_FILE_DOMAIN, "tmpfs", "filesystem", "associate");

	// Xposed
	sepol_allow("untrusted_app", "untrusted_app", "capability", "setgid");
	sepol_allow("system_server", "dex2oat_exec", "file", ALL);

	// Support deodexed ROM on Oreo
	sepol_allow("zygote", "dalvikcache_data_file", "file", "execute");

	// Allow update engine to source addon.d.sh
	sepol_allow("update_engine", "adb_data_file", "dir", ALL);
}


/* SEPolicy */

policydb_t *policydb = NULL;
extern int policydb_index_decls(sepol_handle_t * handle, policydb_t * p);

static void *cmalloc(size_t s) {
	void *t = calloc(s, 1);
	if (t == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	return t;
}

static int get_attr(char *type, int value) {
	type_datum_t *attr = hashtab_search(policydb->p_types.table, type);
	if (!attr)
		return 1;

	if (attr->flavor != TYPE_ATTRIB)
		return 1;

	return !! ebitmap_get_bit(&policydb->attr_type_map[attr->s.value-1], value-1);
}

static int get_attr_id(char *type) {
	type_datum_t *attr = hashtab_search(policydb->p_types.table, type);
	if (!attr)
		return 1;

	if (attr->flavor != TYPE_ATTRIB)
		return 1;

	return attr->s.value;
}

static int set_attr(char *type, int value) {
	type_datum_t *attr = hashtab_search(policydb->p_types.table, type);
	if (!attr)
		return 1;

	if (attr->flavor != TYPE_ATTRIB)
		return 1;

	if(ebitmap_set_bit(&policydb->type_attr_map[value-1], attr->s.value-1, 1))
		return 1;
	if(ebitmap_set_bit(&policydb->attr_type_map[attr->s.value-1], value-1, 1))
		return 1;

	return 0;
}

static int __add_rule(int s, int t, int c, int p, int effect, int not) {
	avtab_key_t key;
	avtab_datum_t *av;
	int new_rule = 0;

	key.source_type = s;
	key.target_type = t;
	key.target_class = c;
	key.specified = effect;

	av = avtab_search(&policydb->te_avtab, &key);
	if (av == NULL) {
		av = cmalloc(sizeof(*av));
		new_rule = 1;
	}

	if(not) {
		if (p < 0)
			av->data = 0U;
		else
			av->data &= ~(1U << (p - 1));
	} else {
		if (p < 0)
			av->data = ~0U;
		else
			av->data |= 1U << (p - 1);
	}

	if (new_rule) {
		if (avtab_insert(&policydb->te_avtab, &key, av)) {
			fprintf(stderr, "Error inserting into avtab\n");
			return 1;
		}
		free(av);
	}

	return 0;
}

static int add_rule_auto(type_datum_t *src, type_datum_t *tgt, class_datum_t *cls, perm_datum_t *perm, int effect, int not) {
	hashtab_ptr_t cur;
	int ret = 0;

	if (src == NULL) {
		hashtab_for_each(policydb->p_types.table, &cur) {
			src = cur->datum;
			ret |= add_rule_auto(src, tgt, cls, perm, effect, not);
		}
	} else if (tgt == NULL) {
		hashtab_for_each(policydb->p_types.table, &cur) {
			tgt = cur->datum;
			ret |= add_rule_auto(src, tgt, cls, perm, effect, not);
		}
	} else if (cls == NULL) {
		hashtab_for_each(policydb->p_classes.table, &cur) {
			cls = cur->datum;
			ret |= __add_rule(src->s.value, tgt->s.value, cls->s.value, -1, effect, not);
		}
	} else {
		return __add_rule(src->s.value, tgt->s.value, cls->s.value, perm ? perm->s.value : -1, effect, not);
	}
	return ret;
}

#define ioctl_driver(x) (x>>8 & 0xFF)
#define ioctl_func(x) (x & 0xFF)

static int __add_xperm_rule(int s, int t, int c, uint16_t low, uint16_t high, int effect, int not) {
	avtab_key_t key;
	avtab_datum_t *av;
	int new_rule = 0;

	key.source_type = s;
	key.target_type = t;
	key.target_class = c;
	key.specified = effect;

	av = avtab_search(&policydb->te_avtab, &key);
	if (av == NULL) {
		av = cmalloc(sizeof(*av));
		av->xperms = cmalloc(sizeof(avtab_extended_perms_t));
		new_rule = 1;
		if (ioctl_driver(low) != ioctl_driver(high)) {
			av->xperms->specified = AVTAB_XPERMS_IOCTLDRIVER;
			av->xperms->driver = 0;
		} else {
			av->xperms->specified = AVTAB_XPERMS_IOCTLFUNCTION;
			av->xperms->driver = ioctl_driver(low);
		}
	}

	if (av->xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
		for (unsigned i = ioctl_driver(low); i <= ioctl_driver(high); ++i) {
			if (not)
				xperm_clear(i, av->xperms->perms);
			else
				xperm_set(i, av->xperms->perms);
		}
	} else {
		for (unsigned i = ioctl_func(low); i <= ioctl_func(high); ++i) {
			if (not)
				xperm_clear(i, av->xperms->perms);
			else
				xperm_set(i, av->xperms->perms);
		}
	}

	if (new_rule) {
		if (avtab_insert(&policydb->te_avtab, &key, av)) {
			fprintf(stderr, "Error inserting into avtab\n");
			return 1;
		}
		free(av);
	}

	return 0;
}

static int add_xperm_rule_auto(type_datum_t *src, type_datum_t *tgt, class_datum_t *cls,
			uint16_t low, uint16_t high, int effect, int not) {
	hashtab_ptr_t cur;
	int ret = 0;

	if (src == NULL) {
		hashtab_for_each(policydb->p_types.table, &cur) {
			src = cur->datum;
			ret |= add_xperm_rule_auto(src, tgt, cls, low, high, effect, not);
		}
	} else if (tgt == NULL) {
		hashtab_for_each(policydb->p_types.table, &cur) {
			tgt = cur->datum;
			ret |= add_xperm_rule_auto(src, tgt, cls, low, high, effect, not);
		}
	} else if (cls == NULL) {
		hashtab_for_each(policydb->p_classes.table, &cur) {
			cls = cur->datum;
			ret |= __add_xperm_rule(src->s.value, tgt->s.value, cls->s.value, low, high, effect, not);
		}
	} else {
		return __add_xperm_rule(src->s.value, tgt->s.value, cls->s.value, low, high, effect, not);
	}
	return ret;
}

int load_policydb(const char *filename) {
	int fd;
	struct stat sb;
	struct policy_file pf;
	void *map;
	int ret;

	if (policydb)
		destroy_policydb();

	policydb = cmalloc(sizeof(*policydb));

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
				filename, strerror(errno));
		return 1;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
				filename, strerror(errno));
		return 1;
	}
	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
				fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't mmap '%s':  %s\n",
				filename, strerror(errno));
		return 1;
	}

	policy_file_init(&pf);
	pf.type = PF_USE_MEMORY;
	pf.data = map;
	pf.len = sb.st_size;
	if (policydb_init(policydb)) {
		fprintf(stderr, "policydb_init: Out of memory!\n");
		return 1;
	}
	ret = policydb_read(policydb, &pf, 0);
	if (ret) {
		fprintf(stderr, "error(s) encountered while parsing configuration\n");
		return 1;
	}

	munmap(map, sb.st_size);
	close(fd);

	return 0;
}

int dump_policydb(const char *filename) {
	int fd, ret;
	void *data = NULL;
	size_t len;
	policydb_to_image(NULL, policydb, &data, &len);
	if (data == NULL) {
		fprintf(stderr, "Fail to dump policy image!");
		return 1;
	}

	fd = creat(filename, 0644);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
		        filename, strerror(errno));
		return 1;
	}
	ret = write(fd, data, len);
	close(fd);
	if (ret < 0) {
		fprintf(stderr, "Could not write policy to %s\n",
		        filename);
		return 1;
	}
	return 0;
}

void destroy_policydb() {
	policydb_destroy(policydb);
	free(policydb);
	policydb = NULL;
}

int create_domain(char *d) {
	symtab_datum_t *src = hashtab_search(policydb->p_types.table, d);
	if(src) {
		fprintf(stderr, "Domain %s already exists\n", d);
		return 0;
	}

	type_datum_t *typedatum = (type_datum_t *) malloc(sizeof(type_datum_t));
	type_datum_init(typedatum);
	typedatum->primary = 1;
	typedatum->flavor = TYPE_TYPE;

	uint32_t value = 0;
	symtab_insert(policydb, SYM_TYPES, strdup(d), typedatum, SCOPE_DECL, 1, &value);
	typedatum->s.value = value;

	if (ebitmap_set_bit(&policydb->global->branch_list->declared.scope[SYM_TYPES], value - 1, 1)) {
		return 1;
	}

	policydb->type_attr_map = realloc(policydb->type_attr_map, sizeof(ebitmap_t) * policydb->p_types.nprim);
	policydb->attr_type_map = realloc(policydb->attr_type_map, sizeof(ebitmap_t) * policydb->p_types.nprim);
	ebitmap_init(&policydb->type_attr_map[value-1]);
	ebitmap_init(&policydb->attr_type_map[value-1]);
	ebitmap_set_bit(&policydb->type_attr_map[value-1], value-1, 1);

	src = hashtab_search(policydb->p_types.table, d);
	if(!src)
		return 1;

	if(policydb_index_decls(NULL, policydb))
		return 1;

	if(policydb_index_classes(policydb))
		return 1;

	if(policydb_index_others(NULL, policydb, 0))
		return 1;

	//Add the domain to all roles
	for(unsigned i=0; i<policydb->p_roles.nprim; ++i) {
		//Not sure all those three calls are needed
		ebitmap_set_bit(&policydb->role_val_to_struct[i]->types.negset, value-1, 0);
		ebitmap_set_bit(&policydb->role_val_to_struct[i]->types.types, value-1, 1);
		type_set_expand(&policydb->role_val_to_struct[i]->types, &policydb->role_val_to_struct[i]->cache, policydb, 0);
	}

	return set_attr("domain", value);
}

int set_domain_state(char* s, int state) {
	type_datum_t *type;
	hashtab_ptr_t cur;
	if (s == NULL) {
		hashtab_for_each(policydb->p_types.table, &cur) {
			type = cur->datum;
			if (ebitmap_set_bit(&policydb->permissive_map, type->s.value, state)) {
				fprintf(stderr, "Could not set bit in permissive map\n");
				return 1;
			}
		}
	} else {
		type = hashtab_search(policydb->p_types.table, s);
		if (type == NULL) {
				fprintf(stderr, "type %s does not exist\n", s);
				return 1;
		}
		if (ebitmap_set_bit(&policydb->permissive_map, type->s.value, state)) {
			fprintf(stderr, "Could not set bit in permissive map\n");
			return 1;
		}
	}

	return 0;
}

int add_transition(char *s, char *t, char *c, char *d) {
	type_datum_t *src, *tgt, *def;
	class_datum_t *cls;

	avtab_key_t key;
	avtab_datum_t *av;
	int new_rule = 0;

	src = hashtab_search(policydb->p_types.table, s);
	if (src == NULL) {
		fprintf(stderr, "source type %s does not exist\n", s);
		return 1;
	}
	tgt = hashtab_search(policydb->p_types.table, t);
	if (tgt == NULL) {
		fprintf(stderr, "target type %s does not exist\n", t);
		return 1;
	}
	cls = hashtab_search(policydb->p_classes.table, c);
	if (cls == NULL) {
		fprintf(stderr, "class %s does not exist\n", c);
		return 1;
	}
	def = hashtab_search(policydb->p_types.table, d);
	if (def == NULL) {
		fprintf(stderr, "default type %s does not exist\n", d);
		return 1;
	}

	key.source_type = src->s.value;
	key.target_type = tgt->s.value;
	key.target_class = cls->s.value;
	key.specified = AVTAB_TRANSITION;
	av = avtab_search(&policydb->te_avtab, &key);
	if (av == NULL) {
		av = cmalloc(sizeof(*av));
		new_rule = 1;
	}

	av->data = def->s.value;

	if (new_rule) {
		if (avtab_insert(&policydb->te_avtab, &key, av)) {
			fprintf(stderr, "Error inserting into avtab\n");
			return 1;
		}
		free(av);
	}
	return 0;
}

int add_file_transition(char *s, char *t, char *c, char *d, char* filename) {
	type_datum_t *src, *tgt, *def;
	class_datum_t *cls;

	src = hashtab_search(policydb->p_types.table, s);
	if (src == NULL) {
		fprintf(stderr, "source type %s does not exist\n", s);
		return 1;
	}
	tgt = hashtab_search(policydb->p_types.table, t);
	if (tgt == NULL) {
		fprintf(stderr, "target type %s does not exist\n", t);
		return 1;
	}
	cls = hashtab_search(policydb->p_classes.table, c);
	if (cls == NULL) {
		fprintf(stderr, "class %s does not exist\n", c);
		return 1;
	}
	def = hashtab_search(policydb->p_types.table, d);
	if (def == NULL) {
		fprintf(stderr, "default type %s does not exist\n", d);
		return 1;
	}

	filename_trans_t trans_key;
	trans_key.stype = src->s.value;
	trans_key.ttype = tgt->s.value;
	trans_key.tclass = cls->s.value;
	trans_key.name = filename;

	filename_trans_datum_t *trans_datum;
	trans_datum = hashtab_search(policydb->p_types.table, (hashtab_key_t) &trans_key);

	if (trans_datum == NULL) {
		trans_datum = cmalloc(sizeof(*trans_datum));
		hashtab_insert(policydb->filename_trans, (hashtab_key_t) &trans_key, trans_datum);
	}

	// Overwrite existing
	trans_datum->otype = def->s.value;
	return 0;
}

int add_typeattribute(char *domainS, char *attr) {
	type_datum_t *domain;

	domain = hashtab_search(policydb->p_types.table, domainS);
	if (domain == NULL) {
		fprintf(stderr, "source type %s does not exist\n", domainS);
		return 1;
	}

	set_attr(attr, domain->s.value);

	int typeId = get_attr_id(attr);
	//Now let's update all constraints!
	//(kernel doesn't support (yet?) type_names rules)
	for(int i=0; i<policydb->p_classes.nprim; ++i) {
		class_datum_t *cl = policydb->class_val_to_struct[i];
		for(constraint_node_t *n = cl->constraints; n ; n=n->next) {
			for(constraint_expr_t *e = n->expr; e; e=e->next) {
				if(e->expr_type == CEXPR_NAMES) {
					if(ebitmap_get_bit(&e->type_names->types, typeId-1)) {
						ebitmap_set_bit(&e->names, domain->s.value-1, 1);
					}
				}
			}
		}
	}
	return 0;
}

int add_rule(char *s, char *t, char *c, char *p, int effect, int not) {
	type_datum_t *src = NULL, *tgt = NULL;
	class_datum_t *cls = NULL;
	perm_datum_t *perm = NULL;

	if (s) {
		src = hashtab_search(policydb->p_types.table, s);
		if (src == NULL) {
			fprintf(stderr, "source type %s does not exist\n", s);
			return 1;
		}
	}

	if (t) {
		tgt = hashtab_search(policydb->p_types.table, t);
		if (tgt == NULL) {
			fprintf(stderr, "target type %s does not exist\n", t);
			return 1;
		}
	}

	if (c) {
		cls = hashtab_search(policydb->p_classes.table, c);
		if (cls == NULL) {
			fprintf(stderr, "class %s does not exist\n", c);
			return 1;
		}
	}

	if (p) {
		if (c == NULL) {
			fprintf(stderr, "No class is specified, cannot add perm [%s] \n", p);
			return 1;
		}

		if (cls != NULL) {
			perm = hashtab_search(cls->permissions.table, p);
			if (perm == NULL && cls->comdatum != NULL) {
				perm = hashtab_search(cls->comdatum->permissions.table, p);
			}
			if (perm == NULL) {
				fprintf(stderr, "perm %s does not exist in class %s\n", p, c);
				return 1;
			}
		}
	}
	return add_rule_auto(src, tgt, cls, perm, effect, not);
}

int add_xperm_rule(char *s, char *t, char *c, char *range, int effect, int not) {
	type_datum_t *src = NULL, *tgt = NULL;
	class_datum_t *cls = NULL;

	if (s) {
		src = hashtab_search(policydb->p_types.table, s);
		if (src == NULL) {
			fprintf(stderr, "source type %s does not exist\n", s);
			return 1;
		}
	}

	if (t) {
		tgt = hashtab_search(policydb->p_types.table, t);
		if (tgt == NULL) {
			fprintf(stderr, "target type %s does not exist\n", t);
			return 1;
		}
	}

	if (c) {
		cls = hashtab_search(policydb->p_classes.table, c);
		if (cls == NULL) {
			fprintf(stderr, "class %s does not exist\n", c);
			return 1;
		}
	}

	uint16_t low, high;

	if (range) {
		if (strchr(range, '-')){
			sscanf(range, "%hx-%hx", &low, &high);
		} else {
			sscanf(range, "%hx", &low);
			high = low;
		}
	} else {
		low = 0;
		high = 0xFFFF;
	}

	return add_xperm_rule_auto(src, tgt, cls, low, high, effect, not);
}


/* Vector */

void vec_init(struct vector *v) {
	if (v == NULL) return;
	vec_size(v) = 0;
	vec_cap(v) = 1;
	vec_entry(v) = malloc(sizeof(void*));
}

void vec_push_back(struct vector *v, void *p) {
	if (v == NULL) return;
	if (vec_size(v) == vec_cap(v)) {
		vec_cap(v) *= 2;
		vec_entry(v) = realloc(vec_entry(v), sizeof(void*) * vec_cap(v));
	}
	vec_entry(v)[vec_size(v)] = p;
	++vec_size(v);
}

void vec_push_back_all(struct vector *v, void *p, ...) {
	va_list argv;
	va_start(argv, p);
	vec_push_back(v, p);
	for (void *arg = va_arg(argv, char*); arg; arg = va_arg(argv, char*))
		vec_push_back(v, arg);
	va_end(argv);
}

void *vec_pop_back(struct vector *v) {
	void *ret = vec_entry(v)[vec_size(v) - 1];
	--vec_size(v);
	return ret;
}

static int (*cmp)(const void *, const void *);

static int vec_comp(const void *a, const void *b) {
	void *aa = *((void **)a), *bb = *((void **)b);
	if (aa == NULL && bb == NULL) return 0;
	else if (aa == NULL) return 1;
	else if (bb == NULL) return -1;
	else return cmp ? cmp(aa, bb) : 0;
}

void vec_sort(struct vector *v, int (*compar)(const void *, const void *)) {
	if (v == NULL) return;
	cmp = compar;
	qsort(vec_entry(v), vec_size(v), sizeof(void*), vec_comp);
	void *e;
	vec_for_each_r(v, e) {
		if (e) break;
		--vec_size(v);
	}
}

/* Will cleanup only the vector itself
 * use in cases when each element requires special cleanup 
 */
void vec_destroy(struct vector *v) {
	if (v == NULL) return;
	vec_size(v) = 0;
	vec_cap(v) = 0;
	free(vec_entry(v));
	vec_entry(v) = NULL; // Prevent double destroy segfault
}

/* Will cleanup each element AND the vector itself
 * Shall be the general case
 */
void vec_deep_destroy(struct vector *v) {
	if (v == NULL) return;
	void *e;
	vec_for_each(v, e) {
		free(e);
	}
	vec_destroy(v);
}

void vec_dup(struct vector *v, struct vector *vv) {
	vec_size(vv) = vec_size(v);
	vec_cap(vv) = vec_cap(v);
	vec_entry(vv) = malloc(sizeof(void*) * vec_cap(v));
	memcpy(vec_entry(vv), vec_entry(v), sizeof(void*) * vec_cap(v));
}


/* MagiskPolicy */

static int syntax_err = 0;
static char err_msg[ARG_MAX];

static void statements() {
	fprintf(stderr,
		"One policy statement should be treated as one parameter;\n"
		"this means a full policy statement should be enclosed in quotes;\n"
		"multiple policy statements can be provided in a single command\n"
		"\n"
		"The statements has a format of \"<action> [args...]\"\n"
		"Use '*' in args to represent every possible match.\n"
		"Collections wrapped in curly brackets can also be used as args.\n"
		"\n"
		"Supported policy statements:\n"
		"\n"
		"Type 1:\n"
		"\"<action> source-class target-class permission-class permission\"\n"
		"Action: allow, deny, auditallow, auditdeny\n"
		"\n"
		"Type 2:\n"
		"\"<action> source-class target-class permission-class ioctl range\"\n"
		"Action: allowxperm, auditallowxperm, dontauditxperm\n"
		"\n"
		"Type 3:\n"
		"\"<action> class\"\n"
		"Action: create, permissive, enforcing\n"
		"\n"
		"Type 4:\n"
		"\"attradd class attribute\"\n"
		"\n"
		"Type 5:\n"
		"\"typetrans source-class target-class permission-class default-class (optional: object-name)\"\n"
		"\n"
		"Notes:\n"
		"- typetrans does not support the all match '*' syntax\n"
		"- permission-class cannot be collections\n"
		"- source-class and target-class can also be attributes\n"
		"\n"
		"Example: allow { source1 source2 } { target1 target2 } permission-class *\n"
		"Will be expanded to:\n"
		"\n"
		"allow source1 target1 permission-class { all-permissions }\n"
		"allow source1 target2 permission-class { all-permissions }\n"
		"allow source2 target1 permission-class { all-permissions }\n"
		"allow source2 target2 permission-class { all-permissions }\n"
		"\n"
	);
}

static void magiskpolicy_usage(char *arg0) {
	fprintf(stderr,
		"MagiskPolicy v" xstr(MAGISK_VERSION) "(" xstr(MAGISK_VER_CODE) ") (by topjohnwu)\n\n"
		"Usage: %s [--options...] [policy statements...]\n"
		"\n"
		"Options:\n"
		"   --live            directly apply sepolicy live\n"
		"   --magisk          inject built-in rules for a minimal\n"
		"                     Magisk selinux environment\n"
		"   --load FILE       load policies from FILE\n"
		"   --save FILE       save policies to FILE\n"
		"\n"
		"If neither --load or --compile-split is specified, it will load\n"
		"from current live policies (" SELINUX_POLICY ")\n"
		"\n"
		, arg0);
	statements();
	exit(1);
}

// Pattern 1: action { source } { target } class { permission }
static int parse_pattern_1(int action, char* statement) {
	int state = 0, in_bracket = 0;
	char *tok, *class, *saveptr;
	struct vector source, target, permission;
	vec_init(&source);
	vec_init(&target);
	vec_init(&permission);
	tok = strtok_r(statement, " ", &saveptr);
	while (tok != NULL) {
		if (tok[0] == '{') {
			if (in_bracket || state == 2) return 1;
			in_bracket = 1;
			if (tok[1]) {
				++tok;
				continue;
			}
		} else if (tok[strlen(tok) - 1] == '}') {
			if (!in_bracket || state == 2) return 1;
			in_bracket = 0;
			if (strlen(tok) - 1) {
				tok[strlen(tok) - 1] = '\0';
				continue;
			}
		} else {
			if (tok[0] == '*') tok = ALL;
			struct vector *vec;
			switch (state) {
			case 0:
				vec = &source;
				break;
			case 1:
				vec = &target;
				break;
			case 2:
				vec = NULL;
				class = tok;
				break;
			case 3:
				vec = &permission;
				break;
			default:
				return 1;
			}
			vec_push_back(vec, tok);
		}
		if (!in_bracket) ++state;
		tok = strtok_r(NULL, " ", &saveptr);
	}
	if (state != 4) return 1;
	for(int i = 0; i < source.size; ++i)
		for (int j = 0; j < target.size; ++j)
			for (int k = 0; k < permission.size; ++k) {
				int (*action_func)(char*, char*, char*, char*);
				char *action_str;
				switch (action) {
				case 0:
					action_func = sepol_allow;
					action_str = "allow";
					break;
				case 1:
					action_func = sepol_deny;
					action_str = "deny";
					break;
				case 2:
					action_func = sepol_auditallow;
					action_str = "auditallow";
					break;
				case 3:
					action_func = sepol_auditdeny;
					action_str = "auditdeny";
					break;
				default:
					return 1;
				}
				if (action_func(source.data[i], target.data[j], class, permission.data[k]))
					fprintf(stderr, "Error in: %s %s %s %s %s\n",
						action_str, (char *) source.data[i], (char *) target.data[j], class, (char *) permission.data[k]);
			}
	vec_destroy(&source);
	vec_destroy(&target);
	vec_destroy(&permission);
	return 0;
}

// Pattern 2: action { class } { attribute }
static int parse_pattern_2(int action, char* statement) {
	int state = 0, in_bracket = 0;
	char *tok, *saveptr;
	struct vector class, attribute;
	vec_init(&class);
	vec_init(&attribute);
	tok = strtok_r(statement, " ", &saveptr);
	while (tok != NULL) {
		if (tok[0] == '{') {
			if (in_bracket) return 1;
			in_bracket = 1;
			if (tok[1]) {
				++tok;
				continue;
			}
		} else if (tok[strlen(tok) - 1] == '}') {
			if (!in_bracket) return 1;
			in_bracket = 0;
			if (strlen(tok) - 1) {
				tok[strlen(tok) - 1] = '\0';
				continue;
			}
		} else {
			if (tok[0] == '*') tok = ALL;
			struct vector *vec;
			switch (state) {
			case 0:
				vec = &class;
				break;
			case 1:
				vec = &attribute;
				break;
			default:
				return 1;
			}
			vec_push_back(vec, tok);
		}
		if (!in_bracket) ++state;
		tok = strtok_r(NULL, " ", &saveptr);
	}
	if (state != 2) return 1;
	for(int i = 0; i < class.size; ++i)
		for (int j = 0; j < attribute.size; ++j) {
			int (*action_func)(char*, char*);
			char *action_str;
			switch (action) {
				case 0:
					action_func = sepol_attradd;
					action_str = "attradd";
					break;
				default:
					return 1;
			}
			if (action_func(class.data[i], attribute.data[j]))
				fprintf(stderr, "Error in: %s %s %s\n",
					action_str, (char *) class.data[i], (char *) attribute.data[j]);
		}
	vec_destroy(&class);
	vec_destroy(&attribute);
	return 0;
}

// Pattern 3: action { type }
static int parse_pattern_3(int action, char* statement) {
	char *tok, *saveptr;
	struct vector classes;
	vec_init(&classes);
	tok = strtok_r(statement, " {}", &saveptr);
	while (tok != NULL) {
		if (tok[0] == '*') tok = ALL;
		vec_push_back(&classes, tok);
		tok = strtok_r(NULL, " {}", &saveptr);
	}
	for (int i = 0; i < classes.size; ++i) {
		int (*action_func)(char*);
		char *action_str;
		switch (action) {
		case 0:
			action_func = sepol_create;
			action_str = "create";
			break;
		case 1:
			action_func = sepol_permissive;
			action_str = "permissive";
			break;
		case 2:
			action_func = sepol_enforce;
			action_str = "enforce";
			break;
		}
		if (action_func(classes.data[i]))
			fprintf(stderr, "Error in: %s %s\n", action_str, (char *) classes.data[i]);
	}
	vec_destroy(&classes);
	return 0;
}

// Pattern 4: action source target class default (filename)
static int parse_pattern_4(int action, char* statement) {
	int state = 0;
	char *tok, *saveptr;
	char *source, *target, *class, *def, *filename = NULL;
	tok = strtok_r(statement, " ", &saveptr);
	while (tok != NULL) {
		switch(state) {
		case 0:
			source = tok;
			break;
		case 1:
			target = tok;
			break;
		case 2:
			class = tok;
			break;
		case 3:
			def = tok;
			break;
		case 4:
			filename = tok;
			break;
		default:
			return 1;
		}
		tok = strtok_r(NULL, " ", &saveptr);
		++state;
	}
	if (state < 4) return 1;
	if (sepol_typetrans(source, target, class, def, filename))
		fprintf(stderr, "Error in: typetrans %s %s %s %s %s\n", source, target, class, def, filename ? filename : "");
	return 0;
}

// Pattern 5: action { source } { target } { class } ioctl range
static int parse_pattern_5(int action, char* statement) {
	int state = 0, in_bracket = 0;
	char *tok, *range, *saveptr;
	struct vector source, target, class;
	vec_init(&source);
	vec_init(&target);
	vec_init(&class);
	tok = strtok_r(statement, " ", &saveptr);
	while (tok != NULL) {
		if (tok[0] == '{') {
			if (in_bracket || state == 3 || state == 4) return 1;
			in_bracket = 1;
			if (tok[1]) {
				++tok;
				continue;
			}
		} else if (tok[strlen(tok) - 1] == '}') {
			if (!in_bracket || state == 3 || state == 4) return 1;
			in_bracket = 0;
			if (strlen(tok) - 1) {
				tok[strlen(tok) - 1] = '\0';
				continue;
			}
		} else {
			if (tok[0] == '*') tok = ALL;
			struct vector *vec;
			switch (state) {
			case 0:
				vec = &source;
				break;
			case 1:
				vec = &target;
				break;
			case 2:
				vec = &class;
				break;
			case 3:
				// Should always be ioctl
				vec = NULL;
				break;
			case 4:
				vec = NULL;
				range = tok;
				break;
			default:
				return 1;
			}
			vec_push_back(vec, tok);
		}
		if (!in_bracket) ++state;
		tok = strtok_r(NULL, " ", &saveptr);
	}
	if (state != 5) return 1;
	for(int i = 0; i < source.size; ++i)
		for (int j = 0; j < target.size; ++j)
			for (int k = 0; k < class.size; ++k) {
				int (*action_func)(char*, char*, char*, char*);
				char *action_str;
				switch (action) {
				case 0:
					action_func = sepol_allowxperm;
					action_str = "allowxperm";
					break;
				case 1:
					action_func = sepol_auditallowxperm;
					action_str = "auditallowxperm";
					break;
				case 2:
					action_func = sepol_dontauditxperm;
					action_str = "dontauditxperm";
					break;
				default:
					return 1;
				}
				if (action_func(source.data[i], target.data[j], class.data[k], range))
					fprintf(stderr, "Error in: %s %s %s %s %s\n",
						action_str, (char *) source.data[i], (char *) target.data[j], (char *) class.data[k], range);
			}
	vec_destroy(&source);
	vec_destroy(&target);
	vec_destroy(&class);
	return 0;
}

static void syntax_error_msg() {
	fprintf(stderr, "Syntax error in \"%s\"\n", err_msg);
	syntax_err = 1;
}

int main_magiskpolicy(int argc, char *argv[]) {
	char *outfile = NULL, *tok, *saveptr;
	int magisk = 0;
	struct vector rules;

	vec_init(&rules);

	if (argc < 2) magiskpolicy_usage(argv[0]);
	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] == '-' && argv[i][1] == '-') {
			if (strcmp(argv[i] + 2, "live") == 0)
				outfile = SELINUX_LOAD;
			else if (strcmp(argv[i] + 2, "magisk") == 0)
				magisk = 1;
			else if (strcmp(argv[i] + 2, "load") == 0) {
				if (i + 1 >= argc)
					magiskpolicy_usage(argv[0]);
				if (load_policydb(argv[i + 1])) {
					fprintf(stderr, "Cannot load policy from %s\n", argv[i + 1]);
					return 1;
				}
				++i;
			} else if (strcmp(argv[i] + 2, "save") == 0) {
				if (i + 1 >= argc)
					magiskpolicy_usage(argv[0]);
				outfile = argv[i + 1];
				++i;
			} else {
				magiskpolicy_usage(argv[0]);
			}
		} else {
			vec_push_back(&rules, argv[i]);
		}
	}

	// Use current policy if nothing is loaded
	if(policydb == NULL && load_policydb(SELINUX_POLICY)) {
		fprintf(stderr, "Cannot load policy from " SELINUX_POLICY "\n");
		return 1;
	}

	if (magisk)
		sepol_magisk_rules();

	for (int i = 0; i < rules.size; ++i) {
		// Since strtok will modify the origin string, copy the policy for error messages
		strcpy(err_msg, rules.data[i]);
		tok = strtok_r(rules.data[i], " ", &saveptr);
		if (strcmp(tok, "allow") == 0) {
			if (parse_pattern_1(0, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "deny") == 0) {
			if (parse_pattern_1(1, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "auditallow") == 0) {
			if (parse_pattern_1(2, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "auditdeny") == 0) {
			if (parse_pattern_1(3, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "attradd") == 0) {
			if (parse_pattern_2(0, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "create") == 0) {
			if (parse_pattern_3(0, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "permissive") == 0) {
			if (parse_pattern_3(1, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "enforce") == 0) {
			if (parse_pattern_3(2, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "typetrans") == 0) {
			if (parse_pattern_4(0, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "allowxperm") == 0) {
			if (parse_pattern_5(0, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "auditallowxperm") == 0) {
			if (parse_pattern_5(1, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else if (strcmp(tok, "dontauditxperm") == 0) {
			if (parse_pattern_5(2, rules.data[i] + strlen(tok) + 1))
				syntax_error_msg();
		} else {
			syntax_error_msg();
		}
	}

	if (syntax_err)
		statements();

	vec_destroy(&rules);

	if (outfile && dump_policydb(outfile)) {
		fprintf(stderr, "Cannot dump policy to %s\n", outfile);
		return 1;
	}

	destroy_policydb();
	return 0;
}
