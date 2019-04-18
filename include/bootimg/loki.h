#ifndef __LOKI_H_
#define __LOKI_H_

#define VERSION "2.1"

#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512

#define BOOT_PARTITION      "/dev/block/platform/msm_sdcc.1/by-name/boot"
#define RECOVERY_PARTITION  "/dev/block/platform/msm_sdcc.1/by-name/recovery"
#define ABOOT_PARTITION     "/dev/block/platform/msm_sdcc.1/by-name/aboot"

#define PATTERN1 "\xf0\xb5\x8f\xb0\x06\x46\xf0\xf7"
#define PATTERN2 "\xf0\xb5\x8f\xb0\x07\x46\xf0\xf7"
#define PATTERN3 "\x2d\xe9\xf0\x41\x86\xb0\xf1\xf7"
#define PATTERN4 "\x2d\xe9\xf0\x4f\xad\xf5\xc6\x6d"
#define PATTERN5 "\x2d\xe9\xf0\x4f\xad\xf5\x21\x7d"
#define PATTERN6 "\x2d\xe9\xf0\x4f\xf3\xb0\x05\x46"

#define BOOT_PATTERN1 "\x4f\xf4\x70\x40\xb3\x49\x2d\xe9"	/* Samsung GS4 */
#define BOOT_PATTERN2 "\x2d\xe9\xf0\x4f\xad\xf5\x82\x5d"	/* LG */
#define BOOT_PATTERN3 "\x2d\xe9\xf0\x4f\x4f\xf4\x70\x40"	/* LG */
#define BOOT_PATTERN4 "\x2d\xe9\xf0\x4f\xad\xf5\x80\x5d"	/* LG G2 */

#define ABOOT_BASE_SAMSUNG 0x88dfffd8
#define ABOOT_BASE_LG 0x88efffd8
#define ABOOT_BASE_G2 0xf7fffd8
#define ABOOT_BASE_VIPER 0x40100000

struct boot_img_hdr {
    unsigned char magic[BOOT_MAGIC_SIZE];
    unsigned kernel_size;   /* size in bytes */
    unsigned kernel_addr;   /* physical load addr */
    unsigned ramdisk_size;  /* size in bytes */
    unsigned ramdisk_addr;  /* physical load addr */
    unsigned second_size;   /* size in bytes */
    unsigned second_addr;   /* physical load addr */
    unsigned tags_addr;     /* physical addr for kernel tags */
    unsigned page_size;     /* flash page size we assume */
    unsigned dt_size;       /* device_tree in bytes */
    unsigned unused;        /* future expansion: should be 0 */
    unsigned char name[BOOT_NAME_SIZE];    /* asciiz product name */
    unsigned char cmdline[BOOT_ARGS_SIZE];
    unsigned id[8];         /* timestamp / checksum / sha1 / etc */
};

struct loki_hdr {
    unsigned char magic[4];     /* 0x494b4f4c */
    unsigned int recovery;      /* 0 = boot.img, 1 = recovery.img */
    char build[128];   /* Build number */

    unsigned int orig_kernel_size;
    unsigned int orig_ramdisk_size;
    unsigned int ramdisk_addr;
};

struct target {
	char *vendor;
	char *device;
	char *build;
	unsigned long check_sigs;
	unsigned long hdr;
	int lg;
};

struct target targets[] = {
	{
		.vendor = "AT&T",
		.device = "Samsung Galaxy S4",
		.build = "JDQ39.I337UCUAMDB or JDQ39.I337UCUAMDL",
		.check_sigs = 0x88e0ff98,
		.hdr = 0x88f3bafc,
		.lg = 0,
	},
	{
		.vendor = "Verizon",
		.device = "Samsung Galaxy S4",
		.build = "JDQ39.I545VRUAMDK",
		.check_sigs = 0x88e0fe98,
		.hdr = 0x88f372fc,
		.lg = 0,
	},
	{
		.vendor = "DoCoMo",
		.device = "Samsung Galaxy S4",
		.build = "JDQ39.SC04EOMUAMDI",
		.check_sigs = 0x88e0fcd8,
		.hdr = 0x88f0b2fc,
		.lg = 0,
	},
	{
		.vendor = "Verizon",
		.device = "Samsung Galaxy Stellar",
		.build = "IMM76D.I200VRALH2",
		.check_sigs = 0x88e0f5c0,
		.hdr = 0x88ed32e0,
		.lg = 0,
	},
	{
		.vendor = "Verizon",
		.device = "Samsung Galaxy Stellar",
		.build = "JZO54K.I200VRBMA1",
		.check_sigs = 0x88e101ac,
		.hdr = 0x88ed72e0,
		.lg = 0,
	},
	{
		.vendor = "T-Mobile",
		.device = "LG Optimus F3Q",
		.build = "D52010c",
		.check_sigs = 0x88f1079c,
		.hdr = 0x88f64508,
		.lg = 1,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG Optimus G",
		.build = "L01E20b",
		.check_sigs = 0x88F10E48,
		.hdr = 0x88F54418,
		.lg = 1,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG Optimus it L05E",
		.build = "L05E10d",
		.check_sigs = 0x88f1157c,
		.hdr = 0x88f31e10,
		.lg = 1,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG Optimus G Pro",
		.build = "L04E10f",
		.check_sigs = 0x88f1102c,
		.hdr = 0x88f54418,
		.lg = 1,
	},
	{
		.vendor = "AT&T or HK",
		.device = "LG Optimus G Pro",
		.build = "E98010g or E98810b",
		.check_sigs = 0x88f11084,
		.hdr = 0x88f54418,
		.lg = 1,
	},
	{
		.vendor = "KT, LGU, or SKT",
		.device = "LG Optimus G Pro",
		.build = "F240K10o, F240L10v, or F240S10w",
		.check_sigs = 0x88f110b8,
		.hdr = 0x88f54418,
		.lg = 1,
	},
	{
		.vendor = "KT, LGU, or SKT",
		.device = "LG Optimus LTE 2",
		.build = "F160K20g, F160L20f, F160LV20d, or F160S20f",
		.check_sigs = 0x88f10864,
		.hdr = 0x88f802b8,
		.lg = 1,
	},
	{
		.vendor = "MetroPCS",
		.device = "LG Spirit",
		.build = "MS87010a_05",
		.check_sigs = 0x88f0e634,
		.hdr = 0x88f68194,
		.lg = 1,
	},
	{
		.vendor = "MetroPCS",
		.device = "LG Motion",
		.build = "MS77010f_01",
		.check_sigs = 0x88f1015c,
		.hdr = 0x88f58194,
		.lg = 1,
	},
	{
		.vendor = "Verizon",
		.device = "LG Lucid 2",
		.build = "VS87010B_12",
		.check_sigs = 0x88f10adc,
		.hdr = 0x88f702bc,
		.lg = 1,
	},
	{
		.vendor = "Verizon",
		.device = "LG Spectrum 2",
		.build = "VS93021B_05",
		.check_sigs = 0x88f10c10,
		.hdr = 0x88f84514,
		.lg = 1,
	},
	{
		.vendor = "Boost Mobile",
		.device = "LG Optimus F7",
		.build = "LG870ZV4_06",
		.check_sigs = 0x88f11714,
		.hdr = 0x88f842ac,
		.lg = 1,
	},
	{
		.vendor = "US Cellular",
		.device = "LG Optimus F7",
		.build = "US78011a",
		.check_sigs = 0x88f112c8,
		.hdr = 0x88f84518,
		.lg = 1,
	},
	{
		.vendor = "Sprint",
		.device = "LG Optimus F7",
		.build = "LG870ZV5_02",
		.check_sigs = 0x88f11710,
		.hdr = 0x88f842a8,
		.lg = 1,
	},
	{
		.vendor = "Virgin Mobile",
		.device = "LG Optimus F3",
		.build = "LS720ZV5",
		.check_sigs = 0x88f108f0,
		.hdr = 0x88f854f4,
		.lg = 1,
	},
	{
		.vendor = "T-Mobile and MetroPCS",
		.device = "LG Optimus F3",
		.build = "LS720ZV5",
		.check_sigs = 0x88f10264,
		.hdr = 0x88f64508,
		.lg = 1,
	},
	{
		.vendor = "AT&T",
		.device = "LG G2",
		.build = "D80010d",
		.check_sigs = 0xf8132ac,
		.hdr = 0xf906440,
		.lg = 1,
	},
	{
		.vendor = "Verizon",
		.device = "LG G2",
		.build = "VS98010b",
		.check_sigs = 0xf8131f0,
		.hdr = 0xf906440,
		.lg = 1,
	},
	{
		.vendor = "AT&T",
		.device = "LG G2",
		.build = "D80010o",
		.check_sigs = 0xf813428,
		.hdr = 0xf904400,
		.lg = 1,
	},
	{
		.vendor = "Verizon",
		.device = "LG G2",
		.build = "VS98012b",
		.check_sigs = 0xf813210,
		.hdr = 0xf906440,
		.lg = 1,
	},
	{
		.vendor = "T-Mobile or Canada",
		.device = "LG G2",
		.build = "D80110c or D803",
		.check_sigs = 0xf813294,
		.hdr = 0xf906440,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG G2",
		.build = "D802b",
		.check_sigs = 0xf813a70,
		.hdr = 0xf9041c0,
		.lg = 1,
	},
	{
		.vendor = "Sprint",
		.device = "LG G2",
		.build = "LS980ZV7",
		.check_sigs = 0xf813460,
		.hdr = 0xf9041c0,
		.lg = 1,
	},
	{
		.vendor = "KT or LGU",
		.device = "LG G2",
		.build = "F320K, F320L",
		.check_sigs = 0xf81346c,
		.hdr = 0xf8de440,
		.lg = 1,
	},
	{
		.vendor = "SKT",
		.device = "LG G2",
		.build = "F320S",
		.check_sigs = 0xf8132e4,
		.hdr = 0xf8ee440,
		.lg = 1,
	},
	{
		.vendor = "SKT",
		.device = "LG G2",
		.build = "F320S11c",
		.check_sigs = 0xf813470,
		.hdr = 0xf8de440,
		.lg = 1,
	},
	{
		.vendor = "DoCoMo",
		.device = "LG G2",
		.build = "L-01F",
		.check_sigs = 0xf813538,
		.hdr = 0xf8d41c0,
		.lg = 1,
	},
	{
		.vendor = "KT",
		.device = "LG G Flex",
		.build = "F340K",
		.check_sigs = 0xf8124a4,
		.hdr = 0xf8b6440,
		.lg = 1,
	},
	{
		.vendor = "KDDI",
		.device = "LG G Flex",
		.build = "LGL2310d",
		.check_sigs = 0xf81261c,
		.hdr = 0xf8b41c0,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG Optimus F5",
		.build = "P87510e",
		.check_sigs = 0x88f10a9c,
		.hdr = 0x88f702b8,
		.lg = 1,
	},
	{
		.vendor = "SKT",
		.device = "LG Optimus LTE 3",
		.build = "F260S10l",
		.check_sigs = 0x88f11398,
		.hdr = 0x88f8451c,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG G Pad 8.3",
		.build = "V50010a",
		.check_sigs = 0x88f10814,
		.hdr = 0x88f801b8,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG G Pad 8.3",
		.build = "V50010c or V50010e",
		.check_sigs = 0x88f108bc,
		.hdr = 0x88f801b8,
		.lg = 1,
	},
	{
		.vendor = "Verizon",
		.device = "LG G Pad 8.3",
		.build = "VK81010c",
		.check_sigs = 0x88f11080,
		.hdr = 0x88fd81b8,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG Optimus L9 II",
		.build = "D60510a",
		.check_sigs = 0x88f10d98,
		.hdr = 0x88f84aa4,
		.lg = 1,
	},
	{
		.vendor = "MetroPCS",
		.device = "LG Optimus F6",
		.build = "MS50010e",
		.check_sigs = 0x88f10260,
		.hdr = 0x88f70508,
		.lg = 1,
	},
	{
		.vendor = "Open EU",
		.device = "LG Optimus F6",
		.build = "D50510a",
		.check_sigs = 0x88f10284,
		.hdr = 0x88f70aa4,
		.lg = 1,
	},
	{
		.vendor = "KDDI",
		.device = "LG Isai",
		.build = "LGL22",
		.check_sigs = 0xf813458,
		.hdr = 0xf8d41c0,
		.lg = 1,
	},
	{
		.vendor = "KDDI",
		.device = "LG",
		.build = "LGL21",
		.check_sigs = 0x88f10218,
		.hdr = 0x88f50198,
		.lg = 1,
	},
	{
		.vendor = "KT",
		.device = "LG Optimus GK",
		.build = "F220K",
		.check_sigs = 0x88f11034,
		.hdr = 0x88f54418,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG Vu 3",
		.build = "F300L",
		.check_sigs = 0xf813170,
		.hdr = 0xf8d2440,
		.lg = 1,
	},
	{
		.vendor = "Sprint",
		.device = "LG Viper",
		.build = "LS840ZVK",
		.check_sigs = 0x4010fe18,
		.hdr = 0x40194198,
		.lg = 1,
	},
	{
		.vendor = "International",
		.device = "LG G Flex",
		.build = "D95510a",
		.check_sigs = 0xf812490,
		.hdr = 0xf8c2440,
		.lg = 1,
	},
	{
		.vendor = "Sprint",
		.device = "LG Mach",
		.build = "LS860ZV7",
		.check_sigs = 0x88f102b4,
		.hdr = 0x88f6c194,
		.lg = 1,
	},
};

int loki_patch(const char* partition_label, const char* aboot_image, const char* in_image, const char* out_image);
int loki_flash(const char* partition_label, const char* loki_image);
int loki_find(const char* aboot_image);
int loki_unlok(const char* in_image, const char* out_image);

#define PATCH	"\xfe\xb5"			\
				"\x0d\x4d"			\
				"\xd5\xf8"			\
				"\x88\x04"			\
				"\xab\x68"			\
				"\x98\x42"			\
				"\x12\xd0"			\
				"\xd5\xf8"			\
				"\x90\x64"			\
				"\x0a\x4c"			\
				"\xd5\xf8"			\
				"\x8c\x74"			\
				"\x07\xf5\x80\x57"	\
				"\x0f\xce"			\
				"\x0f\xc4"			\
				"\x10\x3f"			\
				"\xfb\xdc"			\
				"\xd5\xf8"			\
				"\x88\x04"			\
				"\x04\x49"			\
				"\xd5\xf8"			\
				"\x8c\x24"			\
				"\xa8\x60"			\
				"\x69\x61"			\
				"\x2a\x61"			\
				"\x00\x20"			\
				"\xfe\xbd"			\
				"\xff\xff\xff\xff"	\
				"\xee\xee\xee\xee"

#endif //__LOKI_H_
