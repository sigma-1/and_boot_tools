/* 
 * File:   elftool.c
 * Author: srl3gx@gmail.com
 *
 * Packing and unpacking boot image of sony mobile devices
 * https://forum.xda-developers.com/xperia-j-e/development/arm-elftool-pack-unpack-boot-image-sony-t2146022
 * 
 * Thanks to sony for providing boot image format in packelf.py
 * 
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <elfboot.h>

void handlePackElf(int, char **);
void handleUnpackElf(int, char **);
void usage_elftool();
unsigned int getAddressFromHeader(char *);

long getFileSize(FILE *);
void writeElfHeader(FILE *, unsigned int, int);

struct elfphdr part_headers[5];

struct file {
	char *file_path;
	unsigned int address;
	unsigned int size;
	char *flag;
	unsigned int offset;
};

void writeElfPHeader(FILE *, struct file);

int main_elftool(int argc, char **argv)
{
	if (argc <= 1) {
		usage_elftool();
	}
	char *arg = argv[1];
	if (strcmp(arg, "pack") == 0) {
		printf("Packing ELF file...\n");
		handlePackElf(argc, argv);
	} else if (strcmp(arg, "unpack") == 0) {
		printf("Unpacking ELF file...\n");
		handleUnpackElf(argc, argv);
	} else if (strcmp(arg, "help") == 0) {
		usage_elftool();
	} else {
		printf("Error: Invalid format.\n");
		usage_elftool();
	}
	return 0;
}

void handlePackElf(int argc, char **argv)
{
	struct file files[argc - 1];
	char *output_path = "./";
	FILE *header;
	FILE *temp_file;
	int parts = 0;
	int offset = 4096;
	for (int i = 2; i < argc; i++) {
		char *arg = argv[i];
		char *arguments[3];
		if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
			i++;
			output_path = argv[i];
			continue;
		}
		arg = strtok(arg, "@,=");
		int k = 0;
		while (arg != NULL) {
			arguments[k] = arg;
			arg = strtok(NULL, "@,");
			k++;
		}
		long address;
		if (strcmp(arguments[1], "cmdline") == 0) {
			address = 0L;
			arguments[2] = "cmdline";
		} else if (strcmp(arguments[0], "header") == 0) {
			header = fopen(arguments[1], "rb");
			struct elf_header boot_header;
			fseek(header, 0, SEEK_SET);
			fread(&boot_header, elf_header_size, 1, header);
			if (memcmp(boot_header.e_ident, elf_magic, 8) != 0) {
				printf
				    ("Error: Header file is not a valid ELF image header.\n");
				exit(EXIT_FAILURE);
			}
			int offset = 52;
			for (int i = 0; i < boot_header.e_phnum; i++) {
				struct elfphdr part_header;
				fseek(header, offset, SEEK_SET);
				fread(&part_header, elf_p_header_size, 1,
				      header);
				part_headers[i] = part_header;
				offset += 32;
			}
			fclose(header);
			continue;
		} else {
			address = strtol(arguments[1], NULL, 16);
			if (address == 0) {
				if (strlen(arguments[1]) == 0) {
					arguments[1] = "kernel";
				}
				arguments[2] = arguments[1];
				address = getAddressFromHeader(arguments[1]);
			}
		}
		printf("Reading file %s\n", arguments[0]);
		temp_file = fopen(arguments[0], "r");
		if (temp_file == NULL) {
			printf("Failed to open %s\n", arguments[0]);
			exit(EXIT_FAILURE);
		}
		long size = getFileSize(temp_file);
		struct file f = {
			arguments[0],
			(unsigned int)address,
			(unsigned int)size,
			arguments[2],
			(unsigned int)offset
		};
		offset += size;
		fclose(temp_file);
		files[parts] = f;
		parts++;
	}

	if (parts < 2) {
		printf("Error: Kernel and ramdisk must be specified.\n");
		usage_elftool();
	}

	FILE *output_file = fopen(output_path, "wb");

	if (output_file == NULL) {
		printf("Error: Invalid path %s\n", output_path);
	}

	writeElfHeader(output_file, files[0].address, parts);

	for (int i = 0; i < parts; i++) {
		writeElfPHeader(output_file, files[i]);
	}
	for (int i = 0; i < parts; i++) {
		struct file current_file = files[i];
		fseek(output_file, current_file.offset, SEEK_SET);
		printf("Writing file : %s to ELF image\n",
		       current_file.file_path);
		temp_file = fopen(current_file.file_path, "r");
		if (temp_file == NULL) {
			printf("Error: Cannot read file %s\n",
			       current_file.file_path);
			exit(EXIT_FAILURE);
		}
		int size = getFileSize(temp_file);
		unsigned char *data = malloc(sizeof size);
		fseek(temp_file, 0, SEEK_SET);
		fread(data, size, 1, temp_file);
		fclose(temp_file);
		fwrite(data, size, 1, output_file);
	}
	fclose(output_file);
}

void writeElfHeader(FILE * file, unsigned int address, int number)
{
	printf("Writing ELF header\t address : %x \t number : %i\n", address,
	       number);
	struct elf_header header = {
		{ 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x61 },
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		2,
		40,
		1,
		address,
		52,
		0,
		0,
		52,
		32,
		(short unsigned int)number,
		0,
		0,
		0
	};
	fwrite((char *)&header, sizeof(header), 1, file);
}

void writeElfPHeader(FILE * file, struct file f)
{
	printf("Writing part header for %s\t", f.file_path);
	long flags;
	long type = 1;
	if (strcmp(f.flag, "ramdisk") == 0) {
		printf("Found ramdisk\n");
		flags = 0x80000000;
	} else if (strcmp(f.flag, "ipl") == 0) {
		printf("Found ipl\n");
		flags = 0x40000000;
	} else if (strcmp(f.flag, "cmdline") == 0) {
		printf("Found cmdline\n");
		flags = 0x20000000;
		type = 4;
	} else if (strcmp(f.flag, "rpm") == 0) {
		printf("Found rpm\n");
		flags = 0x01000000;
	} else {
		printf("Using zero flag\n");
		flags = 0;
	}
	printf("Write part header part:%s offset:%i address:%x, size:%i\n",
	       f.flag, f.offset, f.address, f.size);
	struct elfphdr phdr = {
		(unsigned int)type,
		f.offset,
		f.address,
		f.address,
		f.size,
		f.size,
		(unsigned int)flags,
		0
	};
	fwrite((char *)&phdr, sizeof(phdr), 1, file);
}

long getFileSize(FILE * file)
{
	fseek(file, 0, SEEK_END);
	return ftell(file);
}

void handleUnpackElf(int argc, char **argv)
{

	char *input_path = NULL;
	char *output_path = "./";
	char out_name[PATH_MAX];
	int pagesize = 4096;

	for (int i = 2; i < argc; i += 2) {
		char *arg = argv[i];
		if (strcmp(arg, "-i") == 0 || strcmp(arg, "--input") == 0) {
			input_path = argv[i + 1];
		} else if (strcmp(arg, "-o") == 0
			   || strcmp(arg, "--output") == 0) {
			output_path = argv[i + 1];
		}
	}

	if (strlen(input_path) == 0) {
		return usage_elftool();
	}
	if (strlen(output_path) == 0) {
		printf("Error: Output path must be specified.\n");
		return usage_elftool();
	}

	int offset = 0;
	FILE *temp;

	FILE *input_file = fopen(input_path, "rb");

	if (input_file == NULL) {
		printf("Error: Cannot read input boot image %s.\n", input_path);
	}

	fseek(input_file, offset, SEEK_SET);
	struct elf_header header;
	fread(&header, elf_header_size, 1, input_file);
	offset += elf_header_size;

	if (memcmp(elf_magic, header.e_ident, elf_magic_size) != 0) {
		printf("Error: ELF magic not found.\n");
		exit(EXIT_FAILURE);
	}

	int number_of_parts = header.e_phnum;
	printf("Found %i parts in ELF image\n", number_of_parts);

	struct elfphdr pheaders[number_of_parts];

	for (int i = 0; i < number_of_parts; i++) {
		fseek(input_file, offset, SEEK_SET);
		fread(&pheaders[i], elf_p_header_size, 1, input_file);
		offset += elf_p_header_size;
	}

	//dump header
	printf("Writing header....\n");
	unsigned char *fileBuffer = (unsigned char *)malloc(pagesize);
	fseek(input_file, 0, SEEK_SET);
	fread(fileBuffer, pagesize, 1, input_file);
	sprintf(out_name, "%s/header", output_path);
	temp = fopen(out_name, "w+");
	fwrite(fileBuffer, pagesize, 1, temp);
	fclose(temp);
	free(fileBuffer);
	printf("Done...\n");

	for (int i = 0; i < number_of_parts; i++) {
		struct elfphdr pheader = pheaders[i];
		printf("flag : %u\n", pheader.p_flags);
		printf("offset : %i\n", pheader.p_offset);
		printf("size : %i\n", pheader.p_memsz);
		char *name;
		switch (pheader.p_flags) {
		case p_flags_cmdline:
			name = "cmdline";
			break;
		case p_flags_kernel:
			name = "kernel";
			break;
		case p_flags_ipl:
			name = "ipl";
			break;
		case p_flags_rpm:
			name = "rpm";
		case p_flags_ramdisk:
			name = "ramdisk.cpio.gz";
		}
		sprintf(out_name, "%s/%s", output_path, name);
		printf("%s found at offset %i with size %i\n", name,
		       pheader.p_offset, pheader.p_memsz);
		temp = fopen(out_name, "w+");
		unsigned char *buffer =
		    (unsigned char *)malloc(pheader.p_memsz);
		fseek(input_file, pheader.p_offset, SEEK_SET);
		fread(buffer, pheader.p_memsz, 1, input_file);
		fwrite(buffer, pheader.p_memsz, 1, temp);
		fclose(temp);
		free(buffer);
	}
	fclose(input_file);
}

unsigned int getAddressFromHeader(char *flag)
{
	unsigned int part_flag;
	if (strcmp(flag, "cmdline") == 0) {
		part_flag = p_flags_cmdline;
	} else if (strcmp(flag, "kernel") == 0) {
		part_flag = p_flags_kernel;
	} else if (strcmp(flag, "ramdisk") == 0) {
		part_flag = p_flags_ramdisk;
	} else if (strcmp(flag, "rpm") == 0) {
		part_flag = p_flags_rpm;
	} else if (strcmp(flag, "ipl") == 0) {
		part_flag = p_flags_ipl;
	} else {
		printf("Error: Unknown flag: %s\n", flag);
		exit(EXIT_FAILURE);
	}
	for (int i = 0; i < 5; i++) {
		struct elfphdr part_header;
		part_header = part_headers[i];
		if (part_header.p_flags == part_flag) {
			return part_header.p_paddr;
		}
	}
	printf("Error: Address of %x cannot be read from header file.\n",
	       part_flag);
	exit(EXIT_FAILURE);
}

void usage_elftool()
{
	printf("Usage: elftool pack|unpack -options <arguments>\n\n");
	printf("       unpack  Unpack ELF file.\n");
	printf("               -i <input-file> [ -o <output-dir> ]\n\n");
	printf("       pack    Pack ELF file.\n");
	printf
	    ("               -o <output-file> [header=<file>] <file>[@<address>],<flag> <file>@cmdline\n\n");
	printf("               If header file is present:\n");
	printf("                  header=<header>\n");
	printf("                  <kernel>,kernel\n");
	printf("                  <ramdisk>,ramdisk\n");
	printf("                [ <ipl>,ipl ]\n");
	printf("                [ <rpm>,rpm ]\n");
	printf("                  <cmdline>@cmdline\n\n");
	printf
	    ("                If header file is not present you must specify each address manually:\n");
	printf("                  <kernel>@<kernel-address>,kernel\n");
	printf("                  <ramdisk>@<ramdisk-address>,ramdisk\n");
	printf("                [ <ipl>@<ipl-address>,ipl ]\n");
	printf("                [ <rpm>@<rpm-address>,rpm ]\n");
	printf("                  <cmdline>@cmdline\n\n");
	printf("       help     This help screen.\n\n");
	exit(EXIT_FAILURE);
}
