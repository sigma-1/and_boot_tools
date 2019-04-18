/*
 * loki_patch
 *
 * A utility to patch unsigned boot and recovery images to make
 * them suitable for booting on the AT&T/Verizon Samsung
 * Galaxy S4, Galaxy Stellar, and various locked LG devices
 *
 * by Dan Rosenberg (@djrbliss)
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <bootimg/loki.h>

static unsigned char patch[] = PATCH;

int loki_find(const char* aboot_image)
{
    int aboot_fd;
    struct stat st;
    void *aboot, *ptr;
    unsigned long aboot_base, check_sigs, boot_mmc;

    aboot_fd = open(aboot_image, O_RDONLY);
    if (aboot_fd < 0) {
        printf("[-] Failed to open %s for reading.\n", aboot_image);
        return 1;
    }

    if (fstat(aboot_fd, &st)) {
        printf("[-] fstat() failed.\n");
        return 1;
    }

    aboot = mmap(0, (st.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
    if (aboot == MAP_FAILED) {
        printf("[-] Failed to mmap aboot.\n");
        return 1;
    }

    check_sigs = 0;
    aboot_base = *(unsigned int *)(aboot + 12) - 0x28;

    /* Do a pass to find signature checking function */
    for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
        if (!memcmp(ptr, PATTERN1, 8) ||
            !memcmp(ptr, PATTERN2, 8) ||
            !memcmp(ptr, PATTERN3, 8) ||
            !memcmp(ptr, PATTERN4, 8) ||
            !memcmp(ptr, PATTERN5, 8)) {

            check_sigs = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
            break;
        }

        if (!memcmp(ptr, PATTERN6, 8)) {

            check_sigs = (unsigned long)ptr - (unsigned long)aboot + aboot_base;

            /* Don't break, because the other LG patterns override this one */
            continue;
        }
    }

    if (!check_sigs) {
        printf("[-] Could not find signature checking function.\n");
        return 1;
    }

    printf("[+] Signature check function: %.08lx\n", check_sigs);

    boot_mmc = 0;

    /* Do a second pass for the boot_linux_from_emmc function */
    for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
        if (!memcmp(ptr, BOOT_PATTERN1, 8) ||
            !memcmp(ptr, BOOT_PATTERN2, 8) ||
            !memcmp(ptr, BOOT_PATTERN3, 8) ||
            !memcmp(ptr, BOOT_PATTERN4, 8)) {

            boot_mmc = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
            break;
        }
    }

    if (!boot_mmc) {
        printf("[-] Could not find boot_linux_from_mmc.\n");
        return 1;
    }

    printf("[+] boot_linux_from_mmc: %.08lx\n", boot_mmc);

    return 0;
}

int loki_flash(const char* partition_label, const char* loki_image)
{
    int ifd, aboot_fd, ofd, recovery, offs, match;
    void *orig, *aboot, *patch;
    struct stat st;
    struct boot_img_hdr *hdr;
    struct loki_hdr *loki_hdr;
    char outfile[1024];

    if (!strcmp(partition_label, "boot")) {
        recovery = 0;
    } else if (!strcmp(partition_label, "recovery")) {
        recovery = 1;
    } else {
        printf("[+] First argument must be \"boot\" or \"recovery\".\n");
        return 1;
    }

    /* Verify input file */
    aboot_fd = open(ABOOT_PARTITION, O_RDONLY);
    if (aboot_fd < 0) {
        printf("[-] Failed to open aboot for reading.\n");
        return 1;
    }

    ifd = open(loki_image, O_RDONLY);
    if (ifd < 0) {
        printf("[-] Failed to open %s for reading.\n", loki_image);
        return 1;
    }

    /* Map the image to be flashed */
    if (fstat(ifd, &st)) {
        printf("[-] fstat() failed.\n");
        return 1;
    }

    orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, ifd, 0);
    if (orig == MAP_FAILED) {
        printf("[-] Failed to mmap Loki image.\n");
        return 1;
    }

    hdr = orig;
    loki_hdr = orig + 0x400;

    /* Verify this is a Loki image */
    if (memcmp(loki_hdr->magic, "LOKI", 4)) {
        printf("[-] Input file is not a Loki image.\n");
        return 1;
    }

    /* Verify this is the right type of image */
    if (loki_hdr->recovery != recovery) {
        printf("[-] Loki image is not a %s image.\n", recovery ? "recovery" : "boot");
        return 1;
    }

    /* Verify the to-be-patched address matches the known code pattern */
    aboot = mmap(0, 0x40000, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
    if (aboot == MAP_FAILED) {
        printf("[-] Failed to mmap aboot.\n");
        return 1;
    }

    match = 0;

    for (offs = 0; offs < 0x10; offs += 0x4) {

        patch = NULL;

        if (hdr->ramdisk_addr > ABOOT_BASE_LG)
            patch = hdr->ramdisk_addr - ABOOT_BASE_LG + aboot + offs;
        else if (hdr->ramdisk_addr > ABOOT_BASE_SAMSUNG)
            patch = hdr->ramdisk_addr - ABOOT_BASE_SAMSUNG + aboot + offs;
        else if (hdr->ramdisk_addr > ABOOT_BASE_VIPER)
            patch = hdr->ramdisk_addr - ABOOT_BASE_VIPER + aboot + offs;
        else if (hdr->ramdisk_addr > ABOOT_BASE_G2)
            patch = hdr->ramdisk_addr - ABOOT_BASE_G2 + aboot + offs;

        if (patch < aboot || patch > aboot + 0x40000 - 8) {
            printf("[-] Invalid .lok file.\n");
            return 1;
        }

        if (!memcmp(patch, PATTERN1, 8) ||
            !memcmp(patch, PATTERN2, 8) ||
            !memcmp(patch, PATTERN3, 8) ||
            !memcmp(patch, PATTERN4, 8) ||
            !memcmp(patch, PATTERN5, 8) ||
            !memcmp(patch, PATTERN6, 8)) {

            match = 1;
            break;
        }
    }

    if (!match) {
        printf("[-] Loki aboot version does not match device.\n");
        return 1;
    }

    printf("[+] Loki validation passed, flashing image.\n");

    snprintf(outfile, sizeof(outfile),
             "%s",
             recovery ? RECOVERY_PARTITION : BOOT_PARTITION);

    ofd = open(outfile, O_WRONLY);
    if (ofd < 0) {
        printf("[-] Failed to open output block device.\n");
        return 1;
    }

    if (write(ofd, orig, st.st_size) != st.st_size) {
        printf("[-] Failed to write to block device.\n");
        return 1;
    }

    printf("[+] Loki flashing complete!\n");

    close(ifd);
    close(aboot_fd);
    close(ofd);

    return 0;
}

int patch_shellcode(unsigned int header, unsigned int ramdisk)
{

    unsigned int i;
    int found_header, found_ramdisk;
    unsigned int *ptr;

    found_header = 0;
    found_ramdisk = 0;

    for (i = 0; i < sizeof(patch); i++) {
        ptr = (unsigned int *)&patch[i];
        if (*ptr == 0xffffffff) {
            *ptr = header;
            found_header = 1;
        }

        if (*ptr == 0xeeeeeeee) {
            *ptr = ramdisk;
            found_ramdisk = 1;
        }
    }

    if (found_header && found_ramdisk)
        return 0;

    return -1;
}

int loki_patch(const char* partition_label, const char* aboot_image, const char* in_image, const char* out_image)
{
    int ifd, ofd, aboot_fd, pos, i, recovery, offset, fake_size;
    unsigned int orig_ramdisk_size, orig_kernel_size, page_kernel_size, page_ramdisk_size, page_size, page_mask;
    unsigned long target, aboot_base;
    void *orig, *aboot, *ptr;
    struct target *tgt;
    struct stat st;
    struct boot_img_hdr *hdr;
    struct loki_hdr *loki_hdr;
    char *buf;

    if (!strcmp(partition_label, "boot")) {
        recovery = 0;
    } else if (!strcmp(partition_label, "recovery")) {
        recovery = 1;
    } else {
        printf("[+] First argument must be \"boot\" or \"recovery\".\n");
        return 1;
    }

    /* Open input files */
    aboot_fd = open(aboot_image, O_RDONLY);
    if (aboot_fd < 0) {
        printf("[-] Failed to open %s for reading.\n", aboot_image);
        return 1;
    }

    ifd = open(in_image, O_RDONLY);
    if (ifd < 0) {
        printf("[-] Failed to open %s for reading.\n", in_image);
        return 1;
    }

    ofd = open(out_image, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (ofd < 0) {
        printf("[-] Failed to open %s for writing.\n", out_image);
        return 1;
    }

    /* Find the signature checking function via pattern matching */
    if (fstat(aboot_fd, &st)) {
        printf("[-] fstat() failed.\n");
        return 1;
    }

    aboot = mmap(0, (st.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, aboot_fd, 0);
    if (aboot == MAP_FAILED) {
        printf("[-] Failed to mmap aboot.\n");
        return 1;
    }

    target = 0;
    aboot_base = *(unsigned int *)(aboot + 12) - 0x28;

    for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
        if (!memcmp(ptr, PATTERN1, 8) ||
            !memcmp(ptr, PATTERN2, 8) ||
            !memcmp(ptr, PATTERN3, 8) ||
            !memcmp(ptr, PATTERN4, 8) ||
            !memcmp(ptr, PATTERN5, 8)) {

            target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
            break;
        }
    }

    /* Do a second pass for the second LG pattern. This is necessary because
     * apparently some LG models have both LG patterns, which throws off the
     * fingerprinting. */

    if (!target) {
        for (ptr = aboot; ptr < aboot + st.st_size - 0x1000; ptr++) {
            if (!memcmp(ptr, PATTERN6, 8)) {

                target = (unsigned long)ptr - (unsigned long)aboot + aboot_base;
                break;
            }
        }
    }

    if (!target) {
        printf("[-] Failed to find function to patch.\n");
        return 1;
    }

    tgt = NULL;

    for (i = 0; i < (sizeof(targets)/sizeof(targets[0])); i++) {
        if (targets[i].check_sigs == target) {
            tgt = &targets[i];
            break;
        }
    }

    if (!tgt) {
        printf("[-] Unsupported aboot image.\n");
        return 1;
    }

    printf("[+] Detected target %s %s build %s\n", tgt->vendor, tgt->device, tgt->build);

    /* Map the original boot/recovery image */
    if (fstat(ifd, &st)) {
        printf("[-] fstat() failed.\n");
        return 1;
    }

    orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ|PROT_WRITE, MAP_PRIVATE, ifd, 0);
    if (orig == MAP_FAILED) {
        printf("[-] Failed to mmap input file.\n");
        return 1;
    }

    hdr = orig;
    loki_hdr = orig + 0x400;

    if (!memcmp(loki_hdr->magic, "LOKI", 4)) {
        printf("[-] Input file is already a Loki image.\n");

        /* Copy the entire file to the output transparently */
        if (write(ofd, orig, st.st_size) != st.st_size) {
            printf("[-] Failed to copy Loki image.\n");
            return 1;
        }

        printf("[+] Copied Loki image to %s.\n", out_image);

        return 0;
    }

    /* Set the Loki header */
    memcpy(loki_hdr->magic, "LOKI", 4);
    loki_hdr->recovery = recovery;
    strncpy(loki_hdr->build, tgt->build, sizeof(loki_hdr->build) - 1);

    page_size = hdr->page_size;
    page_mask = hdr->page_size - 1;

    orig_kernel_size = hdr->kernel_size;
    orig_ramdisk_size = hdr->ramdisk_size;

    printf("[+] Original kernel address: %.08x\n", hdr->kernel_addr);
    printf("[+] Original ramdisk address: %.08x\n", hdr->ramdisk_addr);

    /* Store the original values in unused fields of the header */
    loki_hdr->orig_kernel_size = orig_kernel_size;
    loki_hdr->orig_ramdisk_size = orig_ramdisk_size;
    loki_hdr->ramdisk_addr = hdr->kernel_addr + ((hdr->kernel_size + page_mask) & ~page_mask);

    if (patch_shellcode(tgt->hdr, hdr->ramdisk_addr) < 0) {
        printf("[-] Failed to patch shellcode.\n");
        return 1;
    }

    /* Ramdisk must be aligned to a page boundary */
    hdr->kernel_size = ((hdr->kernel_size + page_mask) & ~page_mask) + hdr->ramdisk_size;

    /* Guarantee 16-byte alignment */
    offset = tgt->check_sigs & 0xf;

    hdr->ramdisk_addr = tgt->check_sigs - offset;

    if (tgt->lg) {
        fake_size = page_size;
        hdr->ramdisk_size = page_size;
    }
    else {
        fake_size = 0x200;
        hdr->ramdisk_size = 0;
    }

    /* Write the image header */
    if (write(ofd, orig, page_size) != page_size) {
        printf("[-] Failed to write header to output file.\n");
        return 1;
    }

    page_kernel_size = (orig_kernel_size + page_mask) & ~page_mask;

    /* Write the kernel */
    if (write(ofd, orig + page_size, page_kernel_size) != page_kernel_size) {
        printf("[-] Failed to write kernel to output file.\n");
        return 1;
    }

    page_ramdisk_size = (orig_ramdisk_size + page_mask) & ~page_mask;

    /* Write the ramdisk */
    if (write(ofd, orig + page_size + page_kernel_size, page_ramdisk_size) != page_ramdisk_size) {
        printf("[-] Failed to write ramdisk to output file.\n");
        return 1;
    }

    /* Write fake_size bytes of original code to the output */
    buf = malloc(fake_size);
    if (!buf) {
        printf("[-] Out of memory.\n");
        return 1;
    }

    lseek(aboot_fd, tgt->check_sigs - aboot_base - offset, SEEK_SET);
    read(aboot_fd, buf, fake_size);

    if (write(ofd, buf, fake_size) != fake_size) {
        printf("[-] Failed to write original aboot code to output file.\n");
        return 1;
    }

    /* Save this position for later */
    pos = lseek(ofd, 0, SEEK_CUR);

    /* Write the device tree if needed */
    if (hdr->dt_size) {

        printf("[+] Writing device tree.\n");

        if (write(ofd, orig + page_size + page_kernel_size + page_ramdisk_size, hdr->dt_size) != hdr->dt_size) {
            printf("[-] Failed to write device tree to output file.\n");
            return 1;
        }
    }

    lseek(ofd, pos - (fake_size - offset), SEEK_SET);

    /* Write the patch */
    if (write(ofd, patch, sizeof(patch)) != sizeof(patch)) {
        printf("[-] Failed to write patch to output file.\n");
        return 1;
    }

    close(ifd);
    close(ofd);
    close(aboot_fd);

    printf("[+] Output file written to %s\n", out_image);

    return 0;
}

/* Find the original address of the ramdisk, which
 * was embedded in the shellcode. */
int find_ramdisk_addr(void *img, int sz)
{

    int i, ramdisk = 0;

    for (i = 0; i < sz - (sizeof(patch) - 9); i++) {
        if (!memcmp((char *)img + i, patch, sizeof(patch)-9)) {
            ramdisk = *(int *)(img + i + sizeof(patch) - 5);
            break;
        }
    }

    return ramdisk;
}

int loki_unlok(const char* in_image, const char* out_image)
{
    int ifd, ofd;
    unsigned int orig_ramdisk_size, orig_kernel_size, orig_ramdisk_addr;
    unsigned int page_kernel_size, page_ramdisk_size, page_size, page_mask, fake_size;
    void *orig;
    struct stat st;
    struct boot_img_hdr *hdr;
    struct loki_hdr *loki_hdr;

    ifd = open(in_image, O_RDONLY);
    if (ifd < 0) {
        printf("[-] Failed to open %s for reading.\n", in_image);
        return 1;
    }

    ofd = open(out_image, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (ofd < 0) {
        printf("[-] Failed to open %s for writing.\n", out_image);
        return 1;
    }

    /* Map the original boot/recovery image */
    if (fstat(ifd, &st)) {
        printf("[-] fstat() failed.\n");
        return 1;
    }

    orig = mmap(0, (st.st_size + 0x2000 + 0xfff) & ~0xfff, PROT_READ|PROT_WRITE, MAP_PRIVATE, ifd, 0);
    if (orig == MAP_FAILED) {
        printf("[-] Failed to mmap input file.\n");
        return 1;
    }

    hdr = orig;
    loki_hdr = orig + 0x400;

    if (memcmp(loki_hdr->magic, "LOKI", 4)) {
        printf("[-] Input file is not a Loki image.\n");

        /* Copy the entire file to the output transparently */
        if (write(ofd, orig, st.st_size) != st.st_size) {
            printf("[-] Failed to copy Loki image.\n");
            return 1;
        }

        printf("[+] Copied Loki image to %s.\n", out_image);

        return 0;
    }

    page_size = hdr->page_size;
    page_mask = hdr->page_size - 1;

    /* Infer the size of the fake block based on the newer ramdisk address */
    if (hdr->ramdisk_addr > 0x88f00000 || hdr->ramdisk_addr < 0xfa00000)
        fake_size = page_size;
    else
        fake_size = 0x200;

    orig_ramdisk_addr = find_ramdisk_addr(orig, st.st_size);
    if (orig_ramdisk_addr == 0) {
        printf("[-] Failed to find original ramdisk address.\n");
        return 1;
    }

    /* Restore the original header values */
    hdr->ramdisk_addr = orig_ramdisk_addr;
    hdr->kernel_size = orig_kernel_size = loki_hdr->orig_kernel_size;
    hdr->ramdisk_size = orig_ramdisk_size = loki_hdr->orig_ramdisk_size;

    /* Erase the loki header */
    memset(loki_hdr, 0, sizeof(*loki_hdr));

    /* Write the image header */
    if (write(ofd, orig, page_size) != page_size) {
        printf("[-] Failed to write header to output file.\n");
        return 1;
    }

    page_kernel_size = (orig_kernel_size + page_mask) & ~page_mask;

    /* Write the kernel */
    if (write(ofd, orig + page_size, page_kernel_size) != page_kernel_size) {
        printf("[-] Failed to write kernel to output file.\n");
        return 1;
    }

    page_ramdisk_size = (orig_ramdisk_size + page_mask) & ~page_mask;

    /* Write the ramdisk */
    if (write(ofd, orig + page_size + page_kernel_size, page_ramdisk_size) != page_ramdisk_size) {
        printf("[-] Failed to write ramdisk to output file.\n");
        return 1;
    }

    /* Write the device tree if needed */
    if (hdr->dt_size) {

        printf("[+] Writing device tree.\n");

        /* Skip an additional fake_size (page_size of 0x200) bytes */
        if (write(ofd, orig + page_size + page_kernel_size + page_ramdisk_size + fake_size, hdr->dt_size) != hdr->dt_size) {
            printf("[-] Failed to write device tree to output file.\n");
            return 1;
        }
    }

    close(ifd);
    close(ofd);

    printf("[+] Output file written to %s\n", out_image);

    return 0;
}

static int loki_usage(const char* cmd) {
    printf("Usage\n");
    printf("> Patch partition file image:\n");
    printf("%s [patch] [boot|recovery] [aboot.img] [in.img] [out.lok]\n", cmd);
    printf("\n");
    printf("> Flash loki image to boot|recovery:\n");
    printf("%s [flash] [boot|recovery] [in.lok]\n", cmd);
    printf("\n");
    printf("> Find offset from aboot image:\n");
    printf("%s [find] [aboot.img]\n", cmd);
    printf("\n");
    printf("> Revert Loki patching:\n");
    printf("%s [unlok] [in.lok] [out.img]\n", cmd);
    printf("\n");
    return 1;
}

int main_loki(int argc, char **argv) {
    printf("Loki tool v%s\n", VERSION);

    if (argc == 6 && strcmp(argv[1], "patch") == 0) {
        // argv[2]: partition_label
        // argv[3]: aboot_image
        // argv[4]: in_image
        // argv[5]: out_image
        return loki_patch(argv[2], argv[3], argv[4], argv[5]);
    } else if (argc == 4 && strcmp(argv[1], "flash") == 0) {
        // argv[2]: partition_label
        // argv[3]: loki_image
        return loki_flash(argv[2], argv[3]);
    } else if (argc == 3 && strcmp(argv[1], "find") == 0) {
        // argv[2]: aboot_image
        return loki_find(argv[2]);
    } else if (argc == 4 && strcmp(argv[1], "unlok") == 0) {
        // argv[2]: in_image
        // argv[3]: out_image
        return loki_unlok(argv[2], argv[3]);
    }

    return loki_usage(argv[0]);
}
