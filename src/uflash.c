/*
 * (C) Copyright, Alagu Sankar <alagusankar@embwise.com>
 *
 * Utility for flashing the UBL and U-Boot binary onto SD/MMC cards.
 * Signature as Required by RBL is Added by this utility.
 * Tested with DM355EVM Platform with UBL v1.65 and Uboot 2009-03
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

struct rbl_header {
	unsigned int magic_num;
	unsigned int entry_point;
	unsigned int num_blocks;
	unsigned int start_block;
	unsigned int load_address;
	unsigned int padding[123];
};

#define verbose_printf(x...)	if (verbose) printf(x)
#define BLOCK_SIZE		512UL

#define UBL_SIGN_START		1
#define UBL_SIGN_COUNT		24
#define UBL_MAGIC_NUM		0xA1ACED00
#define UBL_ENTRY_POINT		0x00000100
#define UBL_START_BLOCK		0x00000075
#define UBL_BLOCK_OFFSET	0x0000000A

#define UBOOT_SIGN_START		25
#define UBOOT_SIGN_COUNT		26
#define UBOOT_MAGIC_NUM			0xA1ACED66
#define DM3XX_UBOOT_LOAD_ADDRESS	0x81080000
#define DA850_UBOOT_LOAD_ADDRESS	0xC1080000

#define PART1_LBA_OFFSET		0x000001C6
#define DEV_NAME			"/dev/mmcblk0"
#define UBL_NAME			"UBL.bin"
#define UBOOT_NAME			"u-boot.bin"

unsigned char ubl_signature[BLOCK_SIZE];
unsigned char uboot_signature[BLOCK_SIZE];
unsigned char readbuf[BLOCK_SIZE];

static void print_hex(unsigned char *buf, int len);
static int get_file_size(char *fname);
static int write_file(int devfd, char *fname);
static unsigned int get_le32(unsigned char *buf);

static int verbose;
static char *dev_name;
static char *ubl_name;
static char *uboot_name;
static char *platform;
static void usage(void)
{
	printf("Usage : uflash [options]\r\n");
	printf("\t-d DEVNAME     - Block device Name/Node (%s)\r\n", DEV_NAME);
	printf("\t-u UBL_FILE    - UBL File Name (%s)\r\n", UBL_NAME);
	printf("\t-b UBOOT_FILE  - UBoot File Name (%s)\r\n", UBOOT_NAME);
	printf("\t-p PLATFORM    - Platform name (DM3XX/OMAPL138)\r\n");
	printf("\t-e UBOOT_ENTRY - UBoot Entry Point (0x%X - for DM3XX, 0x%X -"\
				" for OMAPL138)\r\n", DM3XX_UBOOT_LOAD_ADDRESS,
						DA850_UBOOT_LOAD_ADDRESS);
	printf("\t-l UBOOT_LOAD  - UBoot Load Address (0x%X - for DM3XX,"\
				" 0x%X - for OMAPL138)\r\n",
		DM3XX_UBOOT_LOAD_ADDRESS, DA850_UBOOT_LOAD_ADDRESS);
	printf("\r\n");
}

int main(int argc, char *argv[])
{
	int i, devfd, c, readlen, writelen;
	int req_blocks, part1_offset;
	int ubl_size = 0, uboot_size;
	struct rbl_header *rblp;
	unsigned int uboot_load_address = 0, uboot_entry_point = 0;
	unsigned int uboot_sign_start = 0, uboot_start_block = 0;

	while ((c = getopt(argc, argv, "?hvd:u:b:l:e:p:")) >= 0) {
		switch (c) {
		case 'd':
			dev_name = optarg;
			break;
		case 'u':
			ubl_name = optarg;
			break;
		case 'l':
			uboot_load_address = strtoul(optarg, NULL, 16);
			break;
		case 'e':
			uboot_entry_point = strtoul(optarg, NULL, 16);
			break;
		case 'v':
			verbose++;
			break;
		case 'b':
			uboot_name = optarg;
			break;
		case 'p':
			platform = optarg;
			for (i = 0; i < strlen(platform) - 1; i++)
				platform[i] = toupper(platform[i]);
			printf("%s\n", platform);
			break;
		case 'h':
		case '?':
			usage();
			return 0;
		}
	}

	if (!ubl_name)
		uboot_start_block = UBL_START_BLOCK;

	if (!strcmp(platform, "DM3XX")) {
		if (!uboot_load_address)
			uboot_load_address = DM3XX_UBOOT_LOAD_ADDRESS;
		if (!uboot_entry_point)
			uboot_entry_point = DM3XX_UBOOT_LOAD_ADDRESS;
	}

	if (!strcmp(platform, "OMAPL138")) {
		if (!uboot_load_address)
			uboot_load_address = DA850_UBOOT_LOAD_ADDRESS;
		if (!uboot_entry_point)
			uboot_entry_point = DA850_UBOOT_LOAD_ADDRESS;
	}

	/* Open the SD/MMC Device in Read-Write Mode */
	devfd = open(dev_name, O_RDWR);
	if (devfd <= 0) {
		fprintf(stderr, "Device open Error : %s\n", strerror(errno));
		exit(-1);
	}

	/* Read Master Boot Record - MBR */
	readlen = read(devfd, readbuf, BLOCK_SIZE);
	if (readlen < 0)
		fprintf(stderr, "Device Read Error : %s\n", strerror(errno));

	if (verbose > 2) {
		printf("====================Master Boot Record============\n");
		print_hex(readbuf, BLOCK_SIZE);
		printf("==================================================\n");
	}

	/* Get UBL file size and round it to upper 512 byte boundary */
	if (!strcmp(platform, "DM3XX")) {
		ubl_size = get_file_size(ubl_name);
		if (ubl_size < 0) {
			close(devfd);
			return -1;
		}

		ubl_size = (ubl_size + BLOCK_SIZE - 1) & ~BLOCK_SIZE;
		verbose_printf("UBL Size %d\n", ubl_size);
	}

	/* Get U-boot file size and round it to upper 512 byte boundary */
	uboot_size = get_file_size(uboot_name);
	if (uboot_size <= 0) {
		fprintf(stderr, "Invalid U-Boot Size %d\n", uboot_size);
		close(devfd);
		return -1;
	}
	uboot_size = (uboot_size + BLOCK_SIZE - 1) & ~BLOCK_SIZE;
	verbose_printf("U-Boot Size %d\n", uboot_size);

	/* Get first partition start address offset from Master Boot Record */
	part1_offset = get_le32 (&readbuf[PART1_LBA_OFFSET]);
	verbose_printf("First partition starts at %d(%ld)\n", part1_offset,
			(part1_offset * BLOCK_SIZE));

	/* Add MBR + UBL Size + Uboot Size */

	if (!(strcmp(platform, "DM3XX"))) {
		req_blocks = UBL_START_BLOCK + (ubl_size / BLOCK_SIZE) +
		UBL_BLOCK_OFFSET + (uboot_size / BLOCK_SIZE) + 1;
		printf("Required Blocks %d, Available Blocks %d\n", req_blocks,
			part1_offset - 1);

		/*
		 * Return if the card does not have enough
		 * space for writing UBL/Uboot
		 */
		if (req_blocks > part1_offset) {
			fprintf(stderr, "Not enough space left for "
					"flashing UBL and U-boot\n");
			fprintf(stderr, "Make sure that the First Partition "
				" Starts after %d sectors\n", req_blocks);
			close(devfd);
			return -1;
		}

		/* Generate UBL Signature */
		rblp = (struct rbl_header *)ubl_signature;
		memset(rblp, 0, sizeof(struct rbl_header));
		rblp->magic_num   = UBL_MAGIC_NUM;
		rblp->entry_point = UBL_ENTRY_POINT;
		rblp->num_blocks  = ubl_size / BLOCK_SIZE;
		rblp->start_block = UBL_START_BLOCK;

		if (verbose > 1) {
			printf("UBL Magic Number     : %08x\n",
							rblp->magic_num);
			printf("UBL Entry Point      : %08x\n",
							rblp->entry_point);
			printf("UBL Number of Blocks : %08x\n",
							rblp->num_blocks);
			printf("UBL Starting Block   : %08x\n",
							rblp->start_block);
			printf("UBL Load Address     : %08x\n",
							rblp->load_address);
		}

		/* Write UBL Signature */
		verbose_printf("Writing UBL Signature\n");
		lseek(devfd, (BLOCK_SIZE * UBL_SIGN_START), SEEK_SET);
		for (i = UBL_SIGN_START; i <
				(UBL_SIGN_COUNT + UBL_SIGN_START); i++) {
			writelen = write(devfd, rblp, BLOCK_SIZE);
			if (writelen < BLOCK_SIZE) {
				close(devfd);
				return -1;
			}
		}

		/* Write UBL Binary */
		verbose_printf("Writing UBL\n");
		lseek(devfd, (BLOCK_SIZE * rblp->start_block), SEEK_SET);
		write_file(devfd, ubl_name);
	}

	/* Generate U-boot signature */
	rblp = (struct rbl_header *)uboot_signature;
	memset(rblp, 0, sizeof(struct rbl_header));
	rblp->magic_num = UBOOT_MAGIC_NUM;
	rblp->entry_point = uboot_entry_point;
	rblp->num_blocks = (uboot_size / BLOCK_SIZE) + 1;

	if (!strcmp(platform, "DM3XX")) {
		rblp->start_block = UBL_START_BLOCK + (ubl_size / BLOCK_SIZE) +
					UBL_BLOCK_OFFSET;
	} else if (!strcmp(platform, "OMAPL138")) {
		rblp->start_block = uboot_start_block;
		uboot_sign_start = 1;
	} else {
		printf("error\n");
		return -1;
	}

	rblp->load_address = uboot_load_address;

	if (verbose > 1) {
		printf("U-Boot Magic Number     : %08x\n", rblp->magic_num);
		printf("U-Boot Entry Point      : %08x\n", rblp->entry_point);
		printf("U-Boot Number of Blocks : %08x\n", rblp->num_blocks);
		printf("U-Boot Starting Block   : %08x\n", rblp->start_block);
		printf("Load U-Boot Address     : %08x\n", rblp->load_address);
	}

	/* Write U-Boot Signature */
	verbose_printf("Writing U-Boot Signature\n");
	if (!strcmp(platform, "DM3XX"))
		lseek(devfd, (BLOCK_SIZE * UBOOT_SIGN_START), SEEK_SET);
	else
		lseek(devfd, (BLOCK_SIZE * uboot_sign_start), SEEK_SET);

	for (i = UBOOT_SIGN_START; i <
				(UBOOT_SIGN_COUNT + UBOOT_SIGN_START); i++) {
		writelen = write(devfd, rblp, BLOCK_SIZE);
		if (writelen < BLOCK_SIZE) {
			close(devfd);
			return -1;
		}
	}

	/* Write U-Boot File */
	lseek(devfd, (BLOCK_SIZE * rblp->start_block), SEEK_SET);
	verbose_printf("Writing U-Boot\n");
	write_file(devfd, uboot_name);

	printf("Done...\n");
	close(devfd);
	return 0;
}

static void print_hex(unsigned char *buf, int len)
{
	int i, j;
	for (i = 0 ; i < len; i += 16) {
		printf("%08x : ", i);
		for (j = i ; (j < (i+16)) && (j < len); j++)
			printf("%02x,", buf[j]);

		printf("    ");
		for (j = i ; (j < (i+16)) && (j < len); j++) {
			if ((buf[j] > 0x20) && (buf[j] < 0x7F))
				printf("%c", buf[j]);
			else
				printf(".");
		}
		printf("\n");
	}
}

static int get_file_size(char *fname)
{
	FILE *fp;
	int size;

	fp = fopen(fname, "rb");
	if (fp == NULL) {
		fprintf(stdout, "File %s Open Error : %s\n",
					fname, strerror(errno));
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fclose(fp);

	return size;
}

static int write_file(int devfd, char *fname)
{
	FILE *fp;
	int readlen, writelen;

	fp = fopen(fname, "rb");
	if (fp == NULL) {
		fprintf(stderr, "File %s Open Error: %s",
				fname, strerror(errno));
		return -1;
	}

	while ((readlen = fread(readbuf, 1, BLOCK_SIZE, fp)) > 0) {
		if (readlen < BLOCK_SIZE)
			memset(&readbuf[readlen], 0, BLOCK_SIZE-readlen);

		writelen = write(devfd, readbuf, BLOCK_SIZE);
		if (writelen < BLOCK_SIZE) {
			close(devfd);
			return -1;
		}
	}

	fclose(fp);

	return 0;
}

static unsigned int get_le32 (unsigned char *buf)
{
	return (unsigned int)(((unsigned int)buf[0]) |
		((unsigned int)buf[1] << 8) |
		((unsigned int)buf[2] << 16) |
		((unsigned int)buf[3] << 24));
}
