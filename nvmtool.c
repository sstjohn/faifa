/*
 *  NVM retrieval
 *
 *  Copyright (C) 2007-2008 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
 *                          Saul St. John <saul.stjohn@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "crc32.h"
#include "faifa.h"
#include "faifa_compat.h"
#include "faifa_priv.h"

#include "homeplug_av.h"


/* Command line arguments storing */
int opt_help = 0;
int opt_key = 0;
const char *opt_fname = NULL;
const char *prog_name = NULL;

/**
 * error - display error message
 */
static void error(char *message)
{
	fprintf(stderr, "%s: %s\n", prog_name, message);
}

/**
 * usage - show the program usage
 */
static void usage(void)
{
	fprintf(stderr, "-i : interface\n"
			"-a : station MAC address\n"
			"-k : network key\n"
			"-v : be verbose (default: no)\n"
			"-h : this help\n");
}

struct read_request_frame {
	union {
		struct {
			struct ether_header eth_header;
			struct hpav_frame_header hpav_header;
			struct hpav_frame_vendor_payload payload;
			struct read_mod_data_request request;
		};
		short data[60];
	};
} __attribute__((__packed__));

struct read_confirmation_frame {
	struct ether_header eth_header;
	struct hpav_frame_header hpav_header;
	struct hpav_frame_vendor_payload payload;
	struct read_mod_data_confirm response;
} __attribute__((__packed__));

int send_read_request(faifa_t *faifa, int len, int offset)
{
	int res;
	struct read_request_frame f;
	
	memcpy(f.eth_header.ether_dhost, ((struct faifa *)faifa)->dst_addr, 
								ETHER_ADDR_LEN);
	memset(f.eth_header.ether_shost, 0, ETHER_ADDR_LEN);
	f.eth_header.ether_type = htons(ETHERTYPE_HOMEPLUG_AV);

	f.hpav_header.mmtype = HPAV_MMTYPE_RD_MOD_REQ;
	f.payload.oui[0] = 0;
	f.payload.oui[1] = 0xb0;
	f.payload.oui[2] = 0x52;

	f.request.module_id = 1;
	f.request.length = len;
	f.request.offset = offset;
	
	res = faifa_send(faifa, &f, sizeof(f));
	if(-1 == res) {
		error(faifa_error(faifa));
	}

	return res;
}

uint32_t checksum(const char *data, size_t len)
{
	uint32_t sum = 0xffffffff;
	int i = 0;
	for ( ; i < len; i++)
	{
		sum ^= (uint32_t)((unsigned char)data[i]);
		sum = (sum >> 8) | (sum << 24);
	}
	return sum;
}

int recv_read_confirmation(faifa_t *faifa, char *nvm, int *offset)
{
	struct read_confirmation_frame *f = malloc(ETHER_MAX_LEN);
	int res;
	uint32_t cksum;

	res = faifa_recv(faifa, (char *)f, ETHER_MAX_LEN);
	
	cksum = checksum((char *)f->response.data, f->response.length);
	if (cksum != f->response.checksum)
		printf("checksum mismatch %08x != %08x !\n", cksum, f->response.checksum);

 	memcpy(&nvm[*offset], &f->response.data, f->response.length);
	*offset += f->response.length;



	free(f);
	return res;
}

void nvm_write_file(char* nvm, size_t size)
{
	const char *fname;
	FILE *file;
	int i;

	if (NULL != opt_fname)
		fname = opt_fname;
	else
		fname = "./nvmtool.out";

	file = fopen(fname, "w");

	for (i = 0; i < size; i++)
		fprintf(file, "%c", nvm[i]);

	fclose(file);	
}

int nvm_dump(faifa_t *faifa)
{
	int offset = 0;
	int sz = 1024;
	char *nvm = malloc(1024);
	int res = 0;
	int err = 0;

	while (!err) {
		if (-1 == ((res = send_read_request(faifa, 1, offset))))
			err++;
		if (-1 == ((res = recv_read_confirmation(faifa, nvm, &offset))))
			err++;
		if (offset == sz) {
			char * new_nvm;
			sz *= 2;
			new_nvm = realloc(nvm, sz);
			if (new_nvm != NULL)
				nvm = new_nvm;
			else
				err++;
		}
	}

	nvm_write_file(nvm, offset);

	free(nvm);
	return err ? -1 : 0;
}

struct write_request_frame {
			struct ether_header eth_header;
			struct hpav_frame_header hpav_header;
			struct hpav_frame_vendor_payload payload;
			struct write_mod_data_request request;
} __attribute__((__packed__));

struct write_confirmation_frame {
	union {
		struct {
			struct ether_header eth_header;
			struct hpav_frame_header hpav_header;
			struct hpav_frame_vendor_payload payload;
			struct write_mod_data_confirm response;
		};
		char data[60];
	};
} __attribute__((__packed__));

struct nvm_write_request_frame {
	union {
		struct {
			struct ether_header eth_header;
			struct hpav_frame_header hpav_header;
			struct hpav_frame_vendor_payload payload;
			struct write_module_data_to_nvm_request request;
		};
		char data[60];
	};
} __attribute__((__packed__));

int send_commit_write_to_nvm(faifa_t *faifa, int module)
{
	struct nvm_write_request_frame f;	
	int res = 0;

	memcpy(f.eth_header.ether_dhost, faifa->dst_addr, ETHER_ADDR_LEN);
	f.eth_header.ether_type = htons(ETHERTYPE_HOMEPLUG_AV);

	f.hpav_header.mmtype = HPAV_MMTYPE_NVM_MOD_REQ;
	f.payload.oui[1] = 0xb0;
	f.payload.oui[2] = 0x52;

	f.request.module_id = module;

	res = faifa_send(faifa, &f, sizeof(f));
	if(-1 == res) {
		error(faifa_error(faifa));
	}

	return res;
	
}	

int send_write_request(faifa_t *faifa, const char *nvm, int offset, int len)
{
	struct write_request_frame *f = malloc(ETHER_MAX_LEN);
	int res = 0;

	memset(f, 0, ETHER_MAX_LEN);

	memcpy(f->eth_header.ether_dhost, faifa->dst_addr, ETHER_ADDR_LEN);
	f->eth_header.ether_type = htons(ETHERTYPE_HOMEPLUG_AV);

	f->hpav_header.mmtype = HPAV_MMTYPE_WR_MOD_REQ;
	f->payload.oui[0] = 0;
	f->payload.oui[1] = 0xb0;
	f->payload.oui[2] = 0x52;

	f->request.module_id = 1;
	f->request.length = len;
	f->request.offset = offset;
	f->request.checksum = checksum(&nvm[offset], len);

	memcpy(&f->request.data, &nvm[offset], len);
	
	res = faifa_send(faifa, f, sizeof(struct write_request_frame) + len);
	if(-1 == res) {
		error(faifa_error(faifa));
	}

	return res;
}

void nvm_read_file(char *nvm)
{
	const char *fname;
	FILE *file;
	int offset = 0;

	if (NULL != opt_fname)
		fname = opt_fname;
	else
		fname = "./nvmtool.in";

	file = fopen(fname, "r");

	while (!feof(file)) {
		int read = fread(&nvm[offset], 1, 0x400, file);
		offset += read;	
	}

	fclose(file);
}

void recv_write_confirmation(faifa_t *faifa)
{
	struct write_confirmation_frame f;
	int res;

	res = faifa_recv(faifa, (char *)&f, 
				sizeof(struct write_confirmation_frame));
}

/*
int nvm_write(faifa_t *faifa)
{
	char *nvm = malloc(16352);
	int offset = 0;

	nvm_read_file(nvm);

	for (offset = 0; offset < 16352; offset += 0x400) {
		int len = (offset + 0x400 > 16352) ?
				16352 - offset :
				0x400;
		send_write_request(faifa, nvm, offset, len);
		recv_write_confirmation(faifa);
	}
	
	send_commit_write_to_nvm(faifa, 2);	
}
*/

void checksum_test()
{
	uint32_t cksum;
	char *buf = malloc(1024);
	
	memset(buf, 0, 1024);
	
	cksum = checksum(buf, 1024);
	printf("checksum_test: 0x%08x\n", cksum);
	free(buf);
}
/**
 * main - main function of faifa
 * @argc:	number of arguments
 * @argv:	array of arguments
 */
int main(int argc, char **argv)
{
	faifa_t *faifa;
	char *opt_ifname = NULL;
	char *opt_macaddr = NULL;
	int opt_verbose = 0;
/*	int opt_write = 0; */
	int opt_dump = 0;
	int c;
	int ret = 0;
	u_int8_t addr[ETHER_ADDR_LEN] = { 0 };

	prog_name = strdup(basename(argv[0]));

	fprintf(stdout, "%s for HomePlug AV (SVN revision %d)\n\n", prog_name, SVN_REV);

	if (argc < 2) {
		usage();
		return -1;
	}

	while ((c = getopt(argc, argv, "di:a:k:f:wvh")) != -1) {
		switch (c) {
			case 'i':
				opt_ifname = optarg;
				break;
			case 'a':
				opt_macaddr = optarg;
				break;
			case 'f':
				opt_fname = optarg;
				break;
			case 'd':
				opt_dump = 1;
				break;
/*			case 'w':
				opt_write = 1;
				break;
*/			case 'k':
				opt_key = 1;
				break;
			case 'v':
				opt_verbose = 1;
				break;
			case 'h':
			default:
				opt_help = 1;
				break;
		}
	}

	if (opt_help) {
		usage();
		return -1;
	}

	if (opt_ifname == NULL)
		opt_ifname = "eth0";

	faifa = faifa_init();
	if (faifa == NULL) {
		error("can't initialize Faifa library");
		return -1;
	}

	if (faifa_open(faifa, opt_ifname) == -1) {
		error(faifa_error(faifa));
		faifa_free(faifa);
		return -1;
	}

	faifa_set_verbose(faifa, opt_verbose);

	if (opt_macaddr) {
		ret = faifa_parse_mac_addr(faifa, opt_macaddr, addr);
		if (ret < 0) {
			error(faifa_error(faifa));
			goto out_error;
		}

		faifa_set_dst_addr(faifa, addr);
	}

	checksum_test();

	if (opt_dump) {
		nvm_dump(faifa);
/*	} else if (opt_write) {
		nvm_write(faifa);
*/	} else {
		error("nothing to do");
		ret = -1;
	}

out_error:
	faifa_close(faifa);
	faifa_free(faifa);

	return ret;
}
