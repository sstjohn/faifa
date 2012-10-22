/*
 *  Program entry and command line parsing
 *
 *  Copyright (C) 2007-2008 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
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
	
	memcpy(f.eth_header.ether_dhost, ((struct faifa *)faifa)->dst_addr, ETHER_ADDR_LEN);
	memset(f.eth_header.ether_shost, 0, ETHER_ADDR_LEN);
	f.eth_header.ether_type = htons(ETHERTYPE_HOMEPLUG_AV);

	f.hpav_header.mmtype = HPAV_MMTYPE_RD_MOD_REQ;
	f.payload.oui[0] = 0;
	f.payload.oui[1] = 0xb0;
	f.payload.oui[2] = 0x52;

	f.request.module_id = 2;
	f.request.length = len;
	f.request.offset = offset;
	
	res = faifa_send(faifa, &f, sizeof(f));
	if(-1 == res) {
		error(faifa_error(faifa));
	}

	return res;
}

int recv_read_confirmation(faifa_t *faifa, char *pib, int *offset)
{
	struct read_confirmation_frame *f = malloc(ETHER_MAX_LEN);
	int res;

	res = faifa_recv(faifa, (char *)f, ETHER_MAX_LEN);
 	memcpy(&pib[*offset], &f->response.data, f->response.length);
	*offset += f->response.length;

	free(f);
	return res;
}

void pib_write_file(char* pib)
{
	const char *fname;
	FILE *file;
	int i;

	if (NULL != opt_fname)
		fname = opt_fname;
	else
		fname = "./pibtool.out";

	file = fopen(fname, "w");

	for (i = 0; i < 16352; i++)
		fprintf(file, "%c", pib[i]);

	fclose(file);	
}

void pib_read_file(char *pib)
{
	const char *fname;
	FILE *file;
	int offset = 0;

	if (NULL != opt_fname)
		fname = opt_fname;
	else
		fname = "./pibtool.in";

	file = fopen(fname, "r");

	while (!feof(file)) {
		int read = fread(&pib[offset], 1, 0x400, file);
		offset += read;	
	}

	fclose(file);
}

int pib_dump(faifa_t *faifa)
{
	int offset = 0;
	char *pib = malloc(16352);
	int res = 0;

	/* this is super insecure */
	while (offset < 16352) {
		int len = (16352 - offset < 0x400) ?
				16352 - offset :
				0x400;
		if (-1 == ((res = send_read_request(faifa, len, offset)))) {
			break;
		}
		if (-1 == ((res = recv_read_confirmation(faifa, pib, &offset)))) {
			break;
		}
	}

	pib_write_file(pib);

	free(pib);
	return res;
}

int pib_write(faifa_t *faifa)
{
	char *pib = malloc(16352);
	int offset = 0;

	pib_read_file(pib);

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
	int opt_write = 0;
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
			case 'w':
				opt_write = 1;
				break;
			case 'k':
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

	if (opt_dump) {
		pib_dump(faifa);
	} else if (opt_write) {
		pib_write(faifa);
	} else {
		error("nothing to do");
		ret = -1;
	}

out_error:
	faifa_close(faifa);
	faifa_free(faifa);

	return ret;
}
