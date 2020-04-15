/* echo test | socat stdio 'udp4-datagram:255.255.255.255:1337,broadcast,so-bindtodevice=wlan1' */
/* gcc -DNIX -Wall barp.c -o barp */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#define PORT 1337
#define BSIZ 1024
#define APNS 4
#define PSIZ 9

struct maps
{
	unsigned long last[PSIZ+1];
	unsigned char host[4];
	char bufs[PSIZ][BSIZ];
};

struct proc
{
	char key[32], low[32], adr[APNS][32], dev[32], mac[32];
};

int min(int a, int b) { if (a < b) { return a; } return b; }
void bz(char *pr) { bzero(pr, BSIZ * sizeof(char)); }

void delb(char *intf) {
	char bcmd[64];
	bzero(bcmd, 64 * sizeof(char));
	snprintf(bcmd, 60, "ip -4 neigh del 255.255.255.255 dev %s", intf);
	system(bcmd);
}

void mask(unsigned int *a, unsigned int *b, int bits) {
	*b = ((1 << (32 - bits)) - 1);
	*a = (0xffffffff ^ *b);
}

int sfclose(FILE *fo) {
	if (fo == NULL) { return 1; }
	fclose(fo); return 0;
}

char *strschr(char *a, char c) {
	if (a == NULL) { return NULL; }
	return strchr(a, c);
}

int strlncmp(char *a, char *b, int n) {
	int l = strlen(a);
	if (l > strlen(b)) { return 1; }
	if (l > n) { return 2; }
	return strncmp(a, b, n);
}

unsigned int ntol(char *addr) {
	unsigned char a[4];
	unsigned int b = 0;
	if (addr == NULL) { return b; }
	if (inet_pton(AF_INET, addr, a) != 1) { return b; }
	b = ((a[0] << 24) + (a[1] << 16) + (a[2] << 8) + (a[3] & 0xff));
	return b;
}

int find(char *stri, struct proc *list, int size) {
	int y = -1;
	for (int x = 0; (x < size) && (stri != NULL); ++x) {
		if (strlncmp(stri, list[x].key, 30) == 0) { return x; }
		if (list[x].key[0] == '\0') { y = (x + 1); break; }
	}
	if (y > -1) { return (y << 16); }
	return y;
}

void swap(unsigned char *a, unsigned char *b) {
	unsigned char t = *a;
	*a = *b; *b = t;
}

void fill(unsigned char *init, unsigned long last, char *host, char part) {
	char d[32];
	char *p = d, *q = d;
	bzero(d, 32 * sizeof(char)); strncpy(d, host, 16);
	for (int x = 0; x < 4; ++x) { /* time{0, 1, 2, 3} */
		init[x] = (last & 0xff); last = (last >> 8);
	} init[4] = part; /* part{4} */
	for (int x = 5; x < 9; ++x) { /* hash{5, 6, 7, 8} */
		init[x] = 0;
	} init[9] = 0; /* null{9} */
	for (int x = 10; x < 14; ++x) { /* addr{10, 11, 12, 13} */
		while ((*p != '.') && (*p != '\0')) { ++p; }
		*p = '\0'; ++p;
		init[x] = atoi(q); q = p;
	} init[14] = 0; /* null{14} */
	for (int x = 15; x < (15+APNS); ++x) { /* relay-ids{15, 16, 17, 18} */
		init[x] = 0;
	}
	for (int x = (15+APNS); x < 128; ++x) { /* rand{19, ...} */
		init[x] = (rand() % 256);
	}
}

int keys(unsigned char *skey, unsigned char *init, char *spwd, int leng) {
	int j = 0;
	int m = min(15+APNS+leng, 128);

	for (int i = 0; i < 256; ++i) {
		skey[i] = i;
	}

	for (int i = 0; i < 256; ++i) {
		j = ((j + skey[i] + init[i % m] + spwd[i % leng]) % 256);
		swap(&(skey[i]), &(skey[j]));
	}

	return m;
}

/* Modified ARC4-KEY[IV]-DROP[4096]-MODE[CBC] */
void ciph(unsigned char *outp, unsigned char *inpt, int leng, unsigned char *skey, char mode) {
	int i = 0, j = 0, k;
	unsigned char l = (leng % 256);

	for (int z = 0; z < 4096; ++z) {
		i = ((i + 1) % 256);
		j = ((j + skey[i]) % 256);
		swap(&(skey[i]), &(skey[j]));
	}

	for (int z = 0; z < leng; ++z) {
		i = ((i + 1) % 256);
		j = ((j + skey[i]) % 256);
		swap(&(skey[i]), &(skey[j]));
		k = ((skey[i] + skey[j] + skey[l]) % 256);
		outp[z] = (inpt[z] ^ skey[k]);
		if (mode == 'e') { l = (l ^ outp[z]); }
		else { l = (l ^ inpt[z]); }
	}
}

/* Modified SDBM-HASH[INIT]-ROUNDS[4]-SIZE[256] */
void hmix(unsigned char *outp, unsigned char *inpt, int leng) {
	unsigned int mixs[] = {1, 6, 16, 13, 33, 27, 67, 55, 123};
	unsigned int hshs[] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	unsigned int less, more = 0;
	int i, mlen = 9, rnds = (4 * mlen);
	for (int x = 0; x < (mlen+leng); ++x) {
		hshs[0] = (mixs[x%mlen] + inpt[x%leng] + (hshs[0] << 6) + (hshs[0] << 16) - hshs[0]);
		more = (more ^ (hshs[0] >> 16));
		i = ((x % (mlen - 1)) + 1);
		less = ((hshs[i] & 0xffff0000) ^ ((hshs[i] & 0xffff) << 16));
		hshs[i] = (less ^ more);
	}
	for (int z = 0; z < rnds; ++z) {
		hshs[0] = (z + more + (hshs[0] << 6) + (hshs[0] << 16) - hshs[0]);
		more = (more ^ (hshs[mlen-1] >> 16));
		for (int y = mlen-1; y > 0; --y) {
			hshs[y] = ((hshs[y] << 16) | (hshs[y-1] >> 16));
			hshs[y-1] = (hshs[y-1] & 0xffff);
		}
	}
	for (int x = 1, y = 0; x < mlen; ++x) {
		for (int z = 3; z > -1; --z, ++y) {
			outp[y] = ((hshs[x] >> (z * 8)) & 0xff);
		}
	}
}

void hmac(unsigned char *outp, unsigned char *mesg, int mlen, unsigned char *skey, int klen) {
	int block_size = 64, hash_size = 32;
	unsigned char inner_pad = 0x36, outer_pad = 0x5C;
	unsigned char ikey[block_size], okey[block_size], ihsh[hash_size], thsh[hash_size];
	unsigned char buff[block_size+mlen+hash_size];
	unsigned char *tkey = skey; int tlen = klen;
	if (klen > block_size) {
		hmix(thsh, skey, klen);
		tkey = thsh; tlen = hash_size;
	}
	for (int x = 0; x < block_size; ++x) {
		unsigned char padc = 0;
		if (x < tlen) { padc = tkey[x]; }
		ikey[x] = (inner_pad ^ padc);
		okey[x] = (outer_pad ^ padc);
	}
	bcopy(ikey, buff, block_size);
	bcopy(mesg, buff+block_size, mlen);
	hmix(ihsh, buff, block_size+mlen);
	bcopy(okey, buff, block_size);
	bcopy(ihsh, buff+block_size, hash_size);
	hmix(outp, buff, block_size+hash_size);
}

int ssnd(char *intf, unsigned char *data, int leng) {
	int socksend, bopt = 1;
	struct sockaddr_in addrsend;
	char *dest = "255.255.255.255";

	if ((socksend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		return 1;
	}
	if (setsockopt(socksend, SOL_SOCKET, SO_BROADCAST, (void *)&bopt, sizeof(bopt)) < 0) {
		close(socksend); return 2;
	}

#ifdef OSX
	int ifdx = if_nametoindex(intf);
	if (setsockopt(socksend, IPPROTO_IP, IP_BOUND_IF, (void *)&ifdx, sizeof(ifdx)) < 0) {
		close(socksend); return 3;
	}
#endif

#ifdef NIX
	if (setsockopt(socksend, SOL_SOCKET, SO_BINDTODEVICE, intf, strlen(intf)) < 0) {
		close(socksend); return 3;
	}
#endif

	memset(&addrsend, 0, sizeof(addrsend));
	addrsend.sin_family = AF_INET;
	addrsend.sin_addr.s_addr = inet_addr(dest);
	addrsend.sin_port = htons(PORT);

	if (sendto(socksend, data, leng, 0, (struct sockaddr *)&addrsend, sizeof(addrsend)) < 1) {
		close(socksend); return 5;
	}

	close(socksend); return 0;
}

int main(int argc, char *argv[]) {

	int newb = -1, newp = -1, stat, bsec = 5, psec = 10, isec = 15;
	unsigned long last = time(0), proc = time(0), nsec;
	const char *ebsec = getenv("BCAST"), *epsec = getenv("PROCS");
	const char *eisec = getenv("EXPIRED"), *forw = getenv("RELAY");
	char *pass = argv[2], *apn_dev = argv[3], *intf, *temp;

	int sockrecv, klen, mlen, slen, ilen, part;
	int ipid = 255, netm = 24;
	struct sockaddr_in addrrecv;
	struct timeval wait;

	char buff[BSIZ], line[BSIZ], apds[BSIZ], devs[BSIZ], host[32];
	unsigned char sign[32], arck[256], encr[BSIZ];
	unsigned char *pntr;
	unsigned int ando, oend, begi, endi;
	struct maps wifi[APNS+1];

	if (ebsec != NULL) { bsec = atoi(ebsec); }
	if (epsec != NULL) { psec = atoi(epsec); }
	if (eisec != NULL) { isec = atoi(eisec); }
	if (argc < 5) {
		printf("Usage: barp [out-file] [key] [ap1-dev ap2-dev ... my-ip/mask] [peer1|dev1] [peer2|dev2] ...\n");
		return 1;
	}

	bzero(host, 32 * sizeof(char));
	bzero(apds, BSIZ * sizeof(char)); apds[0] = ' '; temp = apds+1;
	for (int x = 0, z = -1; x < strlen(apn_dev); ++x) {
		if (apn_dev[x] == '.') { ipid = atoi(apn_dev+x+1); }
		if (apn_dev[x] == '/') { netm = atoi(apn_dev+x+1); z = -1; }
		if ((-1 < z) && (z < 30)) { host[z] = apn_dev[x]; ++z; host[z] = '\0'; }
		if (apn_dev[x] == ' ') { z = 0; host[z] = '\0'; }
		*temp = apn_dev[x]; ++temp;
	}
	mask(&ando, &oend, netm); begi = (ntol(host) & ando); endi = (begi + oend);

	bzero(devs, BSIZ * sizeof(char));
	for (int y = 4; y < argc; ++y) {
		if ((intf = strchr(argv[y], '|')) != NULL) {
			bzero(line, BSIZ * sizeof(char));
			strncpy(line, devs, BSIZ - 8);
			bzero(devs, BSIZ * sizeof(char));
			snprintf(devs, BSIZ - 8, "%s%s ", line, intf+1);
		}
	}

	wait.tv_sec = 0;
	wait.tv_usec = 333000; /* 1,000,000 microseconds == 1 second */
	if ((sockrecv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		return 1;
	}
	if (setsockopt(sockrecv, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait)) < 0) {
		return 2;
	}

	memset(&addrrecv, 0, sizeof(addrrecv));
	addrrecv.sin_family = AF_INET;
	addrrecv.sin_addr.s_addr = htonl(INADDR_ANY);
	addrrecv.sin_port = htons(PORT);
	if (bind(sockrecv, (struct sockaddr *)&addrrecv, sizeof(addrrecv)) < 0) {
		return 3;
	}

	bzero(wifi, (APNS+1) * sizeof(struct maps)); klen = strlen(pass);
	srand(time(0));
	while (1) {
		nsec = time(0);


		/* broadcast: client */
		if ((nsec - last) >= bsec) {
			if ((newb < 0) && (newp < 0)) { last = nsec; newb = fork(); }
		}

		if (newb == 0) {
			printf("b"); fflush(stdout);

			bzero(line, BSIZ * sizeof(char));
#ifdef OSX
			snprintf(line, BSIZ - 8, "echo '1 11:22:33:44:55:66 10.2.3.45' > /tmp/apc.leases");
#endif
#ifdef NIX
			snprintf(line, BSIZ - 8, "clients_ap.sh %s", apds);
			system(line);

			bzero(line, BSIZ * sizeof(char));
			snprintf(line, BSIZ - 8, "clients_stat.sh %s %s %s", argv[1], apds, devs);
			system(line);

			bzero(line, BSIZ * sizeof(char));
			snprintf(line, BSIZ - 8, "clients_zmerge.sh");
#endif
			system(line);

			bzero(line, BSIZ * sizeof(char)); part = 0; temp = buff;

			FILE *fobj = fopen("/tmp/apc.leases", "r");
			while ((fobj != NULL) && (temp != NULL)) {
				bzero(buff, BSIZ * sizeof(char));
				strncpy(buff, line, strlen(line)); mlen = strlen(line);

				while (1) {
					bzero(line, BSIZ * sizeof(char));
					temp = fgets(line, BSIZ - 8, fobj);
					if (temp != NULL) {
						if ((mlen + strlen(line)) < (BSIZ - 256)) {
							strncpy(&(buff[mlen]), line, strlen(line));
							mlen += strlen(line);
						} else { break; }
					} else { break; }
				}

				if ((part == 0) && (mlen < 24)) {
					strncpy(buff, "        ", 8); mlen = strlen(buff);
				}

				if ((part < PSIZ) && ((part == 0) || (mlen > 0))) {
					fill(encr, last, host, part); pntr = encr;
					slen = keys(arck, pntr, pass, klen); pntr += slen;
					ciph(pntr, (unsigned char *)buff, mlen, arck, 'e'); pntr += mlen;
					hmac(pntr, encr, slen+mlen, (unsigned char *)pass, klen);
					encr[15] = ipid;
					for (int z = 0; z < 2; ++z) {
						for (int y = 4; y < argc; ++y) {
							if ((intf = strchr(argv[y], '|')) != NULL) {
								if (z == 0) { delb(intf+1); }
								else { ssnd(intf+1, encr, slen+mlen+32); }
							}
						}
					}
					++part;
				}
			}
			sfclose(fobj);

			exit(0);
		}


		/* broadcast: process */
		if ((nsec - proc) >= psec) {
			if ((newb < 0) && (newp < 0)) { proc = nsec; newp = fork(); }
		}

		if (newp == 0) {
			printf("p"); fflush(stdout);

			/* write out all the recv'd ap client buffers */
			FILE *fobj = fopen("/tmp/wifi.tmp", "w");
			if (fobj != NULL) {
				for (int x = 0; x < APNS; ++x) {
					if ((nsec - wifi[x].last[PSIZ]) > isec) { continue; }
					int cmpt = 0;
					for (int y = 0; y < PSIZ; ++y) {
						if (wifi[x].last[y] > cmpt) { cmpt = wifi[x].last[y]; }
					}
					for (int y = 0; (y < PSIZ) && (cmpt > 0); ++y) {
						temp = wifi[x].bufs[y]; part = 0;
						if (wifi[x].last[y] != cmpt) { continue; }
						for (int z = 0; (z < (BSIZ - 32)) && (temp[z] != '\0'); ++z) {
							if ((z > part) && (temp[z] == '\n')) {
								bzero(line, BSIZ * sizeof(char));
								bcopy(&(temp[part]), line, z-part);
								snprintf(&(line[z-part]), 19, " %d.%d.%d.%d\n", \
									wifi[x].host[0], wifi[x].host[1], wifi[x].host[2], wifi[x].host[3]);
								part = (z + 1); if (strchr(line, ':') != NULL) {
									fwrite(line, sizeof(char), strlen(line), fobj);
								}
							}
						}
					}
				}
			}
			sfclose(fobj);

			bzero(line, BSIZ * sizeof(char));
			snprintf(line, BSIZ - 8, "( cat /tmp/wifi.tmp ; cat /tmp/apc.leases | sed -e 's/$/ %s/' ) | grep -iv '00:00:00:00:00:00' | sort > /tmp/sarp.tmp", host);
			system(line);

			/* - processing:
					-- get a list of known peers / aps
					-- check if each host is connected to us or through another peer
					-- find the lowest ap association time as the best connection / route
					-- collect each assigned ip address per mac address from any network dhcp servers
					-- check if the assigned address is within our provided network cidr mask
					-- write out a standard mapping format that can be used to set static arp entries
			*/
			int pidx, plen = 0, wlen = 0; char peer[BSIZ+1][96], wlan[BSIZ+1][96];
			struct proc seen[BSIZ]; bzero(seen, BSIZ * sizeof(struct proc));

			FILE *fob0 = fopen("/tmp/sarp.tmp", "r");
			FILE *fob1 = fopen("/tmp/wifi.aps", "r");
			FILE *fob2 = fopen("/tmp/wifi.leases", "r");
			if ((fob0 != NULL) && (fob1 != NULL) && (fob2 != NULL)) {
				bz(line); for (int x = 0; (x < BSIZ) && (fgets(line, BSIZ - 8, fob1) != NULL); ++x) {
					bzero(peer[x], 96 * sizeof(char)); strncpy(peer[x], line, 90);
					plen = (x + 1); bz(line);
				}

				bz(line); for (int x = 0; (x < BSIZ) && (fgets(line, BSIZ - 8, fob2) != NULL); ++x) {
					bzero(wlan[x], 96 * sizeof(char)); strncpy(wlan[x], line, 90);
					wlen = (x + 1); bz(line);
				}

				bz(line); while ((temp = fgets(line, BSIZ - 8, fob0)) != NULL) {
					char *d = NULL, *m = NULL, *a = NULL, *r = NULL, *s = NULL, *b = NULL;

					/* split the line string by spaces: [time] [mac] [adr] [peer] */
					temp = strschr(temp, ' '); if (temp != NULL) { ++temp; m = temp; b = m; }
					temp = strschr(temp, ' '); if (temp != NULL) { *temp = '\0'; ++temp; a = temp; }
					temp = strschr(temp, ' '); if (temp != NULL) { *temp = '\0'; ++temp; r = temp; s = r; }
					temp = strschr(temp, '\n'); if (temp != NULL) { *temp = '\0'; }
					if (r == NULL) { bz(line); continue; }

					/* check if we have processed this mac address already */
					if ((pidx = find(m, seen, BSIZ)) > 65535) {
						/* check if the peer address is us and if so copy and use our dev */
						if (strlncmp(r, host, strlen(host)) == 0) {
							bzero(wlan[BSIZ], 96 * sizeof(char));
							snprintf(wlan[BSIZ], 90, " %s ", m);
							for (int x = 0; x < wlen; ++x) {
								temp = strstr(wlan[x], wlan[BSIZ]);
								if (temp != NULL) {
									temp += strlen(wlan[BSIZ]); d = temp;
									while (*temp != '\0') { if (*temp == '\n') { *temp = '\0'; } ++temp; }
									break;
								}
							}
						}

						/* if peer is remote then check if we know the their address and device */
						if (d == NULL) {
							bzero(buff, BSIZ * sizeof(char));
							snprintf(buff, BSIZ - 8, "%s ", s);
							for (int x = 0; x < plen; ++x) {
								if (strncmp(peer[x], buff, strlen(buff)) == 0) {
									bzero(peer[BSIZ], 96 * sizeof(char));
									strncpy(peer[BSIZ], peer[x], 90);
									char *tmp0 = strstr(peer[BSIZ], " dev ");
									char *tmp1 = strstr(peer[BSIZ], " lladdr ");
									if ((tmp0 != NULL) && (tmp1 != NULL)) {
										d = tmp0 + strlen(" dev "); temp = d;
										while ((*temp != ' ') && (*temp != '\0')) { ++temp; } *temp = '\0';
										b = tmp1 + strlen(" lladdr "); temp = b;
										while ((*temp != ' ') && (*temp != '\0')) { ++temp; } *temp = '\0';
										break;
									}
								}
							}
						}

						/* if we have all the required client info then store it now */
						if (d != NULL) {
							pidx = ((pidx >> 16) - 1);
							strncpy(seen[pidx].dev, d, 30);
							strncpy(seen[pidx].mac, b, 30);
							strncpy(seen[pidx].low, r, 30);
							strncpy(seen[pidx].key, m, 30);
						}
					}

					/* append this client address to their static mapping info */
					unsigned int inum = ntol(a);
					if ((-1 < pidx) && (pidx < BSIZ) && (begi < inum) && (inum < endi)) {
						for (int z = 0; z < APNS; ++z) {
							temp = seen[pidx].adr[z]; slen = strlen(temp);
							if (slen < 1) { strncpy(temp, a, 30); break; }
							if (strlncmp(a, temp, slen) == 0) { break; }
						}
					}

					bz(line);
				}

				bzero(buff, BSIZ * sizeof(char));
				snprintf(buff, BSIZ - 8, "%s.tmp", argv[1]);
				FILE *fob2 = fopen(buff, "w");
				for (int x = 0; (x < BSIZ) && (seen[x].key[0] != '\0') && (fob2 != NULL); ++x) {
					for (int y = 0; (y < APNS) && (seen[x].adr[y][0] != '\0'); ++y) {
						fprintf(fob2, "%s %s %s\n", seen[x].dev, seen[x].mac, seen[x].adr[y]);
					}
				}
				sfclose(fob2);

				bzero(line, BSIZ * sizeof(char));
				snprintf(line, BSIZ - 8, "o=$(cat %s | sort) ; a=$(echo \"$o\" | md5sum) ; b=$(cat %s | md5sum) ; test \"$a\" != \"$b\" && echo \"$o\" > %s && mv %s %s", buff, argv[1], buff, buff, argv[1]);
				system(line);
			}
			sfclose(fob0); sfclose(fob1); sfclose(fob2);

			bzero(line, BSIZ * sizeof(char));
			snprintf(line, BSIZ - 8, "clients_zrem.sh %s %s %s", argv[1], apds, devs);
			system(line);

			exit(0);
		}


		/* broadcast: server */
		ilen = min(15+APNS+klen, 128); slen = 32; pntr = NULL;
		bzero(encr, BSIZ * sizeof(unsigned char));
		if ((mlen = recvfrom(sockrecv, encr, BSIZ - 8, 0, NULL, 0)) > (ilen + slen)) {
			int indx = -1, zero = -1, sndr = -1, cmpt = 0;
			unsigned char iips[APNS];

			part = encr[4];
			bcopy(&(encr[15]), iips, APNS * sizeof(unsigned char));
			bzero(&(encr[15]), APNS * sizeof(unsigned char));
			for (int x = 0; x < APNS; ++x) {
				if ((indx < 0) && (iips[x] == ipid)) { indx = x; }
				if ((zero < 0) && (iips[x] == 0)) { zero = x; }
				if ((sndr < 0) && (iips[x] == encr[13])) { sndr = x; }
			}

			if ((indx < 0) && (zero > -1) && (sndr > -1) && (ipid != encr[13])) {
				hmac(sign, encr, mlen-slen, (unsigned char *)pass, klen);
				pntr = &(encr[mlen-slen]);
			}

			if ((pntr != NULL) && (bcmp(pntr, sign, slen * sizeof(unsigned char)) == 0)) {
				keys(arck, encr, pass, klen); pntr = (encr + ilen);
				bzero(buff, BSIZ * sizeof(char));
				ciph((unsigned char *)buff, pntr, mlen-(ilen+slen), arck, 'd');
				for (int x = 0; x < 4; ++x) {
					cmpt = (cmpt << 8); cmpt += encr[3-x];
				}

				indx = -1;
				for (int x = 0; x < APNS; ++x) {
					if (bcmp((wifi[x]).host, &(encr[10]), 4) == 0) {
						indx = x; break;
					} else if (bcmp((wifi[x]).host, (wifi[APNS]).host, 4) == 0) {
						indx = x; bcopy(&(encr[10]), (wifi[x]).host, 4); break;
					}
				}

				if ((indx > -1) && (part < PSIZ) && (cmpt > ((wifi[indx]).last)[part])) {
					printf("Storing [%d][%d] for [%d][%d.%d.%d.%d] [...] \n", \
						cmpt, part, indx, (wifi[indx]).host[0], \
						(wifi[indx]).host[1], (wifi[indx]).host[2], (wifi[indx]).host[3]);

					bcopy(buff, ((wifi[indx]).bufs)[part], BSIZ * sizeof(char));
					((wifi[indx]).last)[part] = cmpt;
					((wifi[indx]).last)[PSIZ] = time(0);

					/* broadcast: forward */
					if (forw != NULL) {
						printf("f"); fflush(stdout);
						iips[zero] = ipid;
						bcopy(iips, &(encr[15]), APNS * sizeof(unsigned char));
						for (int z = 0; z < 2; ++z) {
							for (int y = 4; y < argc; ++y) {
								if ((intf = strchr(argv[y], '|')) != NULL) {
									if (z == 0) { delb(intf+1); }
									else { ssnd(intf+1, encr, mlen); }
								}
							}
						}
					}
				}
			}

		}

		pid_t prss = waitpid(-1, &stat, WNOHANG);
		if (prss < 0) { newb = -1; newp = -1; }


		printf("."); fflush(stdout);
	}

	return 0;
}
