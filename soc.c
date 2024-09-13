/* gcc -O3 -Wall -o soc ... # -DLOCL -Wno-format-truncation # -fsanitize=address -g */

#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "enc.c"
#include "inc.c"

#define LIST 8
#define SIXT 16
#define MINP 42
#define LINT 96
#define NUMI 128
#define MAXP 1337

#define FINX -1
#define PING -2

#define FINL 90
#define PINL 91

#define INVL -1

#define NOOP 0x00
#define OKOP 0x01
#define ENDP 0x03
#define STOP 0x10
#define MSKP 0x0f

int MINT = 96, NUMT = 256;
int WAIT[] = { 0, 45, 450000, 90, 45, 15 };
char *PMAP[] = { "nul", "udp", "tcp", "con", "nat", "eco" };
int DIDX = 0, DLEN = LIST;
char DOBJ[LIST][LINT];

typedef struct header_packet {
	char_u prot, kind, leng[2], sadr[4], sprt[2], dadr[4], dprt[2];
} pckt_h;

typedef struct list_inet {
	numb_u init, addr, mask;
} inet_l;

typedef struct list_cache {
	int prta, prtb;
	char adra[LINT], adrb[LINT];
	time_t last;
} cach_l;

typedef struct buffer_data {
	int leng;
	char_u buff[BMAX];
} data_b;

typedef struct object_args {
	int lprt, rprt;
	char *prot, *cmds, *skey, *nots;
	char *larg, *rarg, *ladr, *radr;
} args_o;

typedef struct object_thread {
	int rprt;
	int indx, excl, stat, sign, wait;
	int kind[2], sock[2], port[2], rpwp[2];
	char adrs[2][LINE];
	struct sockaddr_in addr[2];
	time_t last, lock[2];
	pthread_t thrp;
	numb_u thid, ptid[SIXT][4];
	data_b buff[2];
	pckt_h head[2];
	ciph_o ciph[2];
	args_o *args;
	inet_l *nots;
} thrd_o;

typedef struct object_process {
	int stat, sock, conn;
	int indx, leng, kind;
	int rpwp[2];
	struct sockaddr_in addr;
	numb_u thid;
	char_u buff[BMAX];
	ciph_o ciph;
	args_o *args;
	cach_l *cnat;
	inet_l *nots;
	thrd_o *thrd;
} proc_o;

void sigp(void) {
	struct sigaction a = { 0 };
	a.sa_handler = SIG_IGN;
	a.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &a, NULL);
}

char *getd() {
	DIDX = ((DIDX + 1) % DLEN);
	char *pntr = DOBJ[DIDX];
	char temp[LINT];
	time_t rsec;
	struct tm *dobj;
	struct timespec nobj;
	time(&(rsec));
	dobj = localtime(&(rsec));
	clock_gettime(CLOCK_MONOTONIC_RAW, &(nobj));
	bzero(temp, LINT);
	strftime(temp, LINT - 8, "%Y/%m/%d-%H:%M:%S", dobj);
	bzero(pntr, LINT);
	snprintf(pntr, LINT - 8, "%s.%09ld", temp, nobj.tv_nsec);
	return pntr;
}

void inet(inet_l *objc, char *addr) {
	char *pntr = repl(addr, '/');
	numb_u mask = 0;
	numb_u inum = inet_addr(addr);
	if (pntr != NULL) { mask = atoi(pntr); }
	objc->mask = 0xffffffff;
	if ((0 < mask) && (mask < 32)) {
		objc->mask = (objc->mask - ((1 << (32 - mask)) - 1));
	}
	objc->addr = (((inum & 0xff) << 24) | ((inum & 0xff00) << 8) | ((inum & 0xff0000) >> 8) | ((inum & 0xff000000) >> 24));
	objc->addr = (objc->addr & objc->mask);
	objc->init = 1;
}

int isin(inet_l *objc, char *addr) {
	numb_u nadr;
	inet_l iadr;
	inet(&(iadr), addr);
	for (int x = 0; x < LIST; ++x) {
		if (objc[x].init != 1) { continue; }
		nadr = (iadr.addr & objc[x].mask);
		if (nadr == objc[x].addr) { return 1; }
	}
	return 0;
}

void load(inet_l *objc, char *nots) {
	int leng = 0;
	char info[LINT];
	if (nots != NULL) {
		FILE *fobj = fopen(nots, "r");
		while (1) {
			bzero(info, LINT);
			if (fgets(info, LINT - 8, fobj) == NULL) { break; }
			if ((info[0] == '\0') || (info[0] == ' ') || (info[0] == '#')) { continue; }
			if ((info[0] == '\t') || (info[0] == '\r') || (info[0] == '\n')) { continue; }
			if (leng < LIST) {
				inet(&(objc[leng]), info);
				leng += 1;
			}
		}
		fclose(fobj);
	}
}

int recq(int fdes, unsigned char *buff, int size) {
	int sels = 0, hlen = 4;
	int rlen = 0, retl = 0;
	int leng = 4, trys = 5;
	int maxh = (sizeof(pckt_h) + sizeof(ciph_h));
	unsigned char *hptr = buff, *pntr = buff;
	pckt_h head;
	fd_set rfds;
	struct timeval tval;
	if (size < 1) { size = BTCP; sels = 1; }
	while ((leng > 0) && (trys > 0)) {
		if ((leng - maxh) > (size - retl)) {
			printf("[%s] erro recq len [%d] [%d][%d] [%d]\n", getd(), leng, size, retl, size - retl);
			return -2;
		}
		if (sels == 1) {
			FD_ZERO(&(rfds));
			FD_SET(fdes, &(rfds));
			tval.tv_sec = 5;
			tval.tv_usec = 0;
			if (select(fdes+1, &(rfds), NULL, NULL, &(tval)) < 0) {
				return -1;
			}
		}
		if ((sels != 1) || FD_ISSET(fdes, &(rfds))) {
			rlen = read(fdes, pntr, leng);
			if (rlen < BONE) { return 0; }
			pntr += rlen; leng -= rlen;
			retl += rlen;
			if ((leng == 0) && (retl == hlen)) {
				bcopy(hptr, &(head), sizeof(pckt_h));
				UPACK16(leng, head.leng); hptr += leng;
				if (leng > hlen) { leng = (leng - hlen); }
			}
		} else { trys -= 1; }
	}
	if (leng > 0) {
		printf("[%s] warn recq end [%d]\n", getd(), leng);
	}
	return retl;
}

int recp(int fdes, unsigned char *buff, int size) {
	int rlen, wlen;
	rlen = read(fdes, buff, 2);
	UPACK16(wlen, buff);
	if ((wlen < BONE) || (size < wlen)) {
		printf("[%s] erro recp size [%d]\n", getd(), wlen);
		return -9;
	}
	rlen = read(fdes, buff, wlen);
	if (rlen != wlen) {
		printf("[%s] warn recp note [%d] [%d]\n", getd(), rlen, wlen);
	}
	return rlen;
}

int recu(int fdes, unsigned char *buff, int size) {
	int leng = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	return recvfrom(fdes, buff, size, 0, (struct sockaddr *)&(addr), (unsigned int *)&(leng));
}

int sent(int sock, unsigned char *buff, int leng) {
	int numb = 0, size = 0;
	while (leng > 0) {
		size = leng;
		if (size > 8192) { size = 8192; }
		numb = send(sock, buff, size, MSG_NOSIGNAL);
		if (numb < BONE) { break; }
		buff += numb; leng -= numb;
	}
	return numb;
}

int shft(unsigned char *buff, int offs, int leng) {
	int indx = 0;
	for (indx = 0; (offs + indx) < leng; ++indx) {
		buff[indx] = buff[offs+indx];
	}
	return indx;
}

void hexs(char *pref, unsigned char *data, int *leng) {
	printf("hexs %s [%d][", pref, *leng);
	for (int x = 0; (x < BMAX) && (x < *leng); ++x) {
		printf("\\x%02x", data[x]);
	}
	printf("]\n");
}

int xmit(thrd_o *args, unsigned char *buff, int *leng, int ptid, char mode) {
	int i = 1;
	if (mode == 's') { i = 0; }
	int kind = args->kind[i];
	int sock = args->sock[i];
	struct sockaddr_in *addr = &(args->addr[i]);
	pckt_h *head = &(args->head[i]);
	ciph_o *ciph = &(args->ciph[i]);

	int indx = 0, size = 0, widx = 0;
	int stop = 0, show = 0, retl = 0;
	int maxh = sizeof(pckt_h);
	int slen = sizeof(struct sockaddr_in);
	int rlen = 0, wlen = 0, zlen = *leng;
	unsigned char data[BMAX], temp[BMAX];
	time_t secs = time(NULL);

	char_u *pntr = data;

	if (zlen == FINX) { zlen = 1; stop = FINX; }
	if (zlen == PING) { zlen = 1; stop = PING; }

	show = (secs - args->lock[0]);
	if (stop != 0) { show = 1; }

	if (args->excl == 1) {
		if (kind == SOCK_DGRAM) {
			wlen = sendto(sock, buff, zlen, 0, (struct sockaddr *)addr, slen);
		} else {
			wlen = sent(sock, buff, zlen);
		}
		*leng = 0;
		args->last = secs;
		return wlen;
	}

	rlen = (zlen + maxh);
	PACKU16(head->leng, rlen);
	head->kind = 1;
	widx = maxm(head->prot, 2, 0);

	if (stop == FINX) { head->kind = FINL; }
	if (stop == PING) { head->kind = PINL; }

	for (size = maxh; (size < BMAX) && (indx < zlen); ++size, ++indx) {
		data[size] = buff[indx];
	}
	wlen = (size - maxh); indx = 0;
	if (wlen < BONE) { return -1; }
	bcopy(head, data, maxh);
	wlen = wrap(ciph, temp, BMAX, data, size, 'e');
	if (wlen > 0) { pntr = temp; size = wlen; }
	if (wlen < 0) { return wlen; }

	if (show >= 1) {
		printf("[%s] info xmit snd %s [%d] [%d/%d] [%d] [%s:%d]->[%s:%d]\n", getd(), PMAP[widx], stop, indx, *leng, size, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);
		args->lock[0] = secs;
	}

	retl = sent(sock, pntr, size);
	if (retl < BONE) { return -3; }
	*leng = 0;

	if (stop == 0) { args->last = secs; }
	return retl;
}

void xfin(thrd_o *args, int rprt, int stat) {
	char mode = 'c';
	int side = 1, indx = 0, leng = 0;
	if (stat == FINX) { leng = FINX; indx = 4; }
	if (stat == PING) { leng = PING; indx = 5; }
	if ((leng < 0) && (args->excl == 0)) {
		if ((stat == FINX) || (stat == PING)) { args->ptid[indx][0] = 0; args->ptid[indx][1] = 0; }
		if (rprt == 0) { mode = 's'; side = 0; }
		xmit(args, args->buff[side].buff, &leng, indx, mode);
	}
}

int xbuf(thrd_o *args, unsigned char *buff, int *leng, int ptid, char mode) {
	int i = 1;
	if (mode == 's') { i = 0; }
	int kind = args->kind[i];
	int sock = args->sock[i];
	struct sockaddr_in *addr = &(args->addr[i]);
	pckt_h *head = &(args->head[i]);
	ciph_o *ciph = &(args->ciph[i]);

	int indx = 0, size = 0, widx = 0;
	int stop = 0, show = 0, retl = 0;
	int hlen = sizeof(pckt_h), clen = sizeof(ciph_h);
	int slen = sizeof(struct sockaddr_in);
	int olen = 0, wlen = 0, rlen = 0;
	unsigned char data[BMAX];
	time_t secs = time(NULL);

	char_u *pntr = buff;

	size = *leng;
	show = (secs - args->lock[1]);
	if (stop != 0) { show = 1; }

	/*if (args->excl == 1) {
		if (kind == SOCK_DGRAM) {
			wlen = sendto(sock, buff, size, 0, (struct sockaddr *)addr, slen);
		} else {
			wlen = sent(sock, buff, size);
		}
		*leng = 0;
		args->last = secs;
		return wlen;
	}*/

	wlen = wrap(ciph, data, BMAX, buff, size, 'd');
	if (wlen > 0) { pntr = data; size = wlen; olen += clen; }
	if (wlen < 0) { return wlen; }

	bcopy(pntr, head, hlen);
	olen += hlen;
	pntr += hlen;

	UPACK16(rlen, head->leng);
	size = (rlen - hlen);
	widx = maxm(head->prot, 2, 0);

	if (show >= 1) {
		printf("[%s] info xbuf rcv %s [%d] [%d/%d] [%d] [%s:%d]->[%s:%d]\n", getd(), PMAP[widx], stop, indx, size, *leng, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);
		args->lock[1] = secs;
	}

	if (head->kind == FINL) {
		return -9;
	}
	if (head->kind == PINL) {
		*leng = shft(buff, olen+size, *leng);
		return 0;
	}
	if ((size < BONE) || (BTCP < size)) {
		return -2;
	}
	if (size > (*leng - olen)) {
		printf("[%s] erro xbuf size [%d] [%d][%d] [%d]\n", getd(), size, *leng, olen, *leng - olen);
		return -8;
	}

	if (kind == SOCK_DGRAM) {
		wlen = sendto(sock, pntr, size, 0, (struct sockaddr *)addr, slen);
	} else {
		wlen = sent(sock, pntr, size);
	}
	if (wlen < BONE) { return -3; }
	*leng = shft(buff, olen+size, *leng);

	if (stop == 0) { args->last = secs; }
	return retl;
}

void *xfer(void *argp) {
	thrd_o *args = (thrd_o *)argp;

	int stat = OKOP, side = INVL;
	int fmax = 0, widx = 0, extr = 0, rlen = 0, wlen = 0;
	int sock, conn, erro;
	unsigned char data[BMAX], temp[BMAX];
	time_t secs, last = time(NULL);
	fd_set rfds;
	struct timeval tval;

	int pktl = sizeof(pckt_h);
	int *clen = &(args->buff[0].leng);
	int *slen = &(args->buff[1].leng);
	unsigned int thid = args->thid;
	struct sockaddr_in *addr = &(args->addr[1]);
	pckt_h *ched = &(args->head[0]);
	pckt_h *shed = &(args->head[1]);
	char_u *cbuf = args->buff[0].buff;
	char_u *sbuf = args->buff[1].buff;
	args_o *argv = args->args;
	ciph_o *ciph = &(args->ciph[0]);

	for (int x = 0; x < 4; ++x) {
		args->ptid[x][0] = (thid + 1 + x);
		args->ptid[x][1] = 1; args->ptid[x][2] = 1; args->ptid[x][3] = 1;
	}

	if (stat == OKOP) {
		bzero(args->adrs[1], LINT);
		if (args->rprt > 0) {
			comd(args->adrs[1], &(args->port[1]), ILEN, argv->cmds, argv->prot, args->adrs[0], args->port[0]);
			if (args->adrs[1][0] == '\0') {
				stat = NOOP;
			} else {
				if (strcmp(argv->prot, "udp") == 0) {
					ched->prot = 1;
				} else {
					ched->prot = 2;
				}
				args->kind[1] = SOCK_STREAM;
				PACKU32(ched->sadr, inet_addr(args->adrs[0]));
				PACKU16(ched->sprt, args->port[0]);
				PACKU32(ched->dadr, inet_addr(args->adrs[1]));
				PACKU16(ched->dprt, args->port[1]);
				if (isin(args->nots, args->adrs[1]) == 1) {
					args->excl = 1;
					if (ched->prot == 1) {
						args->kind[1] = SOCK_DGRAM;
					} else {
						args->kind[1] = SOCK_STREAM;
					}
				}
			}
		} else {
			extr = 5;
			bzero(cbuf, BTCP); *clen = 0;
			rlen = recq(args->sock[0], cbuf, -1);
			if (rlen > 0) { bcopy(cbuf, data, rlen); *clen = rlen; }
			wlen = wrap(ciph, temp, BMAX, data, rlen, 'd');
			if (wlen > 0) { bcopy(temp, data, rlen); rlen = wlen; }
			if (wlen < 0) { rlen = 0; }
			if (rlen < 1) { stat = -1; }
			if (rlen > 0) {
				bcopy(data, ched, pktl);
				ched->prot = maxm(ched->prot, 2, 0);
				if (ched->prot == 1) {
					args->kind[1] = SOCK_DGRAM;
				} else {
					args->kind[1] = SOCK_STREAM;
				}
				snprintf(args->adrs[0], ILEN, "%d.%d.%d.%d", ched->sadr[3], ched->sadr[2], ched->sadr[1], ched->sadr[0]);
				UPACK16(args->port[0], ched->sprt);
				snprintf(args->adrs[1], ILEN, "%d.%d.%d.%d", ched->dadr[3], ched->dadr[2], ched->dadr[1], ched->dadr[0]);
				UPACK16(args->port[1], ched->dprt);
			}
		}
		bcopy(ched, shed, pktl);
		widx = shed->prot;
		args->wait = (WAIT[widx] + extr);
	}

	printf("[%s] info xfer syn %s [%s] [%d:%d:%d:%d] [%d:%d] [0x%08x] [%s:%d]->[%s:%d]\n", getd(), argv->prot, PMAP[widx], args->excl, stat, args->stat, args->sign, args->wait, args->rprt, thid, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);

	if (stat == OKOP) {
		bzero(addr, sizeof(struct sockaddr_in));
		if ((args->rprt > 0) && (args->excl == 0)) {
			addr->sin_family = AF_INET;
			addr->sin_port = htons(args->rprt);
			addr->sin_addr.s_addr = inet_addr(argv->radr);
			args->sock[1] = socket(AF_INET, args->kind[1], 0);
			if (args->kind[1] == SOCK_STREAM) {
				if ((erro = connect(args->sock[1], (struct sockaddr *)addr, sizeof(struct sockaddr_in))) != 0) {
					stat = erro;
				}
			}
		} else {
			addr->sin_family = AF_INET;
			addr->sin_port = htons(args->port[1]);
			addr->sin_addr.s_addr = inet_addr(args->adrs[1]);
			args->sock[1] = socket(AF_INET, args->kind[1], 0);
			if (args->kind[1] == SOCK_STREAM) {
				if ((erro = connect(args->sock[1], (struct sockaddr *)addr, sizeof(struct sockaddr_in))) != 0) {
					stat = erro;
				}
			}
		}
	}

	if (stat == OKOP) {
		conn = args->sock[0];
		sock = args->sock[1];
		if (args->rpwp[0] > 0) {
			side = args->sock[0];
			conn = args->rpwp[0];
		}
		if ((*clen > 0) && (args->kind[0] == SOCK_STREAM)) {
			xbuf(args, cbuf, clen, 1, 'c');
		}
		bzero(cbuf, BMAX); *clen = 0;
	} else { conn = -1; sock = -1; }

	while ((stat == OKOP) && (args->stat == OKOP) && (args->sign == OKOP)) {
		FD_ZERO(&(rfds));
		FD_SET(conn, &(rfds));
		FD_SET(sock, &(rfds));
		fmax = (maxs(conn, sock) + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro xfer sels [%d] [0x%08x]\n", getd(), erro, thid);
			stat = erro; break;
		}
		secs = time(NULL);

		if (FD_ISSET(conn, &(rfds))) {
			bzero(cbuf, BMAX); *clen = 0;
			if (args->rprt == 0) {
				rlen = recq(conn, cbuf, BTCP);
			} else if (side != -1) {
				rlen = recp(conn, cbuf, BTCP);
			} else {
				rlen = read(conn, cbuf, BTCP);
			}
			if (rlen < 1) {
				if (rlen != 0) { printf("[%s] erro xfer read conn [%d:%d] [%s] [%d] [0x%08x]\n", getd(), rlen, errno, strerror(errno), side, thid); }
				stat = rlen; break;
			}
			if ((*clen + rlen) > BMAX) { printf("[%s] erro xfer conn len max [%d][%d]\n", getd(), *clen, rlen); stat = -90; break; }
			if (rlen > 0) { *clen += rlen; }
			if ((args->rprt > 0) || (args->excl == 1)) {
				if ((erro = xmit(args, cbuf, clen, 0, 'c')) < 1) {
					if (erro != -9) { printf("[%s] erro xfer xmit conn [%d] [0x%08x]\n", getd(), erro, thid); }
					stat = erro; break;
				}
			} else {
				if ((erro = xbuf(args, cbuf, clen, 1, 'c')) < 0) {
					if (erro != -9) { printf("[%s] erro xfer xbuf conn [%d] [0x%08x]\n", getd(), erro, thid); }
					stat = erro; break;
				}
			}
		}

		if (FD_ISSET(sock, &(rfds))) {
			bzero(sbuf, BMAX); *slen = 0;
			if ((args->rprt > 0) && (args->excl == 0)) {
				rlen = recq(sock, sbuf, BTCP);
			} else if (args->kind[1] == SOCK_DGRAM) {
				rlen = recu(sock, sbuf, BUDP);
			} else {
				rlen = read(sock, sbuf, BTCP);
			}
			if (rlen < 1) {
				if (rlen != 0) { printf("[%s] erro xfer read sock [%d:%d] [%s] [%d] [0x%08x]\n", getd(), rlen, errno, strerror(errno), side, thid); }
				stat = rlen; break;
			}
			if ((*slen + rlen) > BMAX) { printf("[%s] erro xfer sock len max [%d][%d]\n", getd(), *slen, rlen); stat = -90; break; }
			if (rlen > 0) { *slen += rlen; }
			if ((args->rprt > 0) && (args->excl == 0)) {
				if ((erro = xbuf(args, sbuf, slen, 2, 's')) < 0) {
					if (erro != -9) { printf("[%s] erro xfer xbuf sock [%d] [0x%08x]\n", getd(), erro, thid); }
					stat = erro; break;
				}
			} else {
				if ((erro = xmit(args, sbuf, slen, 3, 's')) < 1) {
					if (erro != -9) { printf("[%s] erro xfer xmit sock [%d] [0x%08x]\n", getd(), erro, thid); }
					stat = erro; break;
				}
			}
		}

		if ((secs - args->last) >= args->wait) {
			stat = NOOP; break;
		} else if ((secs - args->last) >= WAIT[5]) {
			if ((secs - last) >= WAIT[5]) {
				xfin(args, args->rprt, PING);
				last = secs;
			}
		}
	}

	printf("[%s] info xfer fin %s [%s] [%d:%d:%d:%d] [%d:%d] [0x%08x] [%s:%d]->[%s:%d]\n", getd(), argv->prot, PMAP[widx], args->excl, stat, args->stat, args->sign, args->wait, args->rprt, thid, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);

	xfin(args, args->rprt, FINX);
	fins(&(args->sock[1]), 1);
	if (args->rpwp[0] > 0) {
		fins(&(args->rpwp[1]), 0);
		fins(&(args->rpwp[0]), 0);
	} else {
		fins(&(args->sock[0]), 1);
	}
	args->stat |= ENDP;

	return NULL;
}

void *prep(void *argp) {
	proc_o *args = (proc_o *)argp;
	thrd_o *thrd = args->thrd;

	int kind = args->kind, leng = args->leng;
	int sock = args->sock, conn = args->conn;
	int sidx = args->indx;
	struct sockaddr_in *pobj, *addr = &(args->addr);
	cach_l *cach = args->cnat;
	char_u *pbuf = args->buff;
	args_o *argv = args->args;
	ciph_o *ciph = &(args->ciph);

	int port = 0, sprt = 0, oprt = 0, wlen = 0, nlen = 0;
	int indx = -1, this = -1, thid = -1, minm = -1, nidx = -1;
	int clen = sizeof(ciph_o);
	int slen = sizeof(struct sockaddr_in);
	char *pntr;
	char cons[LINT], adrs[LINT], adrr[LINT];
	unsigned char ssiz[LINT];
	time_t secs = time(NULL);
	ciph->q = argv->skey;

	bzero(cons, LINT);
	strncpy(cons, inet_ntoa(addr->sin_addr), ILEN);
	port = ntohs(addr->sin_port);

	if (argv->rprt > 0) {
		pntr = strrchr(argv->ladr, '.');
		if (pntr != NULL) { nlen = ((pntr - argv->ladr) + 1); }
		else { nlen = (strlen(argv->ladr) - 1); }
		if (strncmp(cons, "127", 3) != 0) {
			if ((strncmp(argv->prot, "udp", 3) == 0) && (strncmp(cons, argv->ladr, nlen) == 0)) {
				bzero(adrs, LINT);
				for (int x = 0; x < NUMT; ++x) {
					if ((cach[x].last > 0) && ((secs - cach[x].last) >= WAIT[5])) {
						bzero(&(cach[x]), sizeof(cach_l));
					} else if ((port == cach[x].prta) && (strcmp(cach[x].adra, cons) == 0)) {
						memcpy(adrs, cach[x].adrb, ILEN); sprt = cach[x].prtb;
					} else if ((nidx < 0) && (cach[x].last < 1)) {
						nidx = x;
					}
				}
				if (adrs[0] == 0) {
					bzero(adrr, LINT); snprintf(adrr, ILEN, "%s.l", cons);
					endp(adrs, &(sprt), ILEN, 'g', argv->prot, adrr, port);
					if ((adrs[0] != 0) && (nidx > -1)) {
						printf("[%s] warn prep nat (%s:%d) <-> (%s:%d)\n", getd(), cons, port, adrs, sprt);
						memcpy(cach[nidx].adra, cons, ILEN); cach[nidx].prta = port;
						memcpy(cach[nidx].adrb, adrs, ILEN); cach[nidx].prtb = sprt;
						cach[nidx].last = secs;
					}
				}
				if (adrs[0] != 0) {
					bzero(cons, LINT);
					memcpy(cons, adrs, ILEN); port = sprt;
				}
			}
		}
	}

	for (int x = 0, y = sidx; x < NUMT; ++x, ++y) {
		y = (y % NUMT);
		if ((indx < 0) && (thrd[y].stat == NOOP)) {
			indx = y;
		}
		if ((thrd[y].port[0] == port) && (strcmp(thrd[y].adrs[0], cons) == 0)) {
			this = y;
		}
		if ((minm < 0) || (thrd[y].last < thrd[minm].last)) {
			minm = y;
		}
	}
	if (this > -1) { indx = this; }

	if (indx < 0) {
		printf("[%s] warn prep idx [%d][%d]\n", getd(), sock, conn);
		thrd[minm].sign |= STOP;
		if (conn != sock) { fins(&(conn), 1); }
		args->stat |= ENDP; return NULL;
	}

	thid = (args->thid | ((indx + 1) << 4));

	if (this < 0) {
		thrd[indx].wait = WAIT[3];
		thrd[indx].last = secs; thrd[indx].thid = thid;
		thrd[indx].stat = OKOP; thrd[indx].sign = OKOP;
		thrd[indx].kind[0] = kind;
		thrd[indx].sock[0] = conn;
		thrd[indx].port[0] = port;
		thrd[indx].args = args->args;
		thrd[indx].nots = args->nots;
		thrd[indx].rprt = argv->rprt;
		bcopy(cons, thrd[indx].adrs[0], ILEN);
		bcopy(addr, &(thrd[indx].addr[0]), slen);
		bcopy(ciph, &(thrd[indx].ciph[0]), clen);
		bcopy(ciph, &(thrd[indx].ciph[1]), clen);
		thrd[indx].buff[0].leng = leng;
		bcopy(pbuf, thrd[indx].buff[0].buff, leng);
	}

	if (kind == SOCK_DGRAM) {
		if (sprt > 0) {
			pobj = &(thrd[indx].addr[0]);
			if (bcmp(addr, pobj, slen) != 0) {
				oprt = ntohs(pobj->sin_port);
				port = ntohs(addr->sin_port);
				bzero(adrr, LINT); strncpy(adrr, inet_ntoa(addr->sin_addr), ILEN);
				bzero(cons, LINT); strncpy(cons, inet_ntoa(pobj->sin_addr), ILEN);
				printf("[%s] warn prep adr (%s:%d) <-> (%s:%d) [%s:%d]\n", getd(), adrs, sprt, adrr, port, cons, oprt);
				bcopy(addr, pobj, slen);
			}
		}
		if (this < 0) {
			wlen = socketpair(AF_UNIX, SOCK_STREAM, 0, thrd[indx].rpwp);
			pthread_create(&(thrd[indx].thrp), NULL, xfer, &(thrd[indx]));
		}
		PACKU16(ssiz, leng);
		wlen = write(thrd[indx].rpwp[1], ssiz, 2);
		wlen = write(thrd[indx].rpwp[1], pbuf, leng);
		if (wlen != leng) { /* no-op */ }
	} else {
		if (this < 0) {
			pthread_create(&(thrd[indx].thrp), NULL, xfer, &(thrd[indx]));
		}
	}

	args->stat |= ENDP;
	return NULL;
}

void *preq(void *argp) {
	proc_o *args = (proc_o *)argp;
	int indx, leng, rpwp[2];
	unsigned char ssiz[LINT];
	bcopy(args[0].rpwp, rpwp, 2 * sizeof(int));
	while (1) {
		leng = read(rpwp[0], ssiz, 2);
		if (leng < 1) { printf("[%s] erro preq loop pipe\n", getd()); break; }
		UPACK16(leng, ssiz);
		indx = (leng % NUMT);
		prep((void *)&(args[indx]));
	}
	return NULL;
}

void *mgmt(void *argp) {
	thrd_o *args = (thrd_o *)argp;
	int stat, timo;
	time_t secs;
	while (1) {
		secs = time(NULL);
		for (int x = 0; x < NUMT; ++x) {
			stat = (args[x].stat & MSKP);
			timo = (args[x].wait + 5);
			if (stat == ENDP) {
				printf("[%s] info mgmt fin [%d] [%d:%d] [0x%08x]\n", getd(), x, stat, timo, args[x].thid);
				pthread_join(args[x].thrp, NULL);
				bzero(&(args[x]), sizeof(thrd_o));
			} else if (stat == OKOP) {
				if ((secs - args[x].last) >= timo) {
					printf("[%s] info mgmt sec [%d] [%d:%d] [0x%08x]\n", getd(), x, stat, timo, args[x].thid);
					args[x].sign |= STOP;
				}
			}
		}
		sleep(1);
	}
	return NULL;
}

int serv(args_o *args) {
	if (args->rprt == 0) { NUMT = (NUMT * 2); }

	int sock, indx, slen, wlen, rndm, dely;
	int rpwp[2];
	int reus = 1, kind = SOCK_DGRAM;
	int pidn = (((getpid() % 255) + 1) << 24);
	int *plen, *pcon;
	unsigned char ssiz[LINT];
	struct sockaddr_in adrl;
	struct sockaddr_in *padr;
	pthread_t thrm, thrp;

	char_u *pbuf;
	inet_l *nots = malloc(LIST * sizeof(inet_l));
	cach_l *cach = malloc(NUMT * sizeof(cach_l));
	thrd_o *thrd = malloc(NUMT * sizeof(thrd_o));
	proc_o *proc = malloc(NUMT * sizeof(proc_o));

	if (strcmp(args->prot, "tcp") == 0) { kind = SOCK_STREAM; }
	if (args->rprt == 0) { kind = SOCK_STREAM; }

	srand(time(NULL));
	sigp();

	slen = sizeof(struct sockaddr_in);
	bzero(&(adrl), slen);
	adrl.sin_family = AF_INET;
	adrl.sin_port = htons(args->lprt);
	adrl.sin_addr.s_addr = inet_addr(args->ladr);
	sock = socket(AF_INET, kind, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reus, sizeof(reus));
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reus, sizeof(reus));
	bind(sock, (struct sockaddr *)&(adrl), slen);
	if (kind == SOCK_STREAM) { listen(sock, LIST * SIXT); }

	indx = 0;
	bzero(nots, LIST * sizeof(inet_l));
	bzero(cach, NUMT * sizeof(cach_l));
	bzero(thrd, NUMT * sizeof(thrd_o));
	bzero(proc, NUMT * sizeof(proc_o));
	wlen = socketpair(AF_UNIX, SOCK_STREAM, 0, proc[0].rpwp);
	bcopy(proc[0].rpwp, rpwp, 2 * sizeof(int));
	load(nots, args->nots);

	pthread_create(&(thrm), NULL, mgmt, thrd);
	pthread_create(&(thrp), NULL, preq, proc);
	sleep(1);
	while (1) {
		dely = 0;
		while (proc[indx].stat == OKOP) {
			indx = ((indx + 1) % NUMT);
			dely = ((dely + 1) % MAXP);
			if (dely == 0) { printf("[%s] warn main wait\n", getd()); sleep(1); }
		}
		rndm = (((rand() % 255) + 1) << 16);
		bzero(&(proc[indx]), sizeof(proc_o));

		proc[indx].stat = OKOP; proc[indx].indx = indx;
		proc[indx].args = args; proc[indx].thrd = thrd;
		proc[indx].kind = kind; proc[indx].leng = NOOP;
		proc[indx].sock = sock; proc[indx].conn = sock;
		proc[indx].nots = nots; proc[indx].cnat = cach;
		proc[indx].thid = (pidn | rndm);

		pbuf = proc[indx].buff;
		padr = &(proc[indx].addr);
		plen = &(proc[indx].leng);
		pcon = &(proc[indx].conn);
		slen = sizeof(struct sockaddr_in);

		if (kind == SOCK_DGRAM) {
			*plen = recvfrom(sock, pbuf, BUDP, 0, (struct sockaddr *)padr, (unsigned int *)&(slen));
			if (*plen < 1) { printf("[%s] erro main loop udps\n", getd()); break; }
		} else {
			*pcon = accept(sock, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (*pcon < 1) { printf("[%s] erro main loop tcps\n", getd()); break; }
		}

		PACKU16(ssiz, indx);
		wlen = write(rpwp[1], ssiz, 2);
		if (wlen < 1) { printf("[%s] erro main loop pipe\n", getd()); break; }
	}

	free(proc);
	free(thrd);
	free(cach);
	free(nots);

	return 0;
}

int main(int argc, char **argv) {
	char *pntr = NULL;
	args_o args;
	int frkp = 0;
	pid_t pidn = 0;
	bzero(&(args), sizeof(args_o));
	setvbuf(stdout, NULL, _IONBF, 0);
	for (int x = 1; x < argc; ++x) {
		if (strcmp(argv[x], "-f") == 0) { frkp = 1; }
		if (strcmp(argv[x], "-e") == 0) { if ((x+1) < argc) { args.cmds = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-k") == 0) { if ((x+1) < argc) { args.skey = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-l") == 0) { if ((x+1) < argc) { args.larg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-r") == 0) { if ((x+1) < argc) { args.rarg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-n") == 0) { if ((x+1) < argc) { args.nots = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-m") == 0) { if ((x+1) < argc) { NUMT = atoi(argv[x+1]); } }
		if (strcmp(argv[x], "-t") == 0) { if ((x+1) < argc) { WAIT[1] = atoi(argv[x+1]); } }
	}
	args.prot = args.larg;
	args.ladr = repl(args.prot, ':');
	pntr = repl(args.ladr, ':');
	args.lprt = numb(pntr);
	args.radr = repl(args.rarg, ':');
	pntr = repl(args.radr, ':');
	args.rprt = numb(pntr);
	if ((args.ladr != NULL) && (args.radr != NULL)) {
		if (frkp == 1) {
			pidn = fork();
			if (pidn > 0) { exit(0); }
			printf("[%s] info main fork [%d]\n", getd(), pidn);
		}
		serv(&(args));
	}
	return 0;
}
