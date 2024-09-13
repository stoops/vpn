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
#define RTRY -3
#define STRY -4
#define RACK -5
#define SACK -6

#define FINL 65432
#define PINL 61337
#define TRYL 60042
#define ACKL 60009

#define INVL -1

#define NOOP 0x00
#define OKOP 0x01
#define ENDP 0x03
#define STOP 0x10
#define MSKP 0x0f

int MINT = 96, NUMT = 256;
int WAIT[] = { 0, 90, 900000, 15 };
char *PMAP[] = { "nul", "udp", "tcp", "eco" };
int DIDX = 0, DLEN = LIST;
char DOBJ[LIST][LINT];

typedef struct header_packet {
	char_u prot, pnum, nump;
	char_u sadr[4], sprt[2], dadr[4], dprt[2];
	char_u pkti[4], idxp[4], plen[2], leng[2];
} pckt_h;

typedef struct list_inet {
	numb_u init, addr, mask;
} inet_l;

typedef struct list_buffer {
	int stat, nump, leng, full;
	int part[LIST];
	numb_u xpid, pidx;
	char_u buff[LIST][BUDP];
} buff_l;

typedef struct object_args {
	int lprt, rprt;
	char *prot, *cmds, *skey, *nots;
	char *larg, *rarg, *ladr, *radr;
} args_o;

typedef struct object_thread {
	int rprt;
	int stat, sign, wait;
	int indx, leng, excl;
	int kind[2], sock[2], port[2], rpwp[2];
	char adrs[2][LINE];
	struct sockaddr_in addr[2];
	time_t last, lock[2];
	pthread_t thrp;
	numb_u thid, ptid[SIXT][4];
	char_u buff[2][BTCP];
	pckt_h head[2];
	ciph_o ciph[2];
	args_o *args;
	buff_l *bufs;
	inet_l *nots;
} thrd_o;

typedef struct object_process {
	int stat, sock, conn;
	int indx, leng, kind;
	int rpwp[2];
	struct sockaddr_in addr;
	numb_u thid;
	char_u buff[BTCP];
	ciph_o ciph;
	args_o *args;
	buff_l **bufs;
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
	int rlen = 0, retl = 0;
	while (size > 0) {
		rlen = read(fdes, buff, size);
		if (rlen < 1) { return rlen; }
		buff += rlen; size -= rlen;
		retl += rlen;
	}
	return retl;
}

int recp(int fdes, unsigned char *buff, int size) {
	int rlen, wlen;
	rlen = read(fdes, buff, 2);
	UPACK16(wlen, buff);
	if ((wlen < 1) || (size < wlen)) {
		printf("[%s] erro recp size [%d]\n", getd(), wlen);
		return -9;
	}
	rlen = read(fdes, buff, wlen);
	if (rlen != wlen) {
		printf("[%s] warn recp note [%d] [%d]\n", getd(), rlen, wlen);
	}
	return rlen;
}

int sent(int sock, unsigned char *buff, int leng) {
	int numb = 0, size = 0;
	while (leng > 0) {
		size = leng;
		if (size > 8192) { size = 8192; }
		numb = send(sock, buff, size, MSG_NOSIGNAL);
		if (numb < 1) { break; }
		buff += numb; leng -= numb;
	}
	return numb;
}

void fins(int *fdes, int shut) {
	if (shut != 0) {
		shutdown(*fdes, 2);
	}
	if (*fdes > 0) {
		close(*fdes);
	}
	*fdes = -1;
}

int xmit(thrd_o *args, unsigned char *buff, int leng, int ptid, char mode) {
	int i = 1;
	if (mode == 's') { i = 0; }
	int kind = args->kind[i];
	int sock = args->sock[i];
	struct sockaddr_in *addr = &(args->addr[i]);
	pckt_h *head = &(args->head[i]);
	ciph_o *ciph = &(args->ciph[i]);

	int indx = 0, size = 0, pnum = 0, nump = 0;
	int widx = 0, wlen = 0, modn = 0, retl = 0;
	int maxd = (MAXP + MINP), maxh = sizeof(pckt_h);
	int slen = sizeof(struct sockaddr_in);
	unsigned char data[BUDP], temp[BUDP];
	time_t secs = time(NULL);

	int stop = 0, show = 0;
	unsigned int xpid = args->ptid[ptid][0], pidx = args->ptid[ptid][1];
	char_u *pntr = data;

	if (args->excl == 1) {
		if (kind == SOCK_DGRAM) {
			wlen = sendto(sock, buff, leng, 0, (struct sockaddr *)addr, slen);
		} else {
			wlen = sent(sock, buff, leng);
		}
		args->last = secs;
		return wlen;
	}

	if (leng == FINX) { leng = 1; stop = FINX; }
	if (leng == PING) { leng = 2; stop = PING; }

	nump = (leng / maxd); modn = (leng % maxd);
	if (modn != 0) { nump += 1; }
	PACKU32(head->pkti, xpid);
	PACKU32(head->idxp, pidx);
	PACKU16(head->leng, leng);
	widx = maxm(head->prot, 2, 0);

	if (stop == FINX) { PACKU16(head->leng, FINL); }
	if (stop == PING) { PACKU16(head->leng, PINL); }

	indx = 0; show = (secs - args->lock[0]);
	if (stop != 0) { show = 1; }
	while ((indx < leng) && (pnum < nump)) {
		for (size = maxh; (indx < leng) && (size < (maxd + maxh)); ++size) {
			data[size] = buff[indx]; ++indx;
		}
		wlen = (size - maxh);
		if (wlen < 1) { break; }
		head->pnum = pnum;
		head->nump = nump;
		PACKU16(head->plen, wlen);
		bcopy(head, data, maxh);
		wlen = wrap(ciph, temp, data, size, 'e');
		if (wlen > 0) {
			pntr = temp; size = wlen;
			while (size < BUDP) { pntr[size] = 0; ++size; }
		}
		if (wlen < 0) { break; }
		if (show >= 1) {
			printf("[%s] info xmit snd %s [%d] [%d/%d] [%d/%d] [%d] [0x%08x:%u] [%s:%d]->[%s:%d]\n", getd(), PMAP[widx], stop, pnum + 1, nump, indx, leng, size, xpid, pidx, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);
			args->lock[0] = secs;
		}
		wlen = sent(sock, pntr, BUDP);
		if (wlen < 1) { break; }
		++pnum; retl += wlen;
	}
	if (stop == 0) {
		++pidx; args->ptid[ptid][1] = pidx;
		args->last = secs;
	}

	return retl;
}

void xfin(thrd_o *args, int rprt, int stat) {
	char mode = 'c';
	int side = 1, indx = 0, leng = 0;
	if (stat == FINX) { leng = FINX; indx = 4; }
	if (stat == PING) { leng = PING; indx = 5; }
	if (stat == RTRY) { leng = RTRY; indx = 6; }
	if (stat == STRY) { leng = STRY; indx = 7; }
	if (stat == RACK) { leng = RACK; indx = 8; }
	if (stat == SACK) { leng = SACK; indx = 9; }
	if ((leng < 0) && (args->excl == 0)) {
		if ((stat == FINX) || (stat == PING)) { args->ptid[indx][0] = 0; args->ptid[indx][1] = 0; }
		if (rprt == 0) { mode = 's'; side = 0; }
		xmit(args, args->buff[side], leng, indx, mode);
	}
}

int xbuf(thrd_o *args, buff_l *bufs, unsigned char *buff, int leng, int ptid, char mode) {
	int i = 1;
	if (mode == 's') { i = 0; }
	int kind = args->kind[i];
	int sock = args->sock[i];
	struct sockaddr_in *addr = &(args->addr[i]);
	pckt_h *head = &(args->head[i]);
	ciph_o *ciph = &(args->ciph[i]);

	int pnum, nump, size, rlen, wlen, plen;
	int widx = 0, oidx = 0, fidx = 0, show = 0, retl = 0;
	int hlen = sizeof(pckt_h), clen = sizeof(ciph_h);
	int slen = sizeof(struct sockaddr_in);
	int olen = hlen;
	unsigned int xpid, pidx;
	unsigned char data[BTCP];
	time_t secs = time(NULL);
	char_u *pntr = buff;
	buff_l *bptr = NULL;

	wlen = wrap(ciph, data, buff, leng, 'd');
	if (wlen > 0) { pntr = data; leng = wlen; olen += clen; }
	if (wlen < 0) { return 0; }

	bcopy(pntr, head, hlen);
	UPACK32(xpid, head->pkti);
	UPACK32(pidx, head->idxp);
	UPACK16(plen, head->plen);
	UPACK16(size, head->leng);
	leng = plen;
	pnum = head->pnum;
	nump = head->nump;
	pntr = (pntr + hlen);
	widx = maxm(head->prot, 2, 0);

	if (size == FINL) {
		return -9;
	}
	if (size == PINL) {
		return 0;
	}
	if ((leng < 1) || (BUDP < leng) || (plen < 1) || (BUDP < plen)) {
		return -8;
	}
	if ((nump < 1) || (LIST < nump) || (pnum <= -1) || (nump <= pnum)) {
		return -7;
	}
	if ((size < 1) || (BTCP < size) || (xpid < 1) || (pidx < 1)) {
		return -6;
	}

	if ((nump < 2) && (kind == SOCK_DGRAM)) { pidx = 0; }

	if ((nump > 1) || (kind == SOCK_STREAM)) {
		if (kind == SOCK_STREAM) { oidx = maxs(1, args->ptid[ptid][1]); }
	}

	if ((nump > 1) || (pidx != oidx)) {
		for (int x = 0; (x < MINT) && (bptr == NULL); ++x) {
			if (bufs[x].xpid == xpid) {
				bptr = &(bufs[x]);
			}
		}
		if (bptr == NULL) {
			args->indx = ((args->indx + 1) % MINT);
			bptr = &(bufs[args->indx]);
		}

		bptr->stat = OKOP;
		bptr->xpid = xpid; bptr->pidx = pidx;
		bptr->nump = nump; bptr->leng = size;
		bptr->part[pnum] = plen;
		bcopy(pntr, &(bptr->buff[pnum]), plen);

		wlen = OKOP;
		for (int x = 0; x < nump; ++x) {
			if (bptr->part[x] < 1) { wlen = NOOP; break; }
		}
		bptr->full = wlen;

		fidx = -1;
	}

	show = (secs - args->lock[1]);
	while (1) {
		bptr = NULL;
		if (fidx < 0) {
			fidx = -2; rlen = 0; pnum = 0;
			for (int x = 0; (x < MINT) && (pidx > 0); ++x) {
				if ((kind == SOCK_DGRAM) || ((bufs[x].xpid == xpid) && (bufs[x].pidx == oidx))) {
					if (bufs[x].full == OKOP) {
						bptr = &(bufs[x]); pntr = data;
						nump = bptr->nump; size = bptr->leng;
						fidx = -1; break;
					}
				}
			}
		} else { rlen = leng; size = leng; pnum = 0; nump = 1; plen = 0; }
		if (fidx == -2) { break; }
		while (pnum < nump) {
			if (bptr != NULL) { plen = bptr->part[pnum]; }
			if (show >= 1) {
				printf("[%s] info xbuf rcv %s [%d] [%d/%d] [%d/%d] [%d] [0x%08x:%u] [%s:%d]->[%s:%d]\n", getd(), PMAP[widx], fidx, pnum + 1, nump, rlen + plen, size, plen + olen, xpid, pidx, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);
				args->lock[1] = secs;
			}
			if (bptr != NULL) {
				for (int y = 0; (y < plen) && (rlen < BTCP); ++y) {
					data[rlen] = bptr->buff[pnum][y]; ++rlen;
				}
			}
			++pnum;
		}
		if (bptr != NULL) { bzero(bptr, sizeof(buff_l)); }
		if (kind == SOCK_DGRAM) {
			wlen = sendto(sock, pntr, rlen, 0, (struct sockaddr *)addr, slen);
		} else {
			wlen = sent(sock, pntr, rlen);
		}
		if (wlen < 1) { return -5; }
		fidx = -1; retl += wlen;
		if (pidx > 0) {
			++oidx; args->ptid[ptid][1] = oidx;
		}
	}

	args->last = secs;
	return retl;
}

void *xfer(void *argp) {
	thrd_o *args = (thrd_o *)argp;

	int stat = OKOP;
	int fmax = 0, widx = 0, slen = 0, side = -1;
	int sock, conn, leng, erro;
	time_t secs, last = time(NULL);
	fd_set rfds;
	struct timeval tval;

	int pktl = sizeof(pckt_h);
	int clen = args->leng;
	unsigned int thid = args->thid;
	struct sockaddr_in *addr = &(args->addr[1]);
	pckt_h *ched = &(args->head[0]);
	pckt_h *shed = &(args->head[1]);
	char_u *cbuf = args->buff[0];
	char_u *sbuf = args->buff[1];
	args_o *argv = args->args;
	buff_l *bufs = args->bufs;

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
			ched->prot = maxm(ched->prot, 2, 0);
			if (ched->prot == 1) {
				args->kind[1] = SOCK_DGRAM;
			} else {
				args->kind[1] = SOCK_STREAM;
			}
			snprintf(args->adrs[1], ILEN, "%d.%d.%d.%d", ched->dadr[3], ched->dadr[2], ched->dadr[1], ched->dadr[0]);
			UPACK16(args->port[1], ched->dprt);
		}
		bcopy(ched, shed, pktl);
		widx = shed->prot;
		args->wait = WAIT[widx];
	}

	printf("[%s] info xfer syn %s [%s] [%d:%d:%d] [%d:%d] [0x%08x] [%s:%d]->[%s:%d]\n", getd(), argv->prot, PMAP[widx], stat, args->stat, args->sign, args->wait, args->rprt, thid, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);

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
		if (args->rprt > 0) {
			xfin(args, args->rprt, PING);
		}
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
		leng = sizeof(struct sockaddr_in);

		if (FD_ISSET(conn, &(rfds))) {
			if (args->rprt == 0) {
				clen = recq(conn, cbuf, BUDP);
			} else if (side != -1) {
				clen = recp(conn, cbuf, BUDP);
			} else {
				clen = read(conn, cbuf, BTCP);
			}
			if (clen < 1) {
				if (clen != 0) { printf("[%s] erro xfer read conn [%d:%d] [%s] [%d] [0x%08x]\n", getd(), clen, errno, strerror(errno), side, thid); }
				stat = clen; break;
			}
			if ((args->rprt > 0) || (args->excl == 1)) {
				if ((erro = xmit(args, cbuf, clen, 0, 'c')) < 1) {
					if (erro != -9) { printf("[%s] erro xfer xmit conn [%d] [0x%08x]\n", getd(), erro, thid); }
					stat = erro; break;
				}
			} else {
				if ((erro = xbuf(args, bufs, cbuf, clen, 1, 'c')) < 0) {
					if (erro != -9) { printf("[%s] erro xfer xbuf conn [%d] [0x%08x]\n", getd(), erro, thid); }
					stat = erro; break;
				}
			}
		}

		if (FD_ISSET(sock, &(rfds))) {
			if ((args->rprt > 0) && (args->excl == 0)) {
				slen = recq(sock, sbuf, BUDP);
			} else if (args->kind[1] == SOCK_DGRAM) {
				slen = recvfrom(sock, sbuf, BUDP, 0, (struct sockaddr *)addr, (unsigned int *)&(leng));
			} else {
				slen = read(sock, sbuf, BTCP);
			}
			if (slen < 1) {
				if (slen != 0) { printf("[%s] erro xfer read sock [%d:%d] [%s] [%d] [0x%08x]\n", getd(), slen, errno, strerror(errno), side, thid); }
				stat = slen; break;
			}
			if ((args->rprt > 0) && (args->excl == 0)) {
				if ((erro = xbuf(args, bufs, sbuf, slen, 2, 's')) < 0) {
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
		} else if ((secs - args->last) >= WAIT[3]) {
			if ((secs - last) >= WAIT[3]) {
				xfin(args, args->rprt, PING);
				last = secs;
			}
		}
	}

	printf("[%s] info xfer fin %s [%s] [%d:%d:%d] [%d:%d] [0x%08x] [%s:%d]->[%s:%d]\n", getd(), argv->prot, PMAP[widx], stat, args->stat, args->sign, args->wait, args->rprt, thid, args->adrs[0], args->port[0], args->adrs[1], args->port[1]);

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
	struct sockaddr_in *addr = &(args->addr);
	char_u *pbuf = args->buff;
	args_o *argv = args->args;
	ciph_o *ciph = &(args->ciph);

	int port = 0, sprt = 0, wlen = 0;
	int indx = -1, this = -1, thid = -1, minm = -1;
	int hlen = sizeof(pckt_h), clen = sizeof(ciph_o);
	int slen = sizeof(struct sockaddr_in);
	char cons[LINT], adrs[LINT], adrr[LINT];
	unsigned char ssiz[LINT], data[BTCP];
	time_t secs = time(NULL);
	pckt_h hobj;
	pckt_h *head = &(hobj);

	bzero(cons, LINT);
	bzero(head, hlen);
	ciph->q = argv->skey;

	if (argv->rprt > 0) {
		strncpy(cons, inet_ntoa(addr->sin_addr), ILEN);
		port = ntohs(addr->sin_port);
		if (strcmp(argv->prot, "udp") == 0) {
			bzero(adrr, LINT); snprintf(adrr, ILEN, "%s", cons);
			bzero(adrs, LINT);
			endp(adrs, &(sprt), ILEN, 'g', argv->prot, adrr, port);
			if (adrs[0] != 0) {
				bzero(cons, LINT);
				memcpy(cons, adrs, ILEN); port = sprt;
			}
		}
	} else {
		leng = recq(args->conn, pbuf, BUDP);
		bcopy(pbuf, data, leng);
		wlen = wrap(ciph, data, pbuf, leng, 'd');
		if (wlen > hlen) { leng = (wlen - hlen); }
		if (wlen < 0) {
			printf("[%s] warn prep wrap [%d] [%d]\n", getd(), sock, conn);
			if (conn != sock) { fins(&(conn), 1); }
			args->stat |= ENDP; return NULL;
		}
		bcopy(data, head, hlen);
		snprintf(cons, ILEN, "%d.%d.%d.%d", head->sadr[3], head->sadr[2], head->sadr[1], head->sadr[0]);
		UPACK16(port, head->sprt);
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
		printf("[%s] warn prep indx [%d][%d]\n", getd(), sock, conn);
		thrd[minm].sign |= STOP;
		if (conn != sock) { fins(&(conn), 1); }
		args->stat |= ENDP; return NULL;
	}

	thid = (args->thid | ((indx + 1) << 4));
	if (kind == SOCK_STREAM) {
		printf("[%s] info prep loop %s [%d] [0x%08x] [%d:%d] [%s:%d]\n", getd(), argv->prot, leng, thid, indx, this, cons, port);
	}

	if (this < 0) {
		thrd[indx].last = secs; thrd[indx].wait = WAIT[1];
		thrd[indx].thid = thid; thrd[indx].leng = leng;
		thrd[indx].stat = OKOP; thrd[indx].sign = OKOP;
		thrd[indx].kind[0] = kind;
		thrd[indx].sock[0] = conn;
		thrd[indx].port[0] = port;
		thrd[indx].args = args->args;
		thrd[indx].bufs = args->bufs[indx];
		thrd[indx].nots = args->nots;
		thrd[indx].rprt = argv->rprt;
		bcopy(cons, thrd[indx].adrs[0], ILEN);
		bcopy(pbuf, thrd[indx].buff[0], leng);
		bcopy(addr, &(thrd[indx].addr[0]), slen);
		bcopy(head, &(thrd[indx].head[0]), hlen);
		bcopy(head, &(thrd[indx].head[1]), hlen);
		bcopy(ciph, &(thrd[indx].ciph[0]), clen);
		bcopy(ciph, &(thrd[indx].ciph[1]), clen);
	}

	if (kind == SOCK_DGRAM) {
		if (sprt > 0) {
			bcopy(addr, &(thrd[indx].addr[0]), slen);
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
				bzero(args[x].bufs, MINT * sizeof(buff_l));
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
	buff_l **ptrs = malloc(NUMT * sizeof(buff_l *));
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
	bzero(thrd, NUMT * sizeof(thrd_o));
	bzero(proc, NUMT * sizeof(proc_o));
	for (int x = 0; x < NUMT; ++x) {
		ptrs[x] = malloc(MINT * sizeof(buff_l));
		bzero(ptrs[x], MINT * sizeof(buff_l));
	}
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
		proc[indx].nots = nots; proc[indx].bufs = ptrs;
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

	for (int x = 0; x < NUMT; ++x) { free(ptrs[x]); }
	free(nots);
	free(ptrs);
	free(thrd);
	free(proc);

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
