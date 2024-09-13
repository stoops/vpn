/* gcc -Wall -O3 -o tun tun.c */

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define HALT -2
#define INVR -1
#define ZERO 0
#define BONE 1
#define LOGT 3
#define MAXT 4
#define MAXA 5
#define NOUT 7
#define MAXR 6
#define OFFS 6
#define MAXZ 9
#define RNDL 11
#define MAXK 32
#define SUBS 11
#define LIST 96
#define LINE 192
#define ARCF 256
#define ZSEC 750000
#define MODS 0xbac99601

#define THDR (1 << 0)
#define THDW (1 << 1)

#define MAXH 16421

#define INCR(n) ((n % MODS) + BONE)
#define HASH(a, s, p, q) ((((a >> s) & 0xff) + p) * q)

#define MAPS(s, d, i) (((s == i.srca) && (d == i.dsta)) || ((d == i.srca) && (s == i.dsta)))
#define NOTS(s, d, i) ((s == i) || (d == i))
#define MSKS(s, d, i, m) (((s & m) == i) && ((d & m) == i))

struct keyp
{
	int stat, klen, idxi, idxj, idxk, idxv;
	unsigned char init[MAXK], knum[MAXK], hash[MAXK];
	unsigned char xkey[ARCF], skey[ARCF], keys[ARCF];
};

struct argp
{
	int expr, rate;
	char *name, *addr, *mtus, *ques;
	char *mode, *locl, *remo, *skey;
	char *mpkt, *madr, *badr, *bnum;
};

struct thdp
{
	int idno, loop, mgmt, sign;
	int stat, conn, leng, lenp;
	int pinp[2], pout[2], pipo[2];
	unsigned char *buff;
	time_t linp[2], lout[2];
	pthread_t thrd, thdi, thdo;
	struct keyp keye, keyd;
	struct argp *args;
};

struct thdx
{
	int thid;
	struct thdp *argt;
};

struct pktp
{
	int stat, leng, thid;
	unsigned int pktn;
	unsigned char *buff;
};

struct conp
{
	int thid;
	time_t last;
	in_addr_t srca, dsta;
};

struct mapp
{
	int stat, expr;
	int *thid;
	int notl;
	in_addr_t *nots;
	int mskl;
	in_addr_t *msks;
};

struct ipvf
{
	uint8_t  vers, tosv;
	uint16_t totl, idno, frag;
	uint8_t  ttlv, prot;
	uint16_t csum;
	uint32_t sadr, dadr;
};

int MTUS = 1750;
int SIZE = 2000;
int MAXX = (9 * 2000);

unsigned char seed[RNDL];
time_t snum = 0;
pthread_mutex_t sloc = PTHREAD_MUTEX_INITIALIZER;

int ftun = 0, fzzz = 0;
int pipo[2];

unsigned int pids = 0, pidr = 0;
time_t pidl = 0;
struct pktp **pktr, **pkts;

int didx = 0;
char dobj[MAXZ][LINE];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

char *date()
{
	time_t secs = time(NULL);
	struct tm *info = localtime(&secs);
	int modi = ((secs % (MAXZ - 1)) + 1);
	pthread_mutex_lock(&lock);
	if (modi != didx)
	{
		bzero(dobj[modi], LINE * sizeof(char));
		strftime(dobj[modi], 50, "%Y-%m-%d_%H:%M:%S", info);
		didx = modi;
	}
	pthread_mutex_unlock(&lock);
	return dobj[didx];
}

void sige(int s)
{
	printf("EXIT\n");
	exit(0);
}

void sigp(int s)
{
	printf("PIPE\n");
}

void sigs()
{
	signal(SIGINT, sige);
	signal(SIGPIPE, SIG_IGN);
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);
}

int urnd()
{
	int fdes = open("/dev/urandom", O_RDONLY);
	int erro = read(fdes, seed, RNDL);
	close(fdes);
	return erro;
}

unsigned char crnd()
{
	return (rand() & 0xff);
}

unsigned int srnd()
{
	int erro = urnd();
	unsigned int init = ((seed[0] << 24) | (seed[1] << 16) | (seed[2] <<  8) | (seed[3] <<  0));
	if (erro < 0) { /* no-op */ }
	srand(init);
	for (int x = 0; x < RNDL; ++x)
	{
		seed[x] = (seed[x] ^ crnd());
	}
	return init;
}

unsigned char rrnd()
{
	unsigned char r = 0;
	for (int x = 0; x < RNDL; ++x)
	{
		r = (r ^ seed[x]);
		seed[x] = (seed[x] ^ crnd());
	}
	return r;
}

int hexs(unsigned char *a, char *b)
{
	int f = 0, y = 0, z = 0;
	int l = strlen(b);
	for (int x = 0; (x < l) && (y < ARCF); ++x)
	{
		if (f != 0)
		{
			a[y] = b[x]; ++y;
		}
		else if (('0' <= b[x]) && (b[x] <= '9'))
		{
			a[y] |= (((b[x] - '0') +  0) << z);
			y = (z == 4) ? (y + 1) : (y + 0);
			z = (z == 0) ? 4 : 0;
		}
		else if (('A' <= b[x]) && (b[x] <= 'F'))
		{
			a[y] |= (((b[x] - 'A') + 10) << z);
			y = (z == 4) ? (y + 1) : (y + 0);
			z = (z == 0) ? 4 : 0;
		}
		else if (('a' <= b[x]) && (b[x] <= 'f'))
		{
			a[y] |= (((b[x] - 'a') + 10) << z);
			y = (z == 4) ? (y + 1) : (y + 0);
			z = (z == 0) ? 4 : 0;
		}
		else
		{
			a[y] = b[x]; ++y;
			f = 1;
		}
	}
	return y;
}

void gadd(unsigned char *a, int l)
{
	int o = 1;
	for (int x = (l - 1); x >= 0; --x)
	{
		if (o == 0) { break; }
		a[x] = (a[x] + o); o = 0;
		if (a[x] == 0) { o = 1; }
	}
}

int gcmp(unsigned char *a, unsigned char *b, int l)
{
	for (int x = 0; x < l; ++x)
	{
		if (a[x] < b[x]) { return -1; }
		if (a[x] > b[x]) { return  1; }
	}
	return 0;
}

int gini(struct keyp *argk, char mode)
{
	int x = 0, o = 0;
	unsigned char rchr = rrnd();
	if (mode == 'e')
	{
		if ((argk->stat & 1) == 0)
		{
			argk->knum[0] = 0;
			argk->knum[1] = 0; argk->knum[2] = 0; argk->knum[3] = 0; argk->knum[4] = 1;
			argk->stat |= 1;
		}
		if ((argk->stat & 2) == 0)
		{
			gadd(argk->knum, MAXA);
			for (x = 0; x < MAXK; ++x)
			{
				if (x < (MAXK - MAXA))
				{
					argk->init[x] = (rchr ^ crnd());
				}
				else
				{
					argk->init[x] = argk->knum[o]; ++o;
				}
			}
		}
	}
	return 1;
}

int gksa(struct keyp *argk, char mode)
{
	int i = 0, j = 0, k = 0, v = 0, x = 0, y = 0, z = 0;
	int leng = argk->klen;
	unsigned char s = 0;
	if ((argk->stat & 4) == 0)
	{
		for (x = 0; x < ARCF; ++x)
		{
			argk->keys[x] = x;
			argk->xkey[x] = 0;
		}
		for (x = 0; x < (3 * ARCF); ++x)
		{
			y = (x % leng); z = (x % MAXK);
			i = ((i + 1) % ARCF);
			k = ((k + (argk->skey[y] ^ 0x13)) % ARCF);
			v = ((v + (argk->init[z] ^ 0x37)) % ARCF);
			j = (((i ^ j) + (k ^ v)) % ARCF);
			s = argk->keys[i]; argk->keys[i] = argk->keys[j]; argk->keys[j] = s;
		}
		argk->idxi = 0; argk->idxj = 0; argk->idxv = 0; argk->idxk = 0;
		argk->stat |= 4;
	}
	return 1;
}

void core(int *olen, int *ilen, unsigned char *outp, unsigned char *inpt, int leng, struct keyp *argk, char mode)
{
	int z = 0;
	int i = argk->idxi, j = argk->idxj, k = argk->idxk, v = argk->idxv;
	int n = *olen, l = *ilen;
	unsigned char s = 0;
	unsigned char ochr = 0, ichr = 0, xkey = 0, ckey = 0;
	while (leng > 0)
	{
		i = ((i + 1) % ARCF);
		k = ((k + (argk->keys[i] ^ 0x13)) % ARCF);
		v = ((v + (argk->xkey[i] ^ 0x37)) % ARCF);
		j = (((i ^ j) + (k ^ v)) % ARCF);
		z = ((i + 1) % ARCF);
		s = argk->keys[i]; argk->keys[i] = argk->keys[j]; argk->keys[j] = s;
		ichr = inpt[l]; ckey = (argk->keys[i] ^ argk->keys[j]);
		if (mode == 'e')
		{
			ochr = ((ichr ^ xkey) ^ ckey); outp[n] = ochr;
			xkey = ochr; argk->xkey[z] = ochr;
		}
		else
		{
			ochr = ((ichr ^ ckey) ^ xkey); outp[n] = ochr;
			xkey = ichr; argk->xkey[z] = ichr;
		}
		++l; ++n; --leng;
	}
	argk->idxi = i; argk->idxj = j; argk->idxk = k; argk->idxv = v;
	*olen = n; *ilen = l;
}

int ciph(unsigned char *outp, unsigned char *inpt, int leng, struct keyp *argk, char mode)
{
	int ilen = 0, olen = 0, tlen = 0;
	unsigned char *ptra, *ptrb, *ptrc;
	if (mode == 'e')
	{
		gini(argk, mode);
		gksa(argk, mode);
		bcopy(argk->init, outp, MAXK);
		olen += MAXK;
	}
	else
	{
		ptra = (inpt + (MAXK - MAXA));
		if (gcmp(ptra, argk->knum, MAXA) != 1) { return -1; }
		bcopy(inpt, argk->init, MAXK);
		ilen += MAXK; leng -= (2 * MAXK);
		if (leng < 1) { return -2; }
		gksa(argk, mode);
	}
	core(&olen, &ilen, outp, inpt, leng, argk, mode);
	if (mode == 'e')
	{
		ptrb = argk->init; ilen = 0;
		core(&olen, &ilen, outp, ptrb, MAXK, argk, mode);
	}
	else
	{
		ptrc = argk->hash;
		ptrb = &(inpt[ilen]); ilen = 0;
		core(&tlen, &ilen, ptrc, ptrb, MAXK, argk, mode);
		if (memcmp(ptrc, inpt, MAXK) != 0) { return -3; }
		bcopy(ptra, argk->knum, MAXA);
	}
	return olen;
}

void slee(int mill)
{
	usleep(mill * 1000);
}

void pack(unsigned char *buff, unsigned int pktn, int leng)
{
	buff[0] = ((pktn >> 24) & 0xff);
	buff[1] = ((pktn >> 16) & 0xff);
	buff[2] = ((pktn >>  8) & 0xff);
	buff[3] = ((pktn >>  0) & 0xff);
	buff[4] = ((leng >>  8) & 0xff);
	buff[5] = ((leng >>  0) & 0xff);
}

void unpk(unsigned char *buff, unsigned int *pktn, int *leng, int maxl)
{
	*pktn = ((buff[0] << 24) | (buff[1] << 16) | (buff[2] <<  8) | (buff[3] <<  0));
	*leng = ((buff[4] <<  8) | (buff[5] <<  0));
	*leng = (*leng % maxl);
}

void uadr(char **pntr, int *port, char *inpt)
{
	char *temp = strchr(inpt, ':');
	if (temp)
	{
		*temp = 0; ++temp;
		*pntr = inpt;
		*port = atoi(temp);
	}
}

void fins(int *sock)
{
	if (*sock > 1)
	{
		shutdown(*sock, SHUT_RDWR);
		close(*sock);
	}
	*sock = -1;
}

int rall(int sock, unsigned char *buff, int leng)
{
	if (leng < 1) { return -1; }
	return recv(sock, buff, leng, 0);
}

int sall(int sock, unsigned char *buff, int leng)
{
	if (leng < 1) { return -1; }
	while (leng > 0)
	{
		int wlen = send(sock, buff, leng, 0);
		if (wlen < 0) { return -1; }
		buff += wlen; leng -= wlen;
	}
	if (leng > 0) { return -2; }
	return 1;
}

int mdat(unsigned char *data, int dlen, int leng)
{
	int left = (dlen - leng);
	for (int x = 0; x < left; ++x)
	{
		data[x] = data[x + leng];
	}
	return left;
}

int sels(unsigned char *buff, int leng, int rlen, int fdes, int timo, int kind)
{
	fd_set rfds;
	struct timeval tval;
	FD_ZERO(&rfds);
	FD_SET(fdes, &rfds);
	tval.tv_sec = timo;
	tval.tv_usec = ZERO;
	select(fdes + 1, &rfds, NULL, NULL, &tval);
	if (FD_ISSET(fdes, &rfds))
	{
		if (kind == ZERO)
		{
			leng += read(fdes, buff + leng, rlen - leng);
		}
		if (kind == BONE)
		{
			leng += rall(fdes, buff + leng, rlen - leng);
		}
	}
	return leng;
}

void cfgk(unsigned char *init, int leng, struct keyp *argk, char *skey, int indx)
{
	pthread_mutex_lock(&sloc);
	bzero(argk, 1 * sizeof(struct keyp));
	if (indx != -1) { snum += 3; }
	argk->knum[0] = 0;
	argk->knum[1] = ((snum >> 24) & 0xff);
	argk->knum[2] = ((snum >> 16) & 0xff);
	argk->knum[3] = ((snum >>  8) & 0xff);
	argk->knum[4] = ((snum >>  0) & 0xff);
	argk->klen = hexs(argk->skey, skey);
	argk->stat = 1;
	gini(argk, 'e');
	gksa(argk, 'e');
	argk->stat = 3;
	if (indx == -1) { argk->stat = 1; }
	bcopy("auth-", init, 5);
	for (int x = 5; x < (leng + 5); ++x)
	{
		init[x] = rrnd();
	}
	pthread_mutex_unlock(&sloc);
}

void conf(struct thdp *argt, unsigned char *init, unsigned char *inpt)
{
	pthread_mutex_lock(&sloc);
	time_t secs = time(NULL);
	for (int x = 0; x < MAXK; ++x)
	{
		argt->keye.skey[x] = (init[x] ^ inpt[x]);
		argt->keyd.skey[x] = (init[x] ^ inpt[x]);
	}
	argt->keye.klen = MAXK;
	argt->keyd.klen = MAXK;
	if ((secs - pidl) >= (MAXT + 1))
	{
		pids = BONE; pidr = BONE;
		pidl = secs; fzzz = BONE;
	}
	pthread_mutex_unlock(&sloc);
}

void *bbbb(void *argv)
{
	struct argp *args = (struct argp *)argv;

	int maxb = 1337;
	int maxc = MAXZ;
	int kbps = args->rate;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	time_t secs = 0, last = 0;

	int mbps = (maxb * 8);
	int nbps = (kbps * 1024);
	int msec = (1000 * 1000);
	int sent = 0;

	if (nbps < mbps) { nbps = mbps; }
	int maxr = (nbps / mbps);
	int wsec = (msec / maxr);
	if (wsec < 1000) { wsec = 1000; }

	int vlen = 0, indx = 0;
	ssize_t leng = 0;
	uint8_t buff[maxb];
	char adrl[maxc][LINE];
	struct sockaddr_in adrs[maxc];

	char *cadr = args->badr;

	if (vlen < maxc)
	{
		bzero(&(adrs[vlen]), sizeof(struct sockaddr_in));
		adrs[vlen].sin_addr.s_addr = inet_addr(cadr);
		adrs[vlen].sin_port = htons(1);
		adrs[vlen].sin_family = AF_INET;
		cadr = inet_ntoa(adrs[vlen].sin_addr);
		if ((strcmp(cadr, "0.0.0.0") != 0) && (strcmp(cadr, "255.255.255.255") != 0))
		{
			bzero(adrl[vlen], LINE * sizeof(char));
			strncpy(adrl[vlen], cadr, LINE - 11);
			++vlen;
		}
	}

	while (1)
	{
		if (vlen > 0)
		{
			sent = 0;
			while (sent < nbps)
			{
				for (int x = 0; x < maxb; ++x) { buff[x] = (uint8_t)(rand() & 0xff); }
				indx = ((indx + 1) % vlen);
				leng = sendto(sock, buff, maxb, 0, (struct sockaddr *)&(adrs[indx]), sizeof(struct sockaddr_in));
				if (leng < 1) { /* no-op */ }
				sent += mbps;
				usleep(wsec);
			}
			secs = time(NULL);
			if ((secs - last) >= (LOGT * LOGT))
			{
				printf("%s BUST buff sent [%d][%d] [%d] [%s][%d]\n", date(), indx, vlen, wsec, adrl[indx], sent); fflush(stdout);
				last = secs;
			}
		}
		else { sleep(1); }
	}

	close(sock);

	return NULL;
}

int amap(struct mapp *argm, struct conp *argc, unsigned char *buff, int leng)
{
	int thid = *(argm->thid), expr = argm->expr;
	struct ipvf *ipvo = (struct ipvf *)buff;
	in_addr_t srca = ipvo->sadr, dsta = ipvo->dadr;
	if (argm->stat && ((ipvo->vers >> 4) & 0x4))
	{
		int flag = 1;
		for (int y = 0; y < argm->notl; ++y)
		{
			if (NOTS(srca, dsta, argm->nots[y]))
			{
				flag = 0;
			}
		}
		for (int y = 0; (y + 1) < argm->mskl; y += 2)
		{
			if (MSKS(srca, dsta, argm->msks[y], argm->msks[y + 1]))
			{
				flag = 0;
			}
		}
		if (flag == 1)
		{
			int indx = -1, scan = 0, memr = 4, logs = -1;
			time_t secs = time(NULL);
			unsigned int srcn = srca, dstn = dsta;
			unsigned int srch = (HASH(srcn, 24, 11, 103) + HASH(srcn, 16, 13, 107) + HASH(srcn, 8, 17, 109) + HASH(srcn, 0, 19, 113));
			unsigned int dsth = (HASH(dstn, 24, 31, 131) + HASH(dstn, 16, 53, 137) + HASH(dstn, 8, 67, 139) + HASH(dstn, 0, 79, 151));
			unsigned int hidx = (((srch * 163) + (dsth * 167)) % MAXH);
			for (int y = 0; y < MAXH; ++y)
			{
				if (MAPS(srca, dsta, argc[hidx]))
				{
					indx = hidx;
					if ((secs - argc[hidx].last) >= expr) { indx = (-1 * (hidx + 11)); }
					break;
				}
				else if ((secs - argc[hidx].last) >= expr)
				{
					if (indx == -1) { indx = (-1 * (hidx + 11)); }
				}
				if ((scan >= memr) && (indx != -1)) { break; }
				hidx = ((hidx + 1) % MAXH);
				scan += 1;
			}
			if (indx < 0)
			{
				indx = (indx == -1) ? hidx : ((indx * -1) - 11);
				argc[indx].srca = srca;
				argc[indx].dsta = dsta;
				argc[indx].thid = thid;
				logs = 1;
			}
			if (logs == 1)
			{
				char a[28], b[28];
				struct in_addr t;
				t.s_addr = srca; bzero(a, 28); snprintf(a, 24, "%s", inet_ntoa(t));
				t.s_addr = dsta; bzero(b, 28); snprintf(b, 24, "%s", inet_ntoa(t));
				printf("%s MTIO maps cons <%d>(%d) [%s][%s] {%d}{%d}\n", date(), indx, expr, a, b, thid, argc[indx].thid); fflush(stdout);
			}
			thid = argc[indx].thid;
			argc[indx].last = secs;
		}
	}
	return thid;
}

int innr(unsigned char *data, int dlen, struct argp *args, struct thdp *argt)
{
	int indx = argt->idno;

	int maxl = (MTUS - SUBS);
	int idxq = (indx - 1);

	int idxp = 0, leng = 0, noop = 0;
	unsigned int pktn = 0;
	unsigned char *ptrb = data;
	time_t secs = time(NULL);
	struct pktp *pkto;

	for (int y = 0; y < MAXZ; ++y)
	{
		pkto = &pktr[idxq][y];
		if (pkto->stat != ZERO) { printf("%s ERRO innr pktr [%d][%d] [%d][%u] [%d]\n", date(), y, pkto->stat, pkto->leng, pkto->pktn, indx); fflush(stdout); return -1; }
	}

	while (noop == 0)
	{
		noop = 1;

		if ((leng < 1) && (dlen >= OFFS))
		{
			unpk(ptrb, &pktn, &leng, maxl);
			if (leng < 1) { printf("%s ERRO innr leng [%d] [%d]\n", date(), leng, indx); fflush(stdout); return -1; }
			noop = 0;
		}

		if ((leng > 0) && (dlen >= (leng + OFFS)))
		{
			if ((secs - argt->linp[1]) >= LOGT)
			{
				printf("%s INFO link read [%d][%d] [%d] [%d]\n", date(), leng, dlen, pktn, indx); fflush(stdout);
				argt->linp[1] = secs;
			}
			ptrb += OFFS;
			pkto = &pktr[idxq][idxp];
			bcopy(ptrb, pkto->buff, leng);
			pkto->leng = leng;
			pkto->pktn = pktn;
			pkto->stat = BONE;
			++idxp;
			if (idxp > MAXR) { printf("%s ERRO innr idxp [%d] [%d]\n", date(), idxp, indx); fflush(stdout); return -1; }
			ptrb += leng;
			dlen -= (leng + OFFS);
			leng = 0;
			noop = 0;
		}
	}

	return 1;
}

int outr(unsigned char *data, int dlen, struct argp *args, struct thdp *argt)
{
	int indx = argt->idno;

	int maxl = (MAXX - SUBS);
	int idxq = (indx - 1);

	int erro;
	int leng = 0, clen = 0, noop = 0;
	unsigned int pktn;
	unsigned char buff[MAXZ], decr[MAXX];
	unsigned char *ptra, *ptrb;
	time_t secs = 0;
	struct pktp *pkto;

	while (noop == 0)
	{
		noop = 1;

		if ((leng < 1) && (dlen >= OFFS))
		{
			unpk(data, &pktn, &leng, maxl);
			if (leng < 1) { printf("%s ERRO outr leng [%d] [%d]\n", date(), leng, indx); fflush(stdout); return -1; }
			noop = 0;
		}

		if ((leng > 0) && (dlen >= (leng + OFFS)))
		{
			ptra = (decr + ZERO);
			ptrb = (data + OFFS);
			/*bcopy(ptrb, ptra, leng); clen = leng;*/
			clen = ciph(ptra, ptrb, leng, &argt->keyd, 'd');
			if (clen < 1) { printf("%s ERRO outr decr [%d][%d] [%d]\n", date(), leng, clen, indx); fflush(stdout); return -1; }
			if (argt->mgmt != 0)
			{
				erro = sels(buff, 0, 1, argt->pipo[0], NOUT, ZERO);
				if (erro < 1) { /* no-op */ }
				argt->mgmt = 0;
			}
			erro = innr(ptra, clen, args, argt);
			if (erro < 0) { printf("%s ERRO outr innr [%d][%d] [%d]\n", date(), leng, clen, indx); fflush(stdout); return -1; }
			if (args->mpkt)
			{
				buff[0] = indx;
				erro = write(pipo[1], buff, 1);
				if (erro < 1) { /* no-op */ }
				argt->mgmt = 1;
			}
			else
			{
				secs = time(NULL);
				for (int y = 0; y < MAXZ; ++y)
				{
					pkto = &pktr[idxq][y];
					if (pkto->stat != ZERO)
					{
						erro = write(ftun, pkto->buff, pkto->leng);
						if (erro < 1) { /* no-op */ }
						if ((secs - argt->lout[0]) >= LOGT)
						{
							printf("%s INFO intf send [%d] [%d]\n", date(), pkto->leng, indx); fflush(stdout);
							argt->lout[0] = secs;
						}
						pkto->stat = ZERO;
					}
				}
			}
			leng += OFFS;
			dlen = mdat(data, dlen, leng);
			if (dlen < 0) { printf("%s ERRO outr dlen [%d] [%d]\n", date(), dlen, indx); fflush(stdout); return -1; }
			leng = 0;
			noop = 0;
		}
	}

	return dlen;
}

void *mgmt(void *argv)
{
	struct thdp *argt = (struct thdp *)argv;
	struct argp *args = argt->args;

	int erro;
	int qued[MAXT];
	unsigned char buff[MAXZ];
	time_t last = time(NULL);
	time_t hold[MAXT];
	fd_set rfds;
	struct timeval tval;

	bzero(qued, MAXT * sizeof(int));
	bzero(hold, MAXT * sizeof(time_t));
	while (1)
	{
		int indx = -1;
		int fmax = pipo[0];

		FD_ZERO(&rfds);
		FD_SET(fmax, &rfds);
		tval.tv_sec = ZERO;
		tval.tv_usec = ZSEC;
		select(fmax + 1, &rfds, NULL, NULL, &tval);

		if (FD_ISSET(fmax, &rfds))
		{
			erro = read(fmax, buff, 1);
			if (erro < 1) { /* no-op */ }
			indx = (buff[0] - 1);
			if ((-1 < indx) && (indx < MAXT)) { qued[indx] = 1; }
			else { printf("%s WARN mgmt indx [%d]\n", date(), indx); fflush(stdout); indx = -2; }
		}

		time_t secs = time(NULL);

		if (fzzz == INVR)
		{
			for (int x = 0; x < MAXT; ++x)
			{
				if (qued[x] == 1)
				{
					if ((argt[x].sign == BONE) && (argt[x].pipo[1] > 1))
					{
						erro = write(argt[x].pipo[1], buff, 1);
						if (erro < 1) { /* no-op */ }
					}
					qued[x] = 0;
				}
				if (qued[x] != 2)
				{
					for (int y = 0; y < MAXZ; ++y)
					{
						pktr[x][y].stat = ZERO; pkts[x][y].stat = ZERO;
					}
					qued[x] = 2;
				}
			}
			continue;
		}

		if (indx > -1)
		{
			int x = 0;
			while (x < MAXT)
			{
				int z = (x + 1), flag = 0;
				if (qued[x] == 1)
				{
					for (int y = 0; y < MAXZ; ++y)
					{
						struct pktp *pkto = &pktr[x][y];
						if (pkto->stat == ZERO) { continue; }
						if ((pkto->pktn == pidr) || args->madr)
						{
							erro = write(ftun, pkto->buff, pkto->leng);
							if (erro < 1) { /* no-op */ }
							if ((secs - argt[x].lout[0]) >= LOGT)
							{
								printf("%s INFO intf send [%d] [%d][%u] [%d]\n", date(), pkto->leng, y, pidr, z); fflush(stdout);
								argt[x].lout[0] = secs;
							}
							pkto->stat = ZERO;
							pidr = INCR(pidr);
							flag = 1;
							last = secs;
						}
						else
						{
							if ((secs - hold[x]) >= LOGT)
							{
								printf("%s WARN mgmt hold [%d][%u] [%d]\n", date(), y, pidr, z); fflush(stdout);
								hold[x] = secs;
							}
							break;
						}
					}
				}
				if (flag == 1)
				{
					if ((argt[x].sign == BONE) && (argt[x].pipo[1] > 1))
					{
						erro = write(argt[x].pipo[1], buff, 1);
						if (erro < 1) { /* no-op */ }
					}
					qued[x] = 0;
					x = 0;
					continue;
				}
				++x;
			}
			if ((secs - last) >= NOUT)
			{
				printf("%s WARN mgmt last [%u]\n", date(), pidr); fflush(stdout);
				last = secs;
			}
		}
	}
}

void *xfer(void *argv)
{
	struct thdx *argx = (struct thdx *)argv;
	struct thdp *argt = argx->argt;
	struct argp *args = argt->args;

	int thid = argx->thid;
	int indx = argt->idno;

	int maxn = (MAXX - SUBS);

	int erro;
	int leng = 0, pkti = 31337;
	int dlen = 0, rlen = 0, clen = 0;
	unsigned char buff[MAXZ], encr[MAXX];
	unsigned char *data, *ptra, *ptrb;
	fd_set rfds;
	struct timeval tval;

	printf("%s INFO xfer init [%d] [%d]\n", date(), thid, indx); fflush(stdout);

	data = malloc(MAXX * sizeof(unsigned char));
	ptra = data;
	while (1)
	{
		int fmax = 0;
		int sign = argt->sign;
		int conn = argt->conn;
		int sock = argt->pinp[0];
		time_t secs = time(NULL);

		if ((fzzz != BONE) || (sign != BONE)) { break; }

		FD_ZERO(&rfds);
		if ((thid & THDR) != 0)
		{
			FD_SET(sock, &rfds);
			if (sock > fmax) { fmax = sock; }
		}
		if ((thid & THDW) != 0)
		{
			FD_SET(conn, &rfds);
			if (conn > fmax) { fmax = conn; }
		}

		tval.tv_sec = ZERO;
		tval.tv_usec = ZSEC;
		select(fmax + 1, &rfds, NULL, NULL, &tval);

		if (FD_ISSET(sock, &rfds))
		{
			rlen = read(sock, buff, 1);
			if (rlen < 1) { /* no-op */ }
			leng = argt->leng;
			ptra = (encr + OFFS);
			ptrb = (argt->buff + ZERO);
			/*bcopy(ptrb, ptra, leng); clen = leng;*/
			clen = ciph(ptra, ptrb, leng, &argt->keye, 'e');
			if (clen < 1) { printf("%s ERRO xfer encr [%d] [%d]\n", date(), leng, indx); fflush(stdout); break; }
			if ((secs - argt->lout[1]) >= LOGT)
			{
				printf("%s INFO link send [%d][%d] [%d]\n", date(), leng, clen, indx); fflush(stdout);
				argt->lout[1] = secs;
			}
			pack(encr, pkti, clen);
			clen += OFFS;
			sall(conn, encr, clen);
			erro = write(argt->pout[1], buff, 1);
			if (erro < 1) { /* no-op */ }
		}

		if (FD_ISSET(conn, &rfds))
		{
			int maxl = (maxn - dlen);
			if (maxl < 1) { printf("%s ERRO xfer leng [%d][%d] < 1 [%d]\n", date(), dlen, maxl, indx); fflush(stdout); break; }
			rlen = rall(conn, ptra, maxl);
			if (rlen < 1) { printf("%s ERRO xfer read [%d] [%d]\n", date(), rlen, indx); fflush(stdout); break; }
			dlen += rlen;
			if (dlen > maxn) { printf("%s ERRO xfer leng [%d][%d] > [%d][%d] [%d]\n", date(), dlen, rlen, MAXX, SUBS, indx); fflush(stdout); break; }
			dlen = outr(data, dlen, args, argt);
			if (dlen < 0) { printf("%s ERRO xfer outr [%d] [%d]\n", date(), dlen, indx); fflush(stdout); break; }
			ptra = (data + dlen);
		}
	}

	argt->sign = HALT;

	return NULL;
}

void *work(void *argv)
{
	struct thdp *argt = (struct thdp *)argv;
	struct argp *args = argt->args;

	int indx = argt->idno;

	int erro, conn, port;
	int clen = 0, alen = 5, mlen = (MAXK + 5);
	char *dest;
	unsigned char decr[SIZE], encr[SIZE], init[SIZE];
	struct sockaddr_in addr;
	struct thdx thdi, thdo;
	struct keyp argk;

	if (args->remo)
	{
		int stat = 0;
		int rlen = (MAXK + MAXK + MAXK + alen);

		if (fzzz < 0) { sleep(MAXT + 1); }
		if (indx > 1) { sleep(indx - 1); }

		dest = strdup(args->remo);
		port = 0;
		uadr(&dest, &port, dest);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr(dest);

		conn = socket(AF_INET, SOCK_STREAM, 0);
		connect(conn, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

		cfgk(init, MAXK, &argk, args->skey, indx);
		clen = ciph(encr, init, mlen, &argk, 'e');
		erro = sall(conn, encr, clen);
		printf("%s INFO work auth [S] [%d][%lu] [%d]\n", date(), clen, snum, indx); fflush(stdout);
		clen = rall(conn, encr, rlen);
		if ((clen > 0) && (clen < rlen))
		{
			clen = sels(encr, clen, rlen, conn, ZERO, BONE);
		}
		if (clen != rlen) { printf("%s ERRO work leng [%d]\n", date(), clen); fflush(stdout); }
		else
		{
			printf("%s INFO work auth [R] [%d][%lu] [%d]\n", date(), clen, snum, indx); fflush(stdout);
			bzero(decr, alen);
			erro = ciph(decr, encr, clen, &argk, 'd');
			if (erro < 1) { printf("%s ERRO work decr [%d] [%d]\n", date(), erro, indx); fflush(stdout); }
			else
			{
				if (memcmp(decr, "auth-", alen) != 0) { printf("%s ERRO work mesg [%d] [%d]\n", date(), clen, indx); fflush(stdout); }
				else
				{
					printf("%s INFO work auth [X] [%d][%lu] [%d]\n", date(), clen, snum, indx); fflush(stdout);
					conf(argt, init + alen, decr + alen);
					stat = 1;
				}
			}
		}

		if (stat == 1)
		{
			argt->conn = conn;
		}
		else
		{
			fins(&conn);
		}
	}

	if (argt->conn > 1)
	{
		thdi.thid = THDR; thdi.argt = argt;
		pthread_create(&argt->thdi, NULL, xfer, (void *)&thdi);
		thdo.thid = THDW; thdo.argt = argt;
		pthread_create(&argt->thdo, NULL, xfer, (void *)&thdo);

		pthread_join(argt->thdi, NULL);
		pthread_join(argt->thdo, NULL);
	}

	printf("%s INFO work fins [%d]\n", date(), indx); fflush(stdout);
	fzzz = INVR;
	argt->sign = INVR;

	return NULL;
}

void make(struct thdp *argt, struct argp *args, int conn, int indx)
{
	int erro;
	int idno = (indx + 1);
	argt->sign = BONE;
	argt->idno = idno;
	argt->conn = conn;
	argt->args = args;
	erro = socketpair(AF_UNIX, SOCK_DGRAM, 0, argt->pinp);
	if (erro < 1) { /* no-op */ }
	erro = socketpair(AF_UNIX, SOCK_DGRAM, 0, argt->pout);
	if (erro < 1) { /* no-op */ }
	erro = socketpair(AF_UNIX, SOCK_DGRAM, 0, argt->pipo);
	if (erro < 1) { /* no-op */ }
	argt->buff = malloc(MAXX * sizeof(unsigned char));
	pthread_create(&argt->thrd, NULL, work, (void *)argt);
}

void stop(struct thdp *argt)
{
	free(argt->buff);
	fins(&argt->pipo[0]); fins(&argt->pipo[1]);
	fins(&argt->pout[0]); fins(&argt->pout[1]);
	fins(&argt->pinp[0]); fins(&argt->pinp[1]);
	fins(&argt->conn);
	pthread_join(argt->thrd, NULL);
	bzero(argt, 1 * sizeof(struct thdp));
}

int news(struct thdp *argt, struct argp *args, int *conl, int *cidx, int serv)
{
	int erro, indx, port;
	int noop = 0, cnum = *cidx, cmax = serv;
	int clen = 0, alen = 5, mlen = (MAXK + 5);
	char adrs[SIZE];
	unsigned int slen;
	unsigned char decr[SIZE], encr[SIZE], init[SIZE];
	unsigned char *ptrk;
	struct sockaddr_in addr;
	struct keyp argk;

	fd_set rfds;
	struct timeval tval;

	FD_ZERO(&rfds);
	FD_SET(serv, &rfds);
	for (int x = 0; x < LIST; ++x)
	{
		if (conl[x] > 1)
		{
			FD_SET(conl[x], &rfds);
			if (conl[x] > cmax) { cmax = conl[x]; }
		}
	}

	tval.tv_sec = ZERO;
	tval.tv_usec = ZERO;
	select(cmax + 1, &rfds, NULL, NULL, &tval);

	indx = -1;
	for (int y = 0; y < LIST; ++y)
	{
		if ((conl[y] > 1) && FD_ISSET(conl[y], &rfds))
		{
			int stat = 0, conn = conl[y];
			int rlen = (MAXK + MAXK + MAXK + alen);
			clen = rall(conn, encr, rlen);
			if ((clen > 0) && (clen < rlen))
			{
				clen = sels(encr, clen, rlen, conn, ZERO, BONE);
			}
			if (clen != rlen) { printf("%s ERRO news leng [%d] [%d][%d]\n", date(), clen, y, conn); fflush(stdout); }
			else
			{
				cfgk(init, MAXK, &argk, args->skey, indx);
				clen = ciph(decr, encr, clen, &argk, 'd');
				if (clen < 1) { printf("%s ERRO news decr [%d] [%d][%d]\n", date(), clen, y, conn); fflush(stdout); }
				else
				{
					if (memcmp(decr, "auth-", alen) != 0) { printf("%s ERRO news auth [%d][%d]\n", date(), y, conn); fflush(stdout); }
					else
					{
						printf("%s INFO news auth [R] [%d][%lu] [%d][%d]\n", date(), clen, snum, y, conn); fflush(stdout);
						clen = ciph(encr, init, mlen, &argk, 'e');
						erro = sall(conn, encr, clen);
						ptrk = (argk.knum + 1);
						snum = ((ptrk[0] << 24) | (ptrk[1] << 16) | (ptrk[2] <<  8) | (ptrk[3] <<  0));
						printf("%s INFO news auth [S] [%d][%lu] [%d][%d]\n", date(), erro, snum, y, conn); fflush(stdout);
						for (int z = 0; z < MAXT; ++z)
						{
							struct thdp *argz = &argt[z];
							if (argz->conn == 0)
							{
								printf("%s INFO news auth [X] [%lu] [%d][%d] [%d]\n", date(), snum, y, conn, z + 1); fflush(stdout);
								make(argz, args, conn, z);
								conf(argz, init + alen, decr + alen);
								stat = 1;
								break;
							}
						}
					}
				}
			}
			if (stat == 1)
			{
				conl[y] = 0;
			}
			else
			{
				fins(&conl[y]);
			}
		}
	}

	if (FD_ISSET(serv, &rfds))
	{
		slen = sizeof(struct sockaddr_in);
		bzero(&addr, 1 * slen);
		if (conl[cnum] > 1)
		{
			fins(&conl[cnum]);
		}
		conl[cnum] = accept(serv, (struct sockaddr *)&addr, &slen);
		bzero(adrs, SIZE * sizeof(char));
		inet_ntop(AF_INET, &(addr.sin_addr), adrs, INET_ADDRSTRLEN);
		port = ntohs(addr.sin_port);
		printf("%s INFO news conn [%d][%d] [%s:%d]\n", date(), cnum, conl[cnum], adrs, port); fflush(stdout);
		*cidx = ((cnum + 1) % LIST);
		noop = 1;
	}

	return noop;
}

void loop(struct thdp *argt, struct argp *args, int serv)
{
	int erro, leng;
	int qued[MAXT];
	unsigned char buff[MAXZ];
	unsigned char *ptra, *ptrb;
	fd_set rfds;
	struct timeval tval;

	int thid = 0, cidx = 0, ends = 0;
	int conl[LIST];
	time_t secs = 0, last = 0;
	struct mapp argm;
	struct conp cons[MAXH];
	struct thdp *pthd;
	struct pktp *pkto;

	bzero(qued, MAXT * sizeof(int));
	bzero(conl, LIST * sizeof(int));
	bzero(cons, MAXH * sizeof(struct conp));

	in_addr_t nots[] = { inet_addr("0.0.0.0"), inet_addr("255.255.255.255") };
	in_addr_t msks[] = { inet_addr("10.0.0.0"), inet_addr("255.0.0.0") };
	argm.nots = nots; argm.notl = (sizeof(nots) / sizeof(nots[0]));
	argm.msks = msks; argm.mskl = (sizeof(msks) / sizeof(msks[0]));
	if (args->madr)
	{
		argm.stat = 1; argm.expr = args->expr; argm.thid = &thid;
	}

	ends = -1;
	while (1)
	{
		int noop = 0, good = 0, flag = 0, fmax = 0;
		secs = time(NULL);
		if (serv > 1)
		{
			if ((secs - last) >= BONE)
			{
				noop = news(argt, args, conl, &cidx, serv);
				last = secs;
			}
		}

		if (fzzz != BONE)
		{
			if (noop == 0) { sleep(1); }
			continue;
		}

		FD_ZERO(&rfds);
		for (int x = 0; x < MAXT; ++x)
		{
			if (argt[x].sign == INVR)
			{
				stop(&argt[x]);
				if (args->remo)
				{
					make(&argt[x], args, ZERO, x);
				}
			}
			else if (argt[x].pout[0] > 1)
			{
				if (argt[x].conn > 1)
				{
					good = 1;
					if (argt[x].loop != 1)
					{
						flag = 1;
					}
				}
				FD_SET(argt[x].pout[0], &rfds);
				if (argt[x].pout[0] > fmax) { fmax = argt[x].pout[0]; }
			}
		}

		if (good != 1)
		{
			if (noop == 0) { sleep(1); }
			continue;
		}

		tval.tv_sec = ZERO;
		tval.tv_usec = ZERO;
		select(fmax + 1, &rfds, NULL, NULL, (flag == 0) ? NULL : &tval);
		thid = ((thid + 1) % MAXT); flag = 0;
		for (int x = 0; x < MAXT; ++x)
		{
			if (argt[x].pout[0] < 1) { continue; }
			if (FD_ISSET(argt[x].pout[0], &rfds))
			{
				erro = read(argt[x].pout[0], buff, 1);
				if (erro < 1) { /* no-op */ }
				argt[x].lenp = 0; argt[x].leng = 0; argt[x].loop = 0;
				qued[x] = 0;
			}
			if ((argt[x].conn > 1) && (argt[x].loop != 1))
			{
				if ((argt[thid].conn < 1) || (argt[thid].loop == 1))
				{
					thid = x;
				}
				flag = 1;
			}
		}

		if (flag != 1)
		{
			if (noop == 0) { slee(1); }
			continue;
		}

		int idxt = -1, indx = 1, idxb = -1;
		int over = 0, flow = 1, slow = 0;
		idxt = thid; secs = time(NULL);
		for (int z = 0; z < (MAXT * MAXR); ++z)
		{
			int x = (z / MAXR), y = (z % MAXR);
			if (over >= MAXR)
			{
				indx = ((idxt + flow) % MAXT); flow = (flow + 1);
				if ((argt[indx].conn > 1) && (argt[indx].loop != 1))
				{
					idxt = indx; over = 0; flow = 1;
				}
			}
			pkto = &pkts[x][y];
			if (pkto->stat == ZERO)
			{
				if (z > ends)
				{
					FD_ZERO(&rfds);
					FD_SET(ftun, &rfds);
					tval.tv_sec = ZERO;
					tval.tv_usec = (slow != 1) ? ZSEC : ZERO;
					select(ftun + 1, &rfds, NULL, NULL, &tval);
					slow = 1;
					if (FD_ISSET(ftun, &rfds))
					{
						thid = idxt;
						ptra = (pkto->buff + ZERO);
						ptrb = (ptra + OFFS);
						leng = read(ftun, ptrb, MTUS);
						if (leng < 1) { /* no-op*/ }
						if (args->madr)
						{
							thid = amap(&argm, cons, ptrb, leng);
						}
						pkto->leng = leng; pkto->stat = BONE;
						pkto->pktn = pids; pkto->thid = thid;
						indx = (thid + 1);
						if ((secs - argt->linp[0]) >= LOGT)
						{
							printf("%s INFO intf read [%d][%u] [%d]\n", date(), leng, pids, indx); fflush(stdout);
							argt->linp[0] = secs;
						}
						pack(ptra, pids, leng);
						pids = INCR(pids);
						over = (over + 1);
						ends = z;
					}
				}
			}
			if (pkto->stat != ZERO)
			{
				indx = pkto->thid;
				pthd = &argt[indx];
				if ((pthd->conn > 1) && (pthd->loop != 1))
				{
					flag = 0;
					if ((pthd->lenp == 0) || args->madr)
					{
						flag = 1;
					}
					else if ((pthd->lenp > 0) && (pkto->pktn == qued[indx]))
					{
						flag = 1;
					}
					if ((flag == 1) && (pthd->lenp < MAXR))
					{
						qued[indx] = INCR(pkto->pktn);
						leng = (pkto->leng + OFFS);
						ptra = (pthd->buff + pthd->leng);
						ptrb = (pkto->buff + ZERO);
						bcopy(ptrb, ptra, leng);
						pthd->leng += leng;
						pthd->lenp += 1;
						pkto->stat = ZERO;
						slow = 1;
					}
				}
			}
			if (pkto->stat == ZERO)
			{
				if (idxb < 0) { idxb = z; }
			}
			else if (idxb > -1)
			{
				int v = (idxb / MAXR), w = (idxb % MAXR);
				ptra = pkts[v][w].buff; ptrb = pkts[x][y].buff;
				pkts[v][w].leng = pkts[x][y].leng; pkts[v][w].stat = pkts[x][y].stat;
				pkts[v][w].pktn = pkts[x][y].pktn; pkts[v][w].thid = pkts[x][y].thid;
				pkts[v][w].buff = ptrb; pkts[x][y].buff = ptra;
				pkts[x][y].stat = ZERO;
				indx = (idxb + 1); idxb = -1;
				while (indx <= z)
				{
					v = (indx / MAXR); w = (indx % MAXR);
					if (pkts[v][w].stat == ZERO)
					{
						idxb = indx;
						break;
					}
					++indx;
				}
			}
		}

		while (ends > -1)
		{
			int x = (ends / MAXR), y = (ends % MAXR);
			if (pkts[x][y].stat != ZERO) { break; }
			--ends;
		}

		for (int x = 0; x < MAXT; ++x)
		{
			pthd = &argt[x];
			if ((pthd->leng > 0) && (pthd->loop != 1))
			{
				leng = write(pthd->pinp[1], buff, 1);
				if (leng < 1) { /* no-op*/ }
				pthd->loop = 1;
				slow = 1;
			}
		}

		if (slow != 1)
		{
			if (noop == 0) { slee(1); }
			continue;
		}
	}
}

void proc(struct argp *args)
{
	int erro;
	int mtun = atoi(args->mtus);
	char cmds[LINE];
	char *IF_NAME = args->name, *IF_ADDR = args->addr, *IF_MTUS = args->mtus, *IF_QUES = args->ques;
	struct ifreq ifrq = { 0 };

	MTUS = (mtun + 250);
	SIZE = (MTUS + 250);
	MAXX = (MAXZ * SIZE);

	int serv = -1, port = 0, opts = 1;
	unsigned int inum;
	char *dest;
	struct sockaddr_in addr;
	struct thdp argt[MAXT];
	pthread_t thrm, thrb;

	snum = (time(NULL) - LOGT);
	sigs();
	inum = srnd();
	printf("%s INFO proc init [%s] [%s][%s] [%d][%08x]\n", date(), args->mode, args->mpkt, args->madr, RNDL, inum); fflush(stdout);

	ftun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	ifrq.ifr_flags = (IFF_TUN | IFF_NO_PI);
	strncpy(ifrq.ifr_name, IF_NAME, IFNAMSIZ);
	ioctl(ftun, TUNSETIFF, &ifrq);

	bzero(cmds, LINE * sizeof(char));
	snprintf(cmds, LINE - SUBS, "ip link set dev %s mtu %s txqueuelen %s up ; ip addr add %s dev %s", IF_NAME, IF_MTUS, IF_QUES, IF_ADDR, IF_NAME);
	erro = system(cmds);
	if (erro < 1) { /* no-op */ }

	erro = socketpair(AF_UNIX, SOCK_DGRAM, 0, pipo);
	if (erro < 1) { /* no-op */ }
	for (int x = 0; x < MAXT; ++x)
	{
		bzero(&argt[x], 1 * sizeof(struct thdp));
		argt[x].args = args;
	}
	pktr = malloc(MAXT * sizeof(struct pktp *));
	for (int x = 0; x < MAXT; ++x)
	{
		pktr[x] = malloc(MAXZ * sizeof(struct pktp));
		for (int y = 0; y < MAXZ; ++y)
		{
			pktr[x][y].stat = ZERO; pktr[x][y].leng = ZERO;
			pktr[x][y].pktn = ZERO; pktr[x][y].thid = ZERO;
			pktr[x][y].buff = malloc(SIZE * sizeof(unsigned char));
		}
	}
	pkts = malloc(MAXT * sizeof(struct pktp *));
	for (int x = 0; x < MAXT; ++x)
	{
		pkts[x] = malloc(MAXZ * sizeof(struct pktp));
		for (int y = 0; y < MAXZ; ++y)
		{
			pkts[x][y].stat = ZERO; pkts[x][y].leng = ZERO;
			pkts[x][y].pktn = ZERO; pkts[x][y].thid = ZERO;
			pkts[x][y].buff = malloc(SIZE * sizeof(unsigned char));
		}
	}

	pthread_create(&thrm, NULL, mgmt, (void *)argt);
	if (args->badr)
	{
		pthread_create(&thrb, NULL, bbbb, (void *)args);
	}

	if (args->locl)
	{
		dest = strdup(args->locl);
		uadr(&dest, &port, dest);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr(dest);

		serv = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(serv, SOL_SOCKET, SO_REUSEADDR, &opts, sizeof(int));
		bind(serv, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
		listen(serv, LIST);
	}
	if (args->remo)
	{
		for (int x = 0; x < MAXT; ++x)
		{
			make(&argt[x], args, ZERO, x);
		}
	}

	loop(argt, args, serv);
}

int main(int argc, char **argv)
{
	struct argp args;

	bzero(&args, 1 * sizeof(struct argp));
	for (int x = 1; x < argc; ++x)
	{
		if ((strcmp(argv[x], "-i") == 0) && ((x + 1) < argc))
		{
			args.name = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-a") == 0) && ((x + 1) < argc))
		{
			args.addr = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-m") == 0) && ((x + 1) < argc))
		{
			args.mtus = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-q") == 0) && ((x + 1) < argc))
		{
			args.ques = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-o") == 0) && ((x + 2) < argc))
		{
			args.mode = strdup(argv[x + 1]);
			args.expr = atoi(argv[x + 2]);
			if ((strcmp(args.mode, "pkts") == 0) || (strcmp(args.mode, "both") == 0))
			{
				args.mpkt = args.mode;
			}
			if ((strcmp(args.mode, "cons") == 0) || (strcmp(args.mode, "both") == 0))
			{
				args.madr = args.mode;
			}
		}
		if ((strcmp(argv[x], "-l") == 0) && ((x + 1) < argc))
		{
			args.locl = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-r") == 0) && ((x + 1) < argc))
		{
			args.remo = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-k") == 0) && ((x + 1) < argc))
		{
			args.skey = strdup(argv[x + 1]);
		}
		if ((strcmp(argv[x], "-b") == 0) && ((x + 2) < argc))
		{
			args.badr = strdup(argv[x + 1]);
			args.rate = atoi(argv[x + 2]);
		}
	}

	proc(&args);

	return 0;
}
