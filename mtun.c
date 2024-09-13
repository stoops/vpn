/* gcc -Wall -O3 -o tun tun.c */

#include <poll.h>
#include <pthread.h>
#include <stdio.h>

#ifndef BSD
#include <linux/if_tun.h>
#include <linux/virtio_net.h>
#else
#define IFF_TUN 0
#define IFF_NO_PI 0
#define IFF_MULTI_QUEUE 0
#define IFF_VNET_HDR 0
#define TUNSETIFF 0
#define TUNSETVNETHDRSZ 0
#define TUNSETOFFLOAD 0
#define TUN_F_CSUM 0
#define TUN_F_TSO4 0
#define TUN_F_TSO6 0
struct virtio_net_hdr { /* no-op */ };
#endif

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#define ZSEC 753000
#define EXTR 250
#define MAXZ 25
#define MAXR 21
#define SSEC 5
#define NSEC 3
#define MULT 3

int SERV = 0;
int STAT = 0;
int MAXT = 4;
int *TUNF;

int MTUS = 1750;
int SIZE = 1975;
int MAXA = (25 * 1975);
int MAXB = (5 * 31337);

#include "lib/rnd.c"
#include "lib/enc.c"
#include "lib/net.c"
#include "lib/inc.c"
#include "lib/key.c"

struct argp
{
	int expr, rate;
	char *name, *addr, *mtus, *ques;
	char *mode, *locl, *remo, *skey;
	char *badr, *bnum;
};

struct thrp
{
	char mode;
	int idno, sock, auth;
	int *leng, *cons, *alen;
	unsigned char *buff, *arry;
	pthread_mutex_t *lisb, *ligb, *losb, *logb;
	pthread_t thrd;
	struct argp *args;
	struct keyp *keys;
	struct keyp ekey, dkey;
	struct netp *hold;
};

void *bbbb(void *argv)
{
	struct argp *args = (struct argp *)argv;

	int bmax = 1337;
	int cmax = MAXZ;
	int kbps = args->rate;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	time_t secs = 0, last = time(NULL);

	int mbps = (bmax * 8);
	int nbps = (kbps * 1024);
	int msec = (1000 * 1000);
	int sent = 0;

	if (nbps < mbps) { nbps = mbps; }
	int maxr = (nbps / mbps);
	int wsec = (msec / maxr);
	if (wsec < 1000) { wsec = 1000; }

	int vlen = 0, indx = 0;
	ssize_t leng = 0;
	uint8_t buff[bmax];
	char adrl[cmax][LINE];
	struct sockaddr_in adrs[cmax];

	char *cadr = args->badr;

	if (vlen < cmax)
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

	sleep(SSEC * SSEC);

	while (1)
	{
		if (vlen > 0)
		{
			sent = 0;
			while (sent < nbps)
			{
				for (int x = 0; x < bmax; ++x) { buff[x] = (uint8_t)(rand() & 0xff); }
				indx = ((indx + 1) % vlen);
				leng = sendto(sock, buff, bmax, 0, (struct sockaddr *)&(adrs[indx]), sizeof(struct sockaddr_in));
				if (leng < 1) { /* no-op */ }
				sent += mbps;
				usleep(wsec);
			}
			secs = time(NULL);
			if ((secs - last) >= (SSEC * SSEC))
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

int conn(char *locl, char *remo)
{
	int port, fdes = -1, opts = 1;
	char adrs[96];
	char *pntr;
	struct sockaddr_in addr;

	if ((!locl && !remo) || (locl && remo)) { return -1; }

	if (locl || remo)
	{
		bzero(adrs, 96);
		strncpy(adrs, locl ? locl : remo, 96 - 16);
		uadr(&pntr, &port, adrs);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr(pntr);
	}

	if (locl)
	{
		fdes = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(fdes, SOL_SOCKET, SO_REUSEADDR, &opts, sizeof(int));
		bind(fdes, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
		listen(fdes, LIST);
	}

	if (remo)
	{
		fdes = socket(AF_INET, SOCK_STREAM, 0);
		connect(fdes, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	}

	return fdes;
}

void *xfer(void *argv)
{
	struct thrp *argt = (struct thrp *)argv;

	int indx = (argt->idno - 1);

	int maxl = (MAXA - ARCO);

	int sock = argt->sock;
	int auth = argt->auth;
	int *plen = argt->leng;
	pthread_mutex_t *lisb = &(argt->lisb[indx]);
	pthread_mutex_t *ligb = &(argt->ligb[indx]);
	pthread_mutex_t *losb = &(argt->losb[indx]);
	pthread_mutex_t *logb = &(argt->logb[indx]);
	struct netp *hold = argt->hold;

	int erro, leng = 0, lenp = 0;
	unsigned char buff[MAXA], data[MAXA];
	unsigned char *pntr, *pbuf = argt->buff;

	time_t secs, last[2];

	printf("%s INFO xfer init thread-[%d][%c] {%d} <%d><%d>\n", date(), indx + 1, argt->mode, sock, STAT, auth); fflush(stdout);

	last[0] = 0; last[1] = 0;

	while (1)
	{
		if ((STAT != 0) || (auth != 1)) { break; }

		secs = time(NULL);

		if (argt->mode == 'w')
		{
			pthread_mutex_lock(ligb);
			lenp = *plen;
			if ((lenp < 1) || (maxl < lenp)) { STAT = (-1 * ((1 * 10) + indx)); break; }
			bcopy(pbuf, buff, lenp); *plen = ZERO;
			pthread_mutex_unlock(lisb);
			pntr = (data + OFFS);
			leng = ciph(pntr, buff, lenp, &argt->ekey, 'e');
			leng = (leng + OFFS);
			pack(data, leng);
			erro = sall(sock, data, leng);
			if (erro < 1) { /* no-op */ }
			if ((secs - last[0]) >= SSEC)
			{
				printf("%s INFO xfer send thread-[%d][%c] {%d} <%d>\n", date(), indx + 1, argt->mode, sock, leng); fflush(stdout);
				last[0] = secs;
			}
		}

		if (argt->mode == 'r')
		{
			leng = rall(sock, buff, maxl, hold);
			if (leng < 1) { STAT = (-1 * ((2 * 10) + indx)); break; }
			if ((secs - last[1]) >= SSEC)
			{
				printf("%s INFO xfer read thread-[%d][%c] {%d} <%d>\n", date(), indx + 1, argt->mode, sock, leng + OFFS); fflush(stdout);
				last[1] = secs;
			}
			lenp = ciph(data, buff, leng, &argt->dkey, 'd');
			if (lenp < 1) { STAT = (-1 * ((3 * 10) + indx)); break; }
			pthread_mutex_lock(losb);
			pntr = argt->arry;
			argt->alen[0] = lenp;
			bcopy(data, pntr, lenp);
			pthread_mutex_unlock(logb);
		}
	}

	printf("%s INFO xfer fins thread-[%d][%c] {%d} <%d><%d> (%d)(%d)\n", date(), indx + 1, argt->mode, sock, STAT, auth, leng, lenp); fflush(stdout);

	for (int z = 0; z < MAXT; ++z)
	{
		pthread_mutex_unlock(&(argt->lisb[z]));
		pthread_mutex_unlock(&(argt->ligb[z]));
		pthread_mutex_unlock(&(argt->losb[z]));
		pthread_mutex_unlock(&(argt->logb[z]));
		fins(&(argt->cons[z]));
	}

	if (STAT == 0)
	{
		STAT = (-1 * ((9 * 10) + indx));
	}

	return NULL;
}

void *work(void *argv)
{
	struct thrp *argt = (struct thrp *)argv;
	struct argp *args = argt->args;

	int indx = (argt->idno - 1);

	int fdes, idxl = 0;
	unsigned int slen;
	struct sockaddr_in addr;
	struct thrp thrr, thrw;
	struct keyp keyo;

	if (indx > 0)
	{
		while (argt->cons[MAXT - 1] < 1)
		{
			sleep(1);
		}
	}
	else
	{
		while (idxl < MAXT)
		{
			bzero(&keyo, sizeof(struct keyp));
			if (args->locl)
			{
				slen = sizeof(struct sockaddr_in);
				fdes = accept(SERV, (struct sockaddr *)&addr, &slen);
				if (fdes < 1) { break; }
				keyo = xchg(fdes, args->skey, 'c', idxl);
				if (keyo.klen < 1) { fins(&fdes); continue; }
			}
			if (args->remo)
			{
				fdes = conn(args->locl, args->remo);
				if (fdes < 1) { break; }
				keyo = xchg(fdes, args->skey, 's', idxl);
				if (keyo.klen < 1) { fins(&fdes); break; }
				usleep(ZSEC);
			}
			if (keyo.klen > 0)
			{
				argt->keys[idxl] = keyo;
				argt->cons[idxl] = fdes;
				++idxl;
			}
		}
	}

	argt->sock = argt->cons[indx];
	argt->ekey = argt->keys[indx];
	argt->dkey = argt->keys[indx];
	argt->auth = (argt->ekey.klen > 0) ? 1 : 0;

	bcopy(argt, &thrr, sizeof(struct thrp));
	thrr.mode = 'r';
	pthread_create(&(thrr.thrd), NULL, xfer, (void *)&thrr);

	bcopy(argt, &thrw, sizeof(struct thrp));
	thrw.mode = 'w';
	pthread_create(&(thrw.thrd), NULL, xfer, (void *)&thrw);

	pthread_join(thrr.thrd, NULL);
	pthread_join(thrw.thrd, NULL);

	return NULL;
}

void *devo(void *argv)
{
	struct thrp *argt = (struct thrp *)argv;

	pthread_mutex_t *losb = argt->losb;
	pthread_mutex_t *logb = argt->logb;

	int maxp = (SIZE - EXTR);

	int erro, indx, leng, lenp;
	int *alen;
	unsigned char *pntr, *arry;
	struct thrp *thra;

	indx = (argt->idno - 1);

	while (1)
	{
		thra = argt;

		if (STAT != 0) { break; }

		pthread_mutex_lock(&(logb[indx]));
		alen = thra->alen;
		arry = thra->arry;
		pntr = arry; leng = *alen;
		for (int z = 0; (z < MAXR) && (leng > 0); ++z)
		{
			unpk(pntr, &lenp); leng -= OFFS;
			pntr += OFFS; lenp -= OFFS;
			if ((lenp < 1) || (maxp < lenp)) { STAT = (-1 * ((4 * 10) + indx)); break; }
			erro = write(TUNF[indx], pntr, lenp);
			if (erro < 1) { /* no-op */ }
			pntr += lenp; leng -= lenp;
		}
		pthread_mutex_unlock(&(losb[indx]));
	}

	return NULL;
}

void *devi(void *argv)
{
	struct thrp *argt = (struct thrp *)argv;

	pthread_mutex_t *lisb = argt->lisb;
	pthread_mutex_t *ligb = argt->ligb;

	int maxp = (SIZE - EXTR);

	int leng, indx, fast, llen;
	int lens[MAXR];
	int *plen;
	unsigned char buff[MAXR][SIZE];
	unsigned char *pntr;
	fd_set rfds;
	struct timeval tval;
	struct thrp *thra;

	indx = (argt->idno - 1);

	while (1)
	{
		fast = 0; llen = 0;
		thra = argt;

		if (STAT != 0) { break; }

		for (int z = 0; z < MAXR; ++z)
		{
			FD_ZERO(&rfds);
			FD_SET(TUNF[indx], &rfds);
			tval.tv_sec  = ZERO;
			tval.tv_usec = (fast == 0) ? ZSEC : ZERO;
			select(TUNF[indx] + 1, &rfds, NULL, NULL, &tval);
			fast = 1;
			if (FD_ISSET(TUNF[indx], &rfds))
			{
				pntr = (buff[z] + OFFS);
				leng = read(TUNF[indx], pntr, maxp);
				if (leng < 1) { break; }
				leng = (leng + OFFS);
				pack(buff[z], leng);
				lens[z] = leng;
				llen = (z + 1);
			}
			else { break; }
		}

		if (llen > 0)
		{
			pthread_mutex_lock(&(lisb[indx]));
			pntr = thra->buff; leng = 0;
			for (int z = 0; z < llen; ++z)
			{
				bcopy(buff[z], pntr, lens[z]);
				pntr += lens[z]; leng += lens[z];
			}
			plen = thra->leng;
			*plen = leng;
			pthread_mutex_unlock(&(ligb[indx]));
		}
	}

	return NULL;
}

void proc(struct argp *args)
{
	int mtun = nums(args->mtus, 1150, 9950, 1750);
	int quen = nums(args->ques, 1150, 9950, 1337);
	int IF_MTUS = mtun, IF_QUES = quen;
	char *IF_NAME = args->name, *IF_ADDR = args->addr;
	if ((!args->name) || (!args->addr) || (!args->mtus) || (!args->ques)) { exit(1); }

	MTUS = (mtun + EXTR);
	SIZE = (MTUS + EXTR);
	MAXA = (MAXZ * SIZE);
	MAXB = (MULT * MAXA);
	TUNF = malloc(MAXT * sizeof(int));

	int erro;
	int *cons;
	char cmds[LINE];
	struct ifreq ifrq = { 0 };
	struct thrp thrs[MAXT];
	struct thrp *thra;
	struct keyp *keys;
	pthread_t thrb, thri[MAXT], thro[MAXT], *thrd;
	pthread_mutex_t *lisb, *ligb, *losb, *logb;

	unsigned int temp = srnd();
	printf("%s INIT [%d][%d] [%d][%d] [0x%08x]\n", date(), MTUS, SIZE, MAXA, MAXB, temp); fflush(stdout);

	ifrq.ifr_flags = (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE);
	strncpy(ifrq.ifr_name, IF_NAME, IFNAMSIZ - 1);

	for (int z = 0; z < MAXT; ++z)
	{
		TUNF[z] = open("/dev/net/tun", O_RDWR);
		if (TUNF[z] < 1) { /* no-op */ }
		erro = ioctl(TUNF[z], TUNSETIFF, &ifrq);
		if (erro < 0) { printf("%s ERRO TUNSETIFF [%d]\n", date(), z); }
		printf("%s TUNS [%d] [%d][%d] [%d][%d] [%d][%d]\n", date(), z, TUNF[z], IF_MTUS, MTUS, SIZE, MAXA, MAXB);
	}

	bzero(cmds, LINE * sizeof(char));
	snprintf(cmds, LINE - SUBS, "ip link set dev %s mtu %d txqueuelen %d up ; ip addr add %s dev %s", IF_NAME, IF_MTUS, IF_QUES, IF_ADDR, IF_NAME);
	erro = system(cmds);
	if (erro < 1) { /* no-op */ }

	if (args->locl)
	{
		SERV = conn(args->locl, args->remo);
		if (SERV < 1) { /* no-op */ }
	}

	if (args->badr)
	{
		pthread_create(&thrb, NULL, bbbb, (void *)args);
	}

	cons = malloc(MAXT * sizeof(int));
	bzero(cons, MAXT * sizeof(int));
	keys = malloc(MAXT * sizeof(struct keyp));
	bzero(keys, MAXT * sizeof(struct keyp));

	lisb = malloc(MAXT * sizeof(pthread_mutex_t));
	ligb = malloc(MAXT * sizeof(pthread_mutex_t));
	losb = malloc(MAXT * sizeof(pthread_mutex_t));
	logb = malloc(MAXT * sizeof(pthread_mutex_t));
	for (int z = 0; z < MAXT; ++z)
	{
		mutx(&(lisb[z])); mutx(&(ligb[z])); mutx(&(losb[z])); mutx(&(logb[z]));
		pthread_mutex_unlock(&(lisb[z])); pthread_mutex_unlock(&(losb[z]));
	}

	bzero(thrs, MAXT * sizeof(struct thrp));
	for (int z = 0; z < MAXT; ++z)
	{
		thra = &(thrs[z]);
		thrd = &(thra->thrd);
		thra->leng = malloc(MAXT * sizeof(int));
		thra->buff = malloc(MAXA * sizeof(unsigned char));
		thra->alen = malloc(MAXT * sizeof(int));
		thra->arry = malloc(MAXA * sizeof(unsigned char));
		thra->hold = neti(MAXB);
		thra->args = args; thra->idno = (z + 1);
		thra->cons = cons; thra->keys = keys;
		thra->leng[0] = ZERO;
		thra->lisb = lisb; thra->ligb = ligb;
		thra->losb = losb; thra->logb = logb;
		pthread_create(thrd, NULL, work, (void *)thra);
		pthread_create(&thri[z], NULL, devi, (void *)thra);
		pthread_create(&thro[z], NULL, devo, (void *)thra);
	}

	for (int z = 0; z < MAXT; ++z)
	{
		pthread_join(thro[z], NULL);
		pthread_join(thri[z], NULL);
	}

	for (int z = 0; z < MAXT; ++z)
	{
		thra = &(thrs[z]);
		pthread_join(thra->thrd, NULL);
		free((thra->hold)->buff);
		free(thra->arry); free(thra->alen);
		free(thra->buff); free(thra->leng);
	}

	free(logb); free(losb); free(ligb); free(lisb);
	free(keys); free(cons);
}

int main(int argc, char **argv)
{
	char *pntr;
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
			args.rate = nums(argv[x + 2], 100, 900, 175);
		}
		if ((strcmp(argv[x], "-z") == 0) && ((x + 1) < argc))
		{
			MAXT = atoi(argv[x + 1]);
		}
	}

	if ((pntr = getenv("SKEY")) != NULL)
	{
		printf("%s KEYS [%c][%ld]\n", date(), pntr[0], strlen(pntr)); fflush(stdout);
		args.skey = strdup(pntr);
	}

	proc(&args);

	return 0;
}
