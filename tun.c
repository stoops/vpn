/* gcc -Wall -O3 -o tun tun.c */

#include <pthread.h>
#include <stdio.h>

#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include "lib/rnd.c"
#include "lib/enc.c"
#include "lib/net.c"
#include "lib/inc.c"

#define ZSEC 753000
#define EXTR 250
#define MAXZ 9
#define MAXR 6
#define SSEC 5
#define NSEC 3
#define MULT 3

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
	int *leng, *cons;
	unsigned char *buff;
	pthread_mutex_t *lotr, *lotw, *loso, *lozw;
	pthread_t thrd;
	struct argp *args;
	struct keyp *keys;
	struct keyp keye, keyd;
	struct netp hold;
};

int TUNF = 0;
int SERV = 0;
int STAT = 0;
int MAXT = 4;

int MTUS = 1750;
int SIZE = 1975;
int MAXA = (9 * 1975);
int MAXB = (3 * 13375);

void *bbbb(void *argv)
{
	struct argp *args = (struct argp *)argv;

	int maxb = 1337;
	int maxc = MAXZ;
	int kbps = args->rate;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	time_t secs = 0, last = time(NULL);

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

	sleep(SSEC * SSEC);

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

struct keyp xchg(int sock, char *skey, char mode, int indx)
{
	int maxl = (SIZE - ARCO);
	int mlen = (ARCK + ARCL);
	int klen = (ARCL + ZERO);

	int slen, rlen, auth = 0;
	char *hexl = "0123456789abcdef";
	unsigned char init[SIZE], inpt[SIZE], encr[SIZE], decr[SIZE];
	unsigned char *pntr;
	time_t snum = time(NULL);
	fd_set rfds;
	struct timeval tval;
	struct keyp keye, keyd, keyr;
	struct netp hold;

	bzero(&keyr, 1 * sizeof(struct keyp));
	bzero(&keye, 1 * sizeof(struct keyp));
	bzero(&keyd, 1 * sizeof(struct keyp));
	keye.klen = hexs(keye.skey, skey, ARCK);
	keyd.klen = hexs(keyd.skey, skey, ARCK);
	itoc(keye.knum, snum + SSEC, 1);
	itoc(keyd.knum, snum - SSEC, 1);
	keye.stat = 1; keyd.stat = 1;

	bzero(&hold, sizeof(struct netp));
	hold.maxb = MAXB;
	hold.buff = malloc(MAXB * sizeof(unsigned char));

	bcopy("auth-", init, klen);
	for (int x = klen; x < mlen; ++x)
	{
		init[x] = rrnd();
	}

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tval.tv_sec = NSEC;
	tval.tv_usec = ZERO;

	for (int z = 0; z < 2; ++z)
	{
		if (((mode == 'd') && (z == 0)) || ((mode == 'l') && (z == 1)))
		{
			pntr = (encr + OFFS);
			rlen = ciph(pntr, init, mlen, &keye, 'e');
			pack(encr, rlen); rlen += OFFS;
			slen = sall(sock, encr, rlen);
			if (slen < 1) { /* no-op */ }
			printf("%s INFO xchg auth thread-[%d][%c] {S} <%lu>\n", date(), indx + 1, mode, snum); fflush(stdout);
		}

		if (((mode == 'd') && (z == 1)) || ((mode == 'l') && (z == 0)))
		{
			select(sock + 1, &rfds, NULL, NULL, &tval);
			if (FD_ISSET(sock, &rfds))
			{
				rlen = rall(sock, encr, maxl, &hold);
				if (rlen > 0)
				{
					bzero(decr, SIZE);
					slen = ciph(decr, encr, rlen, &keyd, 'd');
					if ((slen == mlen) && (memcmp(decr, "auth-", klen) == 0) && (memcmp(decr, init, mlen) != 0))
					{
						printf("%s INFO xchg auth thread-[%d][%c] {R} <%lu>\n", date(), indx + 1, mode, snum); fflush(stdout);
						bcopy(decr, inpt, mlen);
						auth = 1;
					}
				}
			}
		}
	}

	if (auth == 1)
	{
		char outh[SIZE];
		bzero(outh, SIZE);
		for (int x = 0; x < ARCK; ++x)
		{
			int i = (x + klen);
			keyr.skey[x] = (init[i] ^ inpt[i]);
			int j = (x * 2);
			if (x < 12)
			{
				outh[j+0] = hexl[(keyr.skey[x]>>4)&0xf];
				outh[j+1] = hexl[(keyr.skey[x]>>0)&0xf];
			}
		}
		keyr.klen = ARCK;
		printf("%s INFO xchg auth thread-[%d][%c] {X} <0x%s>\n", date(), indx + 1, mode, outh); fflush(stdout);
	}
	else
	{
		printf("%s ERRO xchg fail thread-[%d][%c] {E} <%lu>\n", date(), indx + 1, mode, snum); fflush(stdout);
	}

	free(hold.buff);

	return keyr;
}

void *xfer(void *argv)
{
	struct thrp *argt = (struct thrp *)argv;

	int maxl = (MAXA - ARCO);
	int maxp = (SIZE - SUBS);
	int indx = (argt->idno - 1);
	int next = ((indx + 1) % MAXT);
	int sock = argt->sock;
	int auth = argt->auth;
	int *plen = argt->leng;
	struct netp *hold = &(argt->hold);

	int erro, leng, lenp;
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
			pthread_mutex_unlock(argt->lotr);
			pthread_mutex_lock(argt->lotw);
			lenp = *plen;
			if ((lenp < 1) || (maxl < lenp)) { STAT = (-1 * ((1 * 10) + indx)); break; }
			*plen = ZERO;
			pntr = (data + OFFS);
			leng = ciph(pntr, pbuf, lenp, &argt->keye, 'e');
			pack(data, leng); leng = (leng + OFFS);
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
			lenp = ciph(data, buff, leng, &argt->keyd, 'd');
			if (lenp < 1) { STAT = (-1 * ((3 * 10) + indx)); break; }
			pthread_mutex_lock(&(argt->loso[indx]));
			pntr = data; leng = lenp;
			for (int z = 0; (z < MAXR) && (leng > 0); ++z)
			{
				unpk(pntr, &lenp); pntr += OFFS;
				if ((lenp < 1) || (maxp < lenp)) { STAT = (-1 * ((4 * 10) + indx)); break; }
				erro = write(TUNF, pntr, lenp);
				if (erro < 1) { /* no-op */ }
				pntr += lenp; leng -= (lenp + OFFS);
			}
			pthread_mutex_unlock(&(argt->loso[next]));
		}
	}

	printf("%s INFO xfer fins thread-[%d][%c] {%d} <%d><%d>\n", date(), indx + 1, argt->mode, sock, STAT, auth); fflush(stdout);

	pthread_mutex_unlock(argt->lotr);
	pthread_mutex_unlock(argt->lotw);
	for (int z = 0; z < MAXT; ++z)
	{
		pthread_mutex_unlock(&(argt->loso[z]));
		pthread_mutex_unlock(&(argt->lozw[z]));
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
				keyo = xchg(fdes, args->skey, 'l', idxl);
				if (keyo.klen < 1) { fins(&fdes); continue; }
			}
			if (args->remo)
			{
				fdes = conn(args->locl, args->remo);
				if (fdes < 1) { break; }
				keyo = xchg(fdes, args->skey, 'd', idxl);
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
	argt->keye = argt->keys[indx];
	argt->keyd = argt->keys[indx];
	argt->auth = (argt->keye.klen > 0) ? 1 : 0;

	bcopy(argt, &thrr, sizeof(struct thrp));
	thrr.mode = 'r';
	pthread_create(&thrr.thrd, NULL, xfer, (void *)&thrr);

	bcopy(argt, &thrw, sizeof(struct thrp));
	thrw.mode = 'w';
	pthread_create(&thrw.thrd, NULL, xfer, (void *)&thrw);

	pthread_join(thrr.thrd, NULL);
	pthread_join(thrw.thrd, NULL);

	return NULL;
}

void loop(struct argp *args, struct thrp *thrs)
{
	int leng, indx, slow, llen;
	int lens[MAXR];
	int *plen;
	unsigned char buff[MAXR][SIZE];
	unsigned char *pntr;
	fd_set rfds;
	struct timeval tval;
	struct thrp *thra;

	indx = 0;

	while (1)
	{
		slow = 0; llen = 0;
		thra = &(thrs[indx]);

		if (STAT != 0) { break; }

		for (int z = 0; z < MAXR; ++z)
		{
			FD_ZERO(&rfds);
			FD_SET(TUNF, &rfds);
			tval.tv_sec = ZERO;
			tval.tv_usec = (slow != 1) ? ZSEC : ZERO;
			select(TUNF + 1, &rfds, NULL, NULL, &tval);
			slow = 1;
			if (FD_ISSET(TUNF, &rfds))
			{
				pntr = (buff[z] + OFFS);
				leng = read(TUNF, pntr, MTUS);
				if (leng < 1) { break; }
				pack(buff[z], leng);
				lens[z] = (leng + OFFS);
				llen = (z + 1);
			}
			else { break; }
		}

		if (llen > 0)
		{
			pthread_mutex_lock(thra->lotr);
			pntr = thra->buff; leng = 0;
			for (int z = 0; z < llen; ++z)
			{
				bcopy(buff[z], pntr, lens[z]);
				pntr += lens[z]; leng += lens[z];
			}
			plen = thra->leng;
			*plen = leng;
			pthread_mutex_unlock(thra->lotw);
			indx = ((indx + 1) % MAXT);
		}
	}
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

	int erro;
	int *cons;
	char cmds[LINE];
	struct ifreq ifrq = { 0 };
	struct thrp thrs[MAXT];
	struct thrp *thra;
	struct keyp *keys;
	pthread_t thrb, *thrd;
	pthread_mutex_t *lotr, *lotw, *loso;

	srnd();

	TUNF = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (TUNF < 1) { /* no-op */ }
	ifrq.ifr_flags = (IFF_TUN | IFF_NO_PI);
	strncpy(ifrq.ifr_name, IF_NAME, IFNAMSIZ);
	ioctl(TUNF, TUNSETIFF, &ifrq);

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

	lotr = malloc(MAXT * sizeof(pthread_mutex_t));
	lotw = malloc(MAXT * sizeof(pthread_mutex_t));
	loso = malloc(MAXT * sizeof(pthread_mutex_t));
	for (int z = 0; z < MAXT; ++z)
	{
		mutx(&(lotr[z])); mutx(&(lotw[z]));
		mutx(&(loso[z]));
	}
	pthread_mutex_unlock(&(loso[0]));

	bzero(thrs, MAXT * sizeof(struct thrp));
	for (int z = 0; z < MAXT; ++z)
	{
		thra = &(thrs[z]);
		thrd = &(thra->thrd);
		thra->leng = malloc(1 * sizeof(int));
		thra->buff = malloc(MAXA * sizeof(unsigned char));
		thra->hold.buff = malloc(MAXB * sizeof(unsigned char));
		thra->args = args; thra->idno = (z + 1);
		thra->cons = cons; thra->keys = keys;
		thra->leng[0] = ZERO; thra->hold.maxb = MAXB;
		thra->lotr = &(lotr[z]); thra->lotw = &(lotw[z]);
		thra->loso = loso; thra->lozw = lotw;
		pthread_create(thrd, NULL, work, (void *)thra);
	}

	loop(args, thrs);

	for (int z = 0; z < MAXT; ++z)
	{
		thra = &(thrs[z]);
		pthread_join(thra->thrd, NULL);
		free(thra->hold.buff);
		free(thra->buff); free(thra->leng);
	}

	free(loso); free(lotw); free(lotr);
	free(keys); free(cons);
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
	}

	proc(&args);

	return 0;
}
