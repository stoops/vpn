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

#define MAXA 5
#define MAXT 4
#define MAXR 6
#define OFFS 6
#define MAXZ 9
#define MAXK 32
#define SUBS 11
#define LIST 96
#define LINE 192
#define ARCF 256
#define MODS 3133731337

#define THDR (1 << 0)
#define THDW (1 << 1)

int MTUS = 1750;
int SIZE = 2000;
int MAXX = (9 * 2000);

struct keyp
{
	int klen;
	unsigned char init[MAXK], hash[MAXK], knum[MAXA];
	unsigned char xkey[ARCF], skey[ARCF], keys[ARCF];
};

struct argp
{
	char *name, *addr, *mtus, *ques;
	char *mode, *locl, *remo, *skey;
};

struct thdp
{
	int idno, busy, mgmt, conn, leng, stop;
	int pinp[2], pout[2];
	unsigned char *buff;
	time_t linp, lout;
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
	int stat, leng;
	unsigned int pktn;
	unsigned char *buff;
};

int tuns = 0;
int pipo[MAXT+1][2];
time_t plas[MAXT+1][2];
unsigned int pids = 1, pidr = 1;
struct pktp **pkts;

int didx = 0;
char dobj[MAXZ][LINE];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

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
		a[x] = (a[x] + o);
		o = 0;
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

void gksa(struct keyp *argk, char mode)
{
	int i = 0, j = 0, k = 0, v = 0, y = 0, z = 0, o = 0;
	int leng = argk->klen;
	unsigned int secs = time(NULL);
	unsigned char s = 0;
	unsigned char temp[] = { 0xf1, 0x13, 0x37, 0x1f };
	unsigned char zero[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	if (mode == 'e')
	{
		if (memcmp(argk->knum, zero, MAXA) == 0)
		{
			argk->knum[1] = ((secs >> 24) & 0xff);
			argk->knum[2] = ((secs >> 16) & 0xff);
			argk->knum[3] = ((secs >>  8) & 0xff);
			argk->knum[4] = ((secs >>  0) & 0xff);
		}
		gadd(argk->knum, MAXA);
	}
	for (int x = 0; x < MAXK; ++x)
	{
		if (mode == 'e')
		{
			if (x < (MAXK - MAXA))
			{
				argk->init[x] = (rand() & 0xff);
			}
			else
			{
				argk->init[x] = argk->knum[o]; ++o;
			}
		}
		argk->hash[x] = ((temp[x % 4] + (x / 4)) & 0xff);
	}
	for (int x = 0; x < ARCF; ++x)
	{
		argk->keys[x] = x;
	}
	for (int x = 0; x < 768; ++x)
	{
		y = (x % MAXK); z = (x % leng);
		i = ((i + 1) % ARCF);
		v = ((v + (argk->init[y] ^ 0x13)) % ARCF);
		k = ((k + (argk->skey[z] ^ 0x37)) % ARCF);
		j = (((j ^ i) + (v ^ k)) % ARCF);
		s = argk->keys[i]; argk->keys[i] = argk->keys[j]; argk->keys[j] = s;
	}
}

int ciph(unsigned char *outp, unsigned char *inpt, int leng, struct keyp *argk, char mode)
{
	int olen = 0;
	int i = 0, j = 0, k = 0, v = 0, z = 0;
	unsigned char s = 0, t = 0;
	unsigned char xkey = 0, ckey = 0;
	unsigned char *pntr;
	if (mode == 'e')
	{
		gksa(argk, mode);
		bcopy(argk->init, outp, MAXK);
		outp += MAXK; olen += MAXK;
	}
	else
	{
		pntr = (inpt + (MAXK - MAXA));
		if (gcmp(pntr, argk->knum, MAXA) != 1)
		{
			return -1;
		}
		bcopy(inpt, argk->init, MAXK);
		inpt += MAXK; leng -= (2 * MAXK);
		gksa(argk, mode);
	}
	bzero(argk->xkey, MAXA * sizeof(unsigned char));
	while (leng > 0)
	{
		i = ((i + 1) % ARCF);
		v = ((v + (argk->xkey[i] ^ 0x13)) % ARCF);
		k = ((k + (argk->keys[i] ^ 0x37)) % ARCF);
		j = (((j ^ i) + (v ^ k)) % ARCF);
		z = ((i + 1) % ARCF);
		s = argk->keys[i]; argk->keys[i] = argk->keys[j]; argk->keys[j] = s;
		t = (argk->keys[i] ^ argk->keys[j]);
		ckey = argk->keys[t];
		if (mode == 'e')
		{
			*outp = ((*inpt ^ xkey) ^ ckey);
			xkey = *outp; argk->xkey[z] = xkey;
		}
		else
		{
			*outp = ((*inpt ^ ckey) ^ xkey);
			xkey = *inpt; argk->xkey[z] = xkey;
		}
		++outp; ++olen;
		++inpt; --leng;
	}
	if (mode == 'e')
	{
		for (int x = 0; x < MAXK; ++x)
		{
			*outp = (argk->hash[x] ^ argk->keys[x]);
			++outp; ++olen;
		}
	}
	else
	{
		for (int x = 0; x < MAXK; ++x)
		{
			t = (argk->hash[x] ^ argk->keys[x]);
			if (t != *inpt)
			{
				return -2;
			}
			++inpt;
		}
		bcopy(pntr, argk->knum, MAXA);
	}
	return olen;
}

void slee(int mill)
{
    usleep(mill * 1000);
}

void pack(unsigned char *buff, unsigned int pktn, int leng)
{
	pktn = (pktn % MODS);
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
	*pktn = (*pktn % MODS);
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

int innr(unsigned char *data, int dlen, struct thdp *argt)
{
	int indx = argt->idno;

	int maxl = (MTUS - SUBS);

	int idxp = 0, leng = 0, noop = 0;
	unsigned int pktn = 0;
	unsigned char *ptrb = data;
	time_t secs = time(NULL);
	struct pktp *pkto;

	for (int y = 0; y < MAXZ; ++y)
	{
		if (pkts[indx][y].stat != 0) { printf("%s ERRO innr pkts [%d][%d] [%d] [%d]\n", date(), y, pkts[indx][y].stat, pkts[indx][y].pktn, indx); fflush(stdout); return -1; }
		pkts[indx][y].stat = 0;
		pkts[indx][y].pktn = 0; pkts[indx][y].leng = 0;
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
			if ((secs - argt->linp) >= 3)
			{
				printf("%s INFO link read [%d][%d] [%d] [%d]\n", date(), leng, dlen, pktn, indx); fflush(stdout);
				argt->linp = secs;
			}
			ptrb += OFFS;
			pkto = &pkts[indx][idxp];
			bcopy(ptrb, pkto->buff, leng);
			pkto->leng = leng;
			pkto->pktn = pktn;
			pkto->stat = 1;
			//outp(indx, idxp);//
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

int outr(unsigned char *data, int dlen, struct thdp *argt)
{
	int indx = argt->idno;

	int maxl = (MAXX - SUBS);

	int erro;
	int leng = 0, clen = 0, noop = 0;
	unsigned int pktn = 0;
	unsigned char buff[MAXZ], decr[MAXX];
	unsigned char *ptrb;

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
			ptrb = (data + OFFS);
			clen = ciph(decr, ptrb, leng, &argt->keyd, 'd');
			if (clen < 1) { printf("%s ERRO outr decr [%d] [%d]\n", date(), leng, indx); fflush(stdout); return -1; }
			if (argt->mgmt != 0)
			{
				erro = read(pipo[indx][0], buff, 1);
				if (erro < 1) { /* no-op */ }
				argt->mgmt = 0;
			}
			pktn = innr(decr, clen, argt);
			if (pktn < 0) { printf("%s ERRO outr pktn [%d] [%d]\n", date(), clen, indx); fflush(stdout); return -1; }
			buff[0] = indx;
			erro = write(pipo[0][1], buff, 1);
			if (erro < 1) { /* no-op */ }
			argt->mgmt = 1;
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
	int erro;
	int qued[MAXT+1];
	unsigned char buff[MAXZ];
	time_t last = time(NULL);
	time_t hold[MAXT+1];
	fd_set rfds;
	struct timeval tval;

	bzero(qued, (MAXT + 1) * sizeof(int));
	bzero(hold, (MAXT + 1) * sizeof(time_t));
	while (1)
	{
		int indx = -1;
		int fmax = pipo[0][0];

		FD_ZERO(&rfds);
		FD_SET(fmax, &rfds);
		tval.tv_sec = 1;
		tval.tv_usec = 0;
		select(fmax + 1, &rfds, NULL, NULL, &tval);

		if (FD_ISSET(fmax, &rfds))
		{
			erro = read(fmax, buff, 1);
			if (erro < 1) { /* no-op */ }
			indx = buff[0];
			if ((1 <= indx) && (indx <= MAXT)) { qued[indx] = 1; }
			else { printf("%s WARN mgmt indx [%d]\n", date(), indx); fflush(stdout); indx = -2; }
		}

		time_t secs = time(NULL);

		if (indx > 0)
		{
			int x = 1;
			while (x <= MAXT)
			{
				int flag = 0;
				if (qued[x] == 1)
				{
					for (int y = 0; y < MAXZ; ++y)
					{
						struct pktp *pkto = &pkts[x][y];
						if (pkto->stat != 1) { continue; }
						if (pkto->pktn == pidr)
						{
							erro = write(tuns, pkto->buff, pkto->leng);
							if (erro < 1) { /* no-op */ }
							if ((secs - plas[x][1]) >= 3)
							{
								printf("%s INFO intf send [%d] [%d][%d] [%d]\n", date(), pkto->leng, y, pidr, x); fflush(stdout);
								plas[x][1] = secs;
							}
							pkto->stat = 0;
							pidr = ((pidr % MODS) + 1);
							flag = 1;
							last = secs;
						}
						else
						{
							if ((secs - hold[x]) >= 3)
							{
								printf("%s WARN mgmt hold [%d][%d] [%d]\n", date(), y, pidr, x); fflush(stdout);
								hold[x] = secs;
							}
							break;
						}
					}
				}
				if (flag == 1)
				{
					erro = write(pipo[x][1], buff, 1);
					if (erro < 1) { /* no-op */ }
					qued[x] = 0;
					x = 0;
				}
				++x;
			}
			if ((secs - last) >= 15)
			{
				printf("%s WARN mgmt last\n", date()); fflush(stdout);
				last = secs;
			}
		}
	}
}

void *xfer(void *argv)
{
	struct thdx *argx = (struct thdx *)argv;
	struct thdp *argt = argx->argt;

	int maxn = (MAXX - SUBS);
	int thid = argx->thid;

	int erro, pkti = 31337;
	int dlen = 0, rlen = 0, plen = 0, clen = 0;
	unsigned char buff[MAXZ], encr[MAXX];
	unsigned char *data, *ptra, *ptrb;
	fd_set rfds;
	struct timeval tval;

	printf("%s INFO xfer init [%d][%d]\n", date(), argt->idno, thid); fflush(stdout);

	data = malloc(MAXX * sizeof(unsigned char));
	ptra = data;
	while (1)
	{
		int fmax = 0;
		int sock = argt->pinp[0];
		int conn = argt->conn;
		time_t secs = time(NULL);

		if (argt->stop != 0) { break; }

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

		tval.tv_sec = 1;
		tval.tv_usec = 0;
		select(fmax + 1, &rfds, NULL, NULL, &tval);

		if (FD_ISSET(sock, &rfds))
		{
			rlen = read(sock, buff, 1);
			if (rlen < 1) { /* no-op */ }
			plen = argt->leng;
			ptra = (encr + OFFS);
			ptrb = argt->buff;
			clen = ciph(ptra, ptrb, plen, &argt->keye, 'e');
			if (clen < 1) { printf("%s ERRO xfer encr [%d]\n", date(), plen); fflush(stdout); break; }
			if ((secs - argt->lout) >= 3)
			{
				printf("%s INFO link send [%d][%d] [%d]\n", date(), plen, clen, argt->idno); fflush(stdout);
				argt->lout = secs;
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
			if (maxl < 1) { printf("%s ERRO xfer leng [%d][%d] < 1\n", date(), dlen, maxl); fflush(stdout); break; }
			rlen = rall(conn, ptra, maxl);
			if (rlen < 1) { printf("%s ERRO xfer read [%d]\n", date(), rlen); fflush(stdout); break; }
			dlen += rlen;
			if (dlen > maxn) { printf("%s ERRO xfer leng [%d][%d] > [%d][%d]\n", date(), dlen, rlen, MAXX, SUBS); fflush(stdout); break; }
			dlen = outr(data, dlen, argt);
			if (dlen < 0) { break; }
			ptra = (data + dlen);
		}
	}

	argt->stop = -2;

	return NULL;
}

void *work(void *argv)
{
	struct thdp *argt = (struct thdp *)argv;
	struct argp *args = argt->args;

	int erro, conn, port;
	char *dest;
	unsigned char encr[SIZE];
	struct sockaddr_in addr;
	struct thdx thdi, thdo;

	if (args->remo)
	{
		dest = strdup(args->remo);
		port = 0;
		uadr(&dest, &port, dest);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr(dest);

		conn = socket(AF_INET, SOCK_STREAM, 0);
		connect(conn, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

		char *auth = "auth";
		erro = ciph(encr, (unsigned char *)auth, strlen(auth), &argt->keye, 'e');
		if (erro < 1) { printf("%s ERRO work auth\n", date()); fflush(stdout); }
		sall(conn, encr, erro);
		printf("%s INFO work auth [S][%d]\n", date(), argt->idno); fflush(stdout);
		rall(conn, encr, 1);
		printf("%s INFO work auth [R][%d]\n", date(), argt->idno); fflush(stdout);

		argt->conn = conn;
	}

	while (argt->conn < 1) { sleep(1); }

	thdi.thid = THDR; thdi.argt = argt;
	pthread_create(&argt->thdi, NULL, xfer, (void *)&thdi);
	thdo.thid = THDW; thdo.argt = argt;
	pthread_create(&argt->thdo, NULL, xfer, (void *)&thdo);

	pthread_join(argt->thdi, NULL);
	pthread_join(argt->thdo, NULL);

	printf("%s INFO work fins [%d]\n", date(), argt->idno); fflush(stdout);

	argt->stop = -1;

	return NULL;
}

void make(struct thdp *argt, struct argp *args, int indx)
{
	int erro;
	bzero(argt, 1 * sizeof(struct thdp));
	argt->idno = (indx + 1);
	argt->args = args;
	argt->buff = malloc(MAXX * sizeof(unsigned char));
	argt->keye.klen = hexs(argt->keye.skey, args->skey);
	argt->keyd.klen = hexs(argt->keyd.skey, args->skey);
	erro = socketpair(AF_UNIX, SOCK_STREAM, 0, argt->pinp);
	if (erro < 1) { /* no-op */ }
	erro = socketpair(AF_UNIX, SOCK_STREAM, 0, argt->pout);
	if (erro < 1) { /* no-op */ }
	pthread_create(&argt->thrd, NULL, work, (void *)argt);
}

void stop(struct thdp *argt)
{
	free(argt->buff);
	fins(&argt->pinp[0]);
	fins(&argt->pinp[1]);
	fins(&argt->pout[0]);
	fins(&argt->pout[1]);
	fins(&argt->conn);
	pthread_join(argt->thrd, NULL);
}

int news(struct thdp *argt, struct keyp *argk, int *cons, int *cidx, int serv)
{
	int maxl = (SIZE - SUBS);

	int erro;
	int noop = 0, cnum = *cidx, cmax = serv;
	unsigned int clen;
	unsigned char temp[SIZE], decr[SIZE];
	struct sockaddr_in addr;
	fd_set rfds;
	struct timeval tval;

	FD_ZERO(&rfds);
	FD_SET(serv, &rfds);
	for (int x = 0; x < LIST; ++x)
	{
		if (cons[x] > 1)
		{
			FD_SET(cons[x], &rfds);
			if (cons[x] > cmax) { cmax = cons[x]; }
		}
	}

	tval.tv_sec = 0;
	tval.tv_usec = 0;
	select(cmax + 1, &rfds, NULL, NULL, &tval);

	if (FD_ISSET(serv, &rfds))
	{
		clen = sizeof(struct sockaddr_in);
		bzero(&addr, 1 * clen);
		if (cons[cnum] > 1)
		{
			fins(&cons[cnum]);
		}
		cons[cnum] = accept(serv, (struct sockaddr *)&addr, &clen);
		bzero(temp, SIZE * sizeof(unsigned char));
		inet_ntop(AF_INET, &(addr.sin_addr), (char *)temp, INET_ADDRSTRLEN);
		printf("%s INFO proc conn [%d][%d] [%s:%d]\n", date(), cnum, cons[cnum], temp, ntohs(addr.sin_port)); fflush(stdout);
		*cidx = ((cnum + 1) % LIST);
		noop = 1;
	}

	for (int y = 0; y < LIST; ++y)
	{
		if ((cons[y] > 1) && FD_ISSET(cons[y], &rfds))
		{
			int stat = 0;
			bzero(argk->knum, MAXA * sizeof(unsigned char));
			bzero(temp, SIZE * sizeof(unsigned char));
			bzero(decr, SIZE * sizeof(unsigned char));
			erro = rall(cons[y], temp, maxl);
			if (erro < 1) { /* no-op */ }
			erro = ciph(decr, temp, erro, argk, 'd');
			if (erro < 1) { printf("%s WARN auth [%d][%d]\n", date(), y, cons[y]); fflush(stdout); }
			if (memcmp(decr, "auth", 4) == 0)
			{
				for (int x = 0; x < MAXT; ++x)
				{
					if (argt[x].conn == 0)
					{
						printf("%s INFO proc auth [%d][%d] [%d]\n", date(), y, cons[y], x + 1); fflush(stdout);
						sall(cons[y], decr, 1);
						argt[x].conn = cons[y];
						cons[y] = 0;
						stat = 1;
						break;
					}
				}
			}
			if (stat != 1)
			{
				fins(&cons[y]);
			}
		}
	}

	return noop;
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

	int leng;
	unsigned char buff[MAXZ];
	unsigned char *ptra, *ptrb;

	fd_set rfds;
	struct timeval tval;
	struct thdp argt[MAXT];
	pthread_t thrm;

	tuns = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	ifrq.ifr_flags = (IFF_TUN | IFF_NO_PI);
	strncpy(ifrq.ifr_name, IF_NAME, IFNAMSIZ);
	ioctl(tuns, TUNSETIFF, &ifrq);

	bzero(cmds, LINE * sizeof(char));
	snprintf(cmds, LINE - SUBS, "ip link set dev %s mtu %s txqueuelen %s up ; ip addr add %s dev %s", IF_NAME, IF_MTUS, IF_QUES, IF_ADDR, IF_NAME);
	erro = system(cmds);
	if (erro < 1) { /* no-op */ }

	for (int x = 0; x < (MAXT + 1); ++x)
	{
		plas[x][0] = 0; plas[x][1] = 0;
		erro = socketpair(AF_UNIX, SOCK_STREAM, 0, pipo[x]);
	}
	pkts = malloc((MAXT + 1) * sizeof(struct pktp *));
	for (int x = 0; x < (MAXT + 1); ++x)
	{
		pkts[x] = malloc((MAXZ + 1) * sizeof(struct pktp));
		for (int y = 0; y < (MAXZ + 1); ++y)
		{
			pkts[x][y].stat = 0;
			pkts[x][y].pktn = 0; pkts[x][y].leng = 0;
			pkts[x][y].buff = malloc((SIZE + 1) * sizeof(unsigned char));
		}
	}
	pthread_create(&thrm, NULL, mgmt, (void *)args);

	for (int x = 0; x < MAXT; ++x)
	{
		make(&argt[x], args, x);
	}

	int serv = -1, cidx = 0, opts = 1;
	int port;
	int cons[LIST];
	char *dest;
	struct sockaddr_in addr;
	struct keyp keyd;

	bzero(cons, LIST * sizeof(int));
	bzero(&keyd, 1 * sizeof(struct keyp));
	keyd.klen = hexs(keyd.skey, args->skey);
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

	srand(time(NULL));
	sigs();
	while (1)
	{
		int noop = 0;
		if (serv > 1)
		{
			noop = news(argt, &keyd, cons, &cidx, serv);
		}

		int good = 0, flag = 0, fmax = 0;
		FD_ZERO(&rfds);
		for (int x = 0; x < MAXT; ++x)
		{
			if (argt[x].stop == -1)
			{
				stop(&argt[x]);
				make(&argt[x], args, x);
			}
			else if (argt[x].pout[0] > 1)
			{
				if (argt[x].conn > 1)
				{
					good = 1;
					if (argt[x].busy != 1)
					{
						flag = 1;
					}
				}
				FD_SET(argt[x].pout[0], &rfds);
				if (argt[x].pout[0] > fmax) { fmax = argt[x].pout[0]; }
			}
		}

		if ((noop == 0) && (good != 1))
		{
			sleep(1);
			continue;
		}

		if ((noop == 0) && (good == 1))
		{
			tval.tv_sec = 0;
			tval.tv_usec = 0;
			select(fmax + 1, &rfds, NULL, NULL, (flag == 0) ? NULL : &tval);
			for (int x = 0; x < MAXT; ++x)
			{
				if (FD_ISSET(argt[x].pout[0], &rfds))
				{
					erro = read(argt[x].pout[0], buff, 1);
					if (erro < 1) { /* no-op */ }
					argt[x].busy = 0;
				}
			}
		}

		int slow = 0, slos = 0;
		time_t secs = time(NULL);
		for (int x = 0; x < MAXT; ++x)
		{
			if ((argt[x].conn > 1) && (argt[x].busy != 1))
			{
				argt[x].leng = 0;

				ptra = (argt[x].buff + 0);
				ptrb = (ptra + OFFS);
				for (int y = 0; y < MAXR; ++y)
				{
					FD_ZERO(&rfds);
					FD_SET(tuns, &rfds);
					tval.tv_sec = (slow == 0) ? 1 : 0;
					tval.tv_usec = 0;
					select(tuns + 1, &rfds, NULL, NULL, &tval);
					slow = 1;
					if (FD_ISSET(tuns, &rfds))
					{
						leng = read(tuns, ptrb, MTUS);
						if (leng < 1) { /* no-op*/ }
						if ((secs - plas[x + 1][0]) >= 3)
						{
							printf("%s INFO intf read [%d][%d] [%d]\n", date(), leng, pids, x + 1); fflush(stdout);
							plas[x + 1][0] = secs;
						}
						pack(ptra, pids, leng);
						pids = ((pids % MODS) + 1);
						ptra = (ptrb + leng);
						ptrb = (ptra + OFFS);
						argt[x].leng += (leng + OFFS);
					}
					else
					{
						break;
					}
				}

				if (argt[x].leng > 0)
				{
					leng = write(argt[x].pinp[1], buff, 1);
					if (leng < 1) { /* no-op*/ }
					argt[x].busy = 1;
				}

				slos = 1;
			}
		}
		if (slos == 0)
		{
			sleep(1);
			continue;
		}
	}
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
		if ((strcmp(argv[x], "-o") == 0) && ((x + 1) < argc))
		{
			args.mode = strdup(argv[x + 1]);
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
	}

	proc(&args);

	return 0;
}
