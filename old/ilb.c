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

int NUMT = 128;
int WAIT[] = { 0, 45, 90, 45, 15 };
char SBUF[LINE];

typedef struct list_addr {
	int port;
	char adrs[LINE];
	struct sockaddr_in addr;
} addr_l;

typedef struct object_args {
	int lprt, rprt, timo, leng;
	char *cmds, *larg, *rarg, *ladr, *radr;
	addr_l ilbs[LIST];
} args_o;

typedef struct list_cons {
	int stat, timo;
	int lprt, sprt, dprt;
	int serv, sock, indx, leng;
	char adrl[LINE], adrs[LINE], adrd[LINE], tadr[LINE];
	unsigned char buff[BUDP];
	struct sockaddr_in addr;
	time_t last;
	pthread_t thrp;
	args_o *args;
	addr_l *dest;
} cons_l;

char *getd() {
	bzero(SBUF, LINE);
	snprintf(SBUF, LINE - 8, "%ld", time(NULL));
	return SBUF;
}

void seta(args_o *args, char *addr) {
	int indx = args->leng;
	char *pntr;
	args->rarg = strdup(addr);
	args->radr = args->rarg;
	pntr = repl(args->radr, ':');
	args->rprt = numb(pntr);
	if (indx < LIST) {
		addr_l *adro = &(args->ilbs[indx]);
		bzero(adro->adrs, LINE);
		strncpy(adro->adrs, args->radr, ILEN);
		adro->port = args->rprt;
		bzero(&(adro->addr), sizeof(struct sockaddr_in));
		adro->addr.sin_family = AF_INET;
		adro->addr.sin_port = htons(adro->port);
		adro->addr.sin_addr.s_addr = inet_addr(adro->adrs);
		args->leng += 1;
	}
}

void *loop(void *args) {
	cons_l *conn = (cons_l *)args;
	args_o *argo = conn->args;

	int rprt, leng, fmax;
	char radr[LINE];
	char *prot = "udp";
	unsigned char buff[BUDP];
	struct timeval tval;
	fd_set rfds;
	time_t secs;

	char *pntr = (conn->dest)->adrs;
	int slen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr, dest;
	struct sockaddr_in *aobj = &(addr), *dobj = &(dest);

	bcopy(&(conn->addr), &(addr), slen);
	bcopy(&((conn->dest)->addr), &(dest), slen);

	bzero(radr, LINE);
	if (argo->leng > 1) {
		bcopy(pntr, radr, ILEN); rprt = (conn->dest)->port;
	}

	bzero(conn->adrd, LINE);
	endp(conn->adrd, &(conn->dprt), ILEN, 'g', prot, conn->adrs, conn->sprt);
	if (conn->adrd[0] == 0) {
		comd(conn->adrd, &(conn->dprt), ILEN, argo->cmds, prot, conn->adrs, conn->sprt);
		if (conn->adrd[0] == 0) {
			conn->stat = -1;
		} else {
			endp(conn->adrd, &(conn->dprt), ILEN, 's', prot, conn->adrs, conn->sprt);
		}
	}

	if (conn->stat == 1) {
		if (argo->leng == 1) {
			bzero(conn->tadr, LINE); snprintf(conn->tadr, ILEN, "%s.r", conn->adrs);
			endp(radr, &(rprt), ILEN, 'g', prot, conn->tadr, conn->sprt);
			if (radr[0] == 0) {
				bcopy(pntr, radr, ILEN); rprt = (conn->dest)->port;
				endp(radr, &(rprt), ILEN, 's', prot, conn->tadr, conn->sprt);
			}
			dobj->sin_port = htons(rprt);
			dobj->sin_addr.s_addr = inet_addr(radr);
		}
	}

	if (conn->stat == 1) {
		bzero(conn->tadr, LINE); snprintf(conn->tadr, ILEN, "%s.l", conn->adrl);
		endp(conn->adrs, &(conn->sprt), ILEN, 's', prot, conn->tadr, conn->lprt);
		leng = sendto(conn->sock, conn->buff, conn->leng, 0, (struct sockaddr *)dobj, slen);
	}

	printf("[%s] loop init conn [%d:%d:%d] (%s:%d) [%s:%d] -> [%s:%d] (%s:%d)\n", getd(), conn->indx, conn->leng, conn->timo, conn->adrl, conn->lprt, conn->adrs, conn->sprt, conn->adrd, conn->dprt, radr, rprt);

	fmax = (conn->sock + 1);
	while (conn->stat == 1) {
		FD_ZERO(&(rfds));
		FD_SET(conn->sock, &(rfds));
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if (select(fmax, &(rfds), NULL, NULL, &(tval)) < 0) {
			conn->stat = -1; break;
		}
		secs = time(NULL);

		if (FD_ISSET(conn->sock, &(rfds))) {
			leng = recvfrom(conn->sock, buff, BUDP, 0, (struct sockaddr *)&(dest), (unsigned int *)&(slen));
			if (leng < 1) { conn->stat = -1; break; }
			leng = sendto(conn->serv, buff, leng, 0, (struct sockaddr *)aobj, slen);
			//if (leng < 1) { conn->stat = -1; break; }
			conn->last = secs;
		}

		if ((secs - conn->last) >= conn->timo) {
			conn->stat = -1; break;
		}
	}

	printf("[%s] loop fins conn [%d:%d:%d] (%s:%d) [%s:%d] -> [%s:%d] (%s:%d)\n", getd(), conn->indx, conn->leng, conn->timo, conn->adrl, conn->lprt, conn->adrs, conn->sprt, conn->adrd, conn->dprt, radr, rprt);

	conn->stat = 2;
	return NULL;
}

void serv(args_o *args) {
	NUMT = (NUMT * args->leng);

	int sock, sprt, dprt;
	int indx, leng, fidx;
	int didx = 0, reus = 1;
	char adrs[LINE], adrd[LINE];
	unsigned char buff[BUDP];
	time_t secs;

	int slen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr, dest, temp;
	struct sockaddr_in *aobj = &(addr), *dobj = &(dest), *pobj;

	cons_l cons[NUMT];
	addr_l *aptr;

	srand(time(NULL));

	bzero(&(addr), slen);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(args->lprt);
	addr.sin_addr.s_addr = inet_addr(args->ladr);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reus, sizeof(reus));
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reus, sizeof(reus));
	bind(sock, (struct sockaddr *)aobj, slen);

	indx = 0;
	bzero(&(cons), NUMT * sizeof(cons_l));
	for (int x = 0; x < NUMT; ++x) {
		aptr = &(args->ilbs[didx]);
		bzero(&(dest), slen);
		dest.sin_family = AF_INET;
		dest.sin_port = htons(13370+x);
		dest.sin_addr.s_addr = inet_addr(args->ladr);
		cons[x].sock = socket(AF_INET, SOCK_DGRAM, 0);
		setsockopt(cons[x].sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reus, sizeof(reus));
		setsockopt(cons[x].sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reus, sizeof(reus));
		bind(cons[x].sock, (struct sockaddr *)dobj, slen);
		getsockname(cons[x].sock, (struct sockaddr *)&(temp), (unsigned int *)&(slen));
		strncpy(cons[x].adrl, inet_ntoa(temp.sin_addr), ILEN);
		cons[x].lprt = ntohs(temp.sin_port);
		cons[x].timo = args->timo;
		cons[x].args = args;
		cons[x].dest = aptr;
		cons[x].serv = sock;
		cons[x].indx = x;
		didx = ((didx + 1) % args->leng);
	}

	while (1) {
		bzero(aobj, slen);
		leng = recvfrom(sock, buff, BUDP, 0, (struct sockaddr *)&(addr), (unsigned int *)&(slen));
		secs = time(NULL);
		if (leng > 0) {
			sprt = ntohs(addr.sin_port); bzero(adrs, LINE); strncpy(adrs, inet_ntoa(addr.sin_addr), ILEN);
			dprt = ntohs(dest.sin_port); bzero(adrd, LINE); strncpy(adrd, inet_ntoa(dest.sin_addr), ILEN);

			indx = -1; fidx = -1;
			for (int x = 0; x < NUMT; ++x) {
				if (indx < 0) {
					if (cons[x].stat == 1) {
						if ((sprt == cons[x].sprt) && (strcmp(adrs, cons[x].adrs) == 0)) {
							indx = x; break;
						}
					}
				}
				if (fidx < 0) {
					if ((cons[x].stat == 0) || (cons[x].stat == 2)) {
						if (cons[x].stat == 2) {
							pthread_join(cons[x].thrp, NULL);
							cons[x].stat = 0;
						}
						fidx = x;
					}
				}
			}

			if ((indx < 0) && (fidx > -1)) {
				printf("[%s] serv init sock [%d:%d:%d] [%s:%d] -> [%s:%d]\n", getd(), indx, fidx, leng, adrs, sprt, adrd, dprt);
				indx = fidx;
				pobj = &(cons[indx].addr);
				bcopy(aobj, pobj, slen);
				bcopy(buff, cons[indx].buff, leng);
				bcopy(adrs, cons[indx].adrs, ILEN);
				cons[indx].sprt = sprt;
				cons[indx].leng = leng;
				cons[indx].last = secs;
				cons[indx].stat = 1;
				pthread_create(&(cons[indx].thrp), NULL, loop, &(cons[indx]));
			} else if (indx > -1) {
				pobj = &(cons[indx].dest->addr);
				leng = sendto(cons[indx].sock, buff, leng, 0, (struct sockaddr *)pobj, slen);
				cons[indx].last = secs;
			} else {
				printf("[%s] serv init indx\n", getd());
			}
		}
	}

	for (int x = 0; x < NUMT; ++x) {
		close(cons[x].sock);
	}
	close(sock);
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
		if (strcmp(argv[x], "-l") == 0) { if ((x+1) < argc) { args.larg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-r") == 0) { if ((x+1) < argc) { seta(&(args), argv[x+1]); } }
		if (strcmp(argv[x], "-m") == 0) { if ((x+1) < argc) { NUMT = atoi(argv[x+1]); } }
		if (strcmp(argv[x], "-t") == 0) { if ((x+1) < argc) { WAIT[1] = atoi(argv[x+1]); } }
	}
	args.ladr = args.larg;
	pntr = repl(args.ladr, ':');
	args.lprt = numb(pntr);
	args.timo = WAIT[1];
	if ((args.ladr != NULL) && (args.radr != NULL)) {
		printf("[%s] info main addr [%s:%d] -> [%s:%d]\n", getd(), args.ladr, args.lprt, args.radr, args.rprt);
		if (frkp == 1) {
			pidn = fork();
			if (pidn > 0) { exit(0); }
			printf("[%s] info main fork [%d]\n", getd(), pidn);
		}
		serv(&(args));
	}
	return 0;
}
