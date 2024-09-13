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

int NUMT = 96;
char SECS[LINE];

typedef struct list_cons {
	int sock;
	struct sockaddr_in addr;
} cons_l;

typedef struct object_args {
	int lprt, rprt;
	char mode, *skey;
	char *larg, *rarg, *ladr, *radr;
} args_o;

char *getd() {
	bzero(SECS, LINE);
	snprintf(SECS, LINE - 8, "%ld", time(NULL));
	return SECS;
}

void serv(args_o *args) {
	int sock, indx, leng, fmax, erro;
	int reus = 1, slen = sizeof(struct sockaddr_in);
	char mode, sadr[LINE], dadr[LINE];
	unsigned char *pbuf, buff[BUDP], data[BUDP];
	struct sockaddr_in addr, dest, *psoc;
	fd_set rfds;
	cons_l cons[NUMT];
	ciph_o ciph;

	srand(time(NULL));

	bzero(&(addr), slen);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(args->lprt);
	addr.sin_addr.s_addr = inet_addr(args->ladr);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reus, sizeof(reus));
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reus, sizeof(reus));
	bind(sock, (struct sockaddr *)&(addr), slen);

	bzero(&(dest), slen);
	dest.sin_family = AF_INET;
	dest.sin_port = htons(args->rprt);
	dest.sin_addr.s_addr = inet_addr(args->radr);

	indx = 0;
	ciph.q = args->skey;
	bzero(&(cons), NUMT * sizeof(cons_l));
	for (int x = 0; x < NUMT; ++x) {
		cons[x].sock = socket(AF_INET, SOCK_DGRAM, 0);
	}
	while (1) {
		FD_ZERO(&(rfds));
		FD_SET(sock, &(rfds)); fmax = sock;
		for (int x = 0; x < NUMT; ++x) {
			FD_SET(cons[x].sock, &(rfds));
			fmax = maxs(fmax, cons[x].sock);
		}
		if ((erro = select(fmax + 1, &(rfds), NULL, NULL, NULL)) < 0) {
			printf("[%s] erro main sels [%d]\n", getd(), erro);
			break;
		}
		if (FD_ISSET(sock, &(rfds))) {
			pbuf = buff;
			leng = recvfrom(sock, buff, BUDP, 0, (struct sockaddr *)&(addr), (unsigned int *)&(slen));
			if (leng > 0) {
				psoc = &(cons[indx].addr);
				bzero(sadr, LINE); strncpy(sadr, inet_ntoa(addr.sin_addr), ILEN);
				bzero(dadr, LINE); strncpy(dadr, inet_ntoa(dest.sin_addr), ILEN);
				printf("[%s] serv loop sock [%d:%d] [%s:%d] -> [%s:%d]\n", getd(), indx, leng, sadr, ntohs(addr.sin_port), dadr, ntohs(dest.sin_port));
				bcopy(&(addr), psoc, slen);
				if (args->mode == 'c') { mode = 'e'; } else { mode = 'd'; }
				erro = wrap(&(ciph), data, BUDP, buff, leng, mode);
				if (erro > 0) { pbuf = data; leng = erro; }
				if (erro < 0) { pbuf = NULL; }
				if (pbuf != NULL) {
					leng = sendto(cons[indx].sock, pbuf, leng, 0, (struct sockaddr *)&(dest), slen);
				}
				indx = ((indx + 1) % NUMT);
			}
		}
		for (int x = 0; x < NUMT; ++x) {
			if (FD_ISSET(cons[x].sock, &(rfds))) {
				pbuf = buff;
				leng = recvfrom(cons[x].sock, buff, BUDP, 0, (struct sockaddr *)&(addr), (unsigned int *)&(slen));
				if (leng > 0) {
					psoc = &(cons[x].addr);
					bzero(sadr, LINE); strncpy(sadr, inet_ntoa(dest.sin_addr), ILEN);
					bzero(dadr, LINE); strncpy(dadr, inet_ntoa(psoc->sin_addr), ILEN);
					printf("[%s] serv loop conn [%d:%d] [%s:%d] -> [%s:%d]\n", getd(), x, leng, sadr, ntohs(dest.sin_port), dadr, ntohs(psoc->sin_port));
					if (args->mode == 'c') { mode = 'd'; } else { mode = 'e'; }
					erro = wrap(&(ciph), data, BUDP, buff, leng, mode);
					if (erro > 0) { pbuf = data; leng = erro; }
					if (erro < 0) { pbuf = NULL; }
					if (pbuf != NULL) {
						leng = sendto(sock, pbuf, leng, 0, (struct sockaddr *)psoc, slen);
					}
				}
			}
		}
	}
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
		if (strcmp(argv[x], "-c") == 0) { args.mode = 'c'; }
		if (strcmp(argv[x], "-s") == 0) { args.mode = 's'; }
		if (strcmp(argv[x], "-k") == 0) { if ((x+1) < argc) { args.skey = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-l") == 0) { if ((x+1) < argc) { args.larg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-r") == 0) { if ((x+1) < argc) { args.rarg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-m") == 0) { if ((x+1) < argc) { NUMT = atoi(argv[x+1]); } }
	}
	args.ladr = args.larg;
	pntr = repl(args.ladr, ':');
	args.lprt = numb(pntr);
	args.radr = args.rarg;
	pntr = repl(args.radr, ':');
	args.rprt = numb(pntr);
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
