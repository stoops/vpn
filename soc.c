/* gcc -Wno-format-truncation -O3 -Wall -o soc soc.c */
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

#include "lib/enc.c"
#include "lib/inc.c"
#include "lib/net.c"

int NUMC = 64, EXPC = 15;

#include "udpc.c"
#include "udps.c"
#include "tcpc.c"
#include "tcps.c"

char mode(char *argv) {
	if (strcmp(argv, "uc") == 0) { return 1; }
	if (strcmp(argv, "us") == 0) { return 2; }
	if (strcmp(argv, "tc") == 0) { return 3; }
	if (strcmp(argv, "ts") == 0) { return 4; }
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
		if (strcmp(argv[x], "-m") == 0) { if ((x+1) < argc) { args.mode = mode(argv[x+1]); } }
		if (strcmp(argv[x], "-d") == 0) { if ((x+1) < argc) { args.dest = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-e") == 0) { if ((x+1) < argc) { args.comd = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-k") == 0) { if ((x+1) < argc) { args.skey = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-l") == 0) { if ((x+1) < argc) { args.larg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-r") == 0) { if ((x+1) < argc) { args.rarg = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-n") == 0) { if ((x+1) < argc) { args.nots = strdup(argv[x+1]); } }
		if (strcmp(argv[x], "-c") == 0) { if ((x+1) < argc) { NUMC = atoi(argv[x+1]); } }
		if (strcmp(argv[x], "-t") == 0) { if ((x+1) < argc) { EXPC = atoi(argv[x+1]); } }
	}
	args.ladr = args.larg;
	pntr = repl(args.ladr, ':');
	args.lprt = numb(pntr);
	args.radr = args.rarg;
	pntr = repl(args.radr, ':');
	args.rprt = numb(pntr);
	pntr = repl(args.dest, ':');
	args.dprt = numb(pntr);
	if ((args.ladr != NULL) && (args.radr != NULL)) {
		printf("[%s] info main addr [%s:%d] -> [%s:%d]\n", gett(), args.ladr, args.lprt, args.radr, args.rprt);
		if (frkp == 1) {
			pidn = fork();
			if (pidn > 0) { exit(0); }
			printf("[%s] info main fork [%d]\n", gett(), pidn);
		}
		if (args.mode == 1) { udpc_serv(&(args)); }
		if (args.mode == 2) { udps_serv(&(args)); }
		if (args.mode == 3) { tcpc_serv(&(args)); }
		if (args.mode == 4) { tcps_serv(&(args)); }
	}
	return 0;
}
