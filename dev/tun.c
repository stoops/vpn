#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define NUMP 4
#define NUMT 1
#define SIZE 9500
#define MAXS 64000

typedef struct thread_object {
	int pidn;
	int *pfds;
	struct sockaddr_in *cadr;
	int clen;
} objc_t;

int maxs(int a, int b) {
	if (a > b) { return a; }
	return b;
}

void form(char *outp, int olen, unsigned char *buff, int blen) {
	int x, l, z;
	char *p;
	for (x = 0; x < blen; ++x) {
		l = strlen(outp);
		p = &(outp[l]);
		z = (olen - l);
		if ((31 < buff[x]) && (buff[x] < 127)) { snprintf(p, z, "%c", buff[x]); }
		else { snprintf(p, z, "\\x%02x", buff[x]); }
	}
}

void *proc(void *argp) {
	objc_t *args = (objc_t *)argp;

	int *pfds = args->pfds;
	struct sockaddr_in *cadr = args->cadr;
	int clen = args->clen;

	int rfds = pfds[0], wfds = pfds[2], pidn = pfds[3];
	int rlen, wlen, kind;
	char *name[2] = { "sock", "tuns" };
	unsigned char buff[SIZE];
	unsigned int xfer = 0, rate;
	time_t secs, last = 0;

	kind = ((pidn * -1) % 2);
	printf("proc [%d:%s]\n", pidn, name[kind]);

	while (1) {
		rlen = read(rfds, buff, 16);
		buff[15] = 0; wlen = atoi((char *)buff);
		if ((wlen < 1) || (1900 < wlen)) {
			printf("send erro [%d]\n", wlen);
			break;
		}
		rlen = read(rfds, buff, wlen);
		if (rlen != wlen) {
			printf("send warn [%d] [%d]\n", rlen, wlen);
		}
		if (kind == 0) {
			wlen = sendto(wfds, buff, rlen, 0, (struct sockaddr *)cadr, clen);
		} else {
			wlen = write(wfds, buff, rlen);
		}
		xfer += rlen;
		secs = time(NULL);
		if ((secs - last) >= 1) {
			rate = (((xfer * 8) / (secs - last)) / 1000000);
			printf("send %s:%d [%d:%d/mbps] -> [%s:%d]\n", name[kind], pidn, rlen, rate, inet_ntoa(cadr->sin_addr), ntohs(cadr->sin_port));
			xfer = 0; last = secs;
		}
	}

	return NULL;
}

void *serv(void *argp) {
	char **argv = (char **)argp;

	char *IF_NAME = argv[1], *IF_ADDR = argv[2];
	char line[MAXS];
	unsigned char buff[SIZE];
	int tuns = -1, rlen = -1, wlen = -1;
	struct ifreq ifrq = { 0 };

	tuns = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	ifrq.ifr_flags = (IFF_MULTI_QUEUE | IFF_NO_PI | IFF_TUN);
	strncpy(ifrq.ifr_name, IF_NAME, IFNAMSIZ);
	ioctl(tuns, TUNSETIFF, &ifrq);

	bzero(line, MAXS);
	snprintf(line, MAXS - 8, "ip link set %s up ; ip addr add %s dev %s ; ip link set dev %s txqueuelen 1500", IF_NAME, IF_ADDR, IF_NAME, IF_NAME);
	system(line);

	int sock = -1, fmax = -1;
	int port = atoi(argv[0]); //atoi(argv[5]);
	struct sockaddr_in sadr = { 0 }, cadr = { 0 };
	int slen = sizeof(sadr), clen = sizeof(cadr);
	fd_set rfds;
	struct timeval tval;
	time_t secs, ping, last[2];
	unsigned int xfer[2], rate;

	printf("main [%s:%d]\n", argv[4], port);

	int temp, wfds, indx[2];
	int tfds[NUMT][4], sfds[NUMT][4];
	pthread_t thds[NUMT][2];
	objc_t args[NUMT][2];

	ping = 0;
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sadr.sin_family = AF_INET;
	sadr.sin_port = htons(port);
	sadr.sin_addr.s_addr = inet_addr(argv[4]);
	if (strcmp(argv[3], "s") == 0) {
		bind(sock, (struct sockaddr *)&sadr, slen);
	} else {
		bcopy(&sadr, &cadr, clen);
	}
	for (int x = 0; x < 2; ++x) {
		last[x] = 0;
		xfer[x] = 0;
		indx[x] = 0;
	}

	for (int x = 0; x < NUMT; ++x) {
		bzero(&(args[x][0]), sizeof(objc_t));
		bzero(&(args[x][1]), sizeof(objc_t));
		pipe(tfds[x]); tfds[x][2] = sock; tfds[x][3] = (-1 * ((x + 1) * 2));
		pipe(sfds[x]); sfds[x][2] = tuns; sfds[x][3] = (-1 * ((x * 2) + 1));
		args[x][0].pfds = tfds[x];
		args[x][1].pfds = sfds[x];
		args[x][0].cadr = &cadr; args[x][0].clen = clen;
		args[x][1].cadr = &cadr; args[x][1].clen = clen;
		pthread_create(&(thds[x][0]), NULL, proc, &(args[x][0]));
		pthread_create(&(thds[x][1]), NULL, proc, &(args[x][1]));
		sleep(1);
	}

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(tuns, &rfds);
		FD_SET(sock, &rfds);
		fmax = (maxs(tuns, sock) + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		select(fmax, &rfds, NULL, NULL, &tval);
		secs = time(NULL);
		if (FD_ISSET(tuns, &rfds)) {
			rlen = read(tuns, buff, SIZE - 8);
			if (rlen == 1) {
				printf("main null [%s:%d]\n", inet_ntoa(cadr.sin_addr), ntohs(cadr.sin_port));
			} else {
				xfer[0] += rlen;
				if ((secs - last[0]) >= 1) {
					rate = (((xfer[0] * 8) / (secs - last[0])) / 1000000);
					printf("read tuns [%d:%d/mbps] -> [%s:%d]\n", rlen, rate, inet_ntoa(cadr.sin_addr), ntohs(cadr.sin_port));
					xfer[0] = 0; last[0] = secs;
				}
				//wlen = sendto(sock, buff, rlen, 0, (struct sockaddr *)&cadr, clen);
				temp = indx[0]; wfds = tfds[temp][1];
				bzero(line, 24); snprintf(line, 12, "%d", rlen);
				wlen = write(wfds, line, 16);
				wlen = write(wfds, buff, rlen);
				indx[0] = ((temp + 1) % NUMT);
			}
		}
		if (FD_ISSET(sock, &rfds)) {
			rlen = recvfrom(sock, buff, SIZE - 8, 0, (struct sockaddr *)&cadr, (unsigned int *)&clen);
			if (rlen == 1) {
				printf("main ping [%s:%d]\n", inet_ntoa(cadr.sin_addr), ntohs(cadr.sin_port));
			} else {
				xfer[1] += rlen;
				if ((secs - last[1]) >= 1) {
					rate = (((xfer[1] * 8) / (secs - last[1])) / 1000000);
					printf("read sock [%s:%d] -> [%d:%d/mbps]\n", inet_ntoa(cadr.sin_addr), ntohs(cadr.sin_port), rlen, rate);
					xfer[1] = 0; last[1] = secs;
				}
				//wlen = write(tuns, buff, rlen);
				temp = indx[1]; wfds = sfds[temp][1];
				bzero(line, 24); snprintf(line, 12, "%d", rlen);
				wlen = write(wfds, line, 16);
				wlen = write(wfds, buff, rlen);
				indx[1] = ((temp + 1) % NUMT);
			}
		}
		if ((secs - ping) >= 15) {
			rlen = 1 ; buff[0] = '\0';
			wlen = sendto(sock, buff, rlen, 0, (struct sockaddr *)&cadr, clen);
			ping = secs;
		}
	}

	//pthread_join(threads[0], NULL);
	//pthread_join(threads[1], NULL);
	close(sock);
	close(tuns);
	pthread_exit(NULL);

	return NULL;
}

int main(int argc, char **argv) {
	if (argc < 6) {
		printf("args [%d]\n", argc);
		return 1;
	}

	char *port[NUMP] = { "3531", "3532", "3533", "3534" };
	pthread_t thds[NUMP];

	for (int x = 0; x < NUMP; ++x) {
		argv[0] = port[x];
		pthread_create(&(thds[x]), NULL, serv, argv);
		sleep(1);
	}

	while (1) { sleep(3); }

	return 0;
}
