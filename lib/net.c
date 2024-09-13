/* gcc -Wall -O3 -fPIC -shared -o net.o lib/net.c */

#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define SUBS 8
#define OFFS 4
#define BONE 1
#define ZERO 0

struct netp
{
	int leng, size, maxb;
	unsigned char *buff;
};

int LIST = 16;

void uadr(char **pntr, int *port, char *inpt)
{
	char *temp = strchr(inpt, ':');
	*pntr = inpt; *port = 0;
	if (temp)
	{
		*temp = 0; ++temp;
		*pntr = inpt;
		*port = atoi(temp);
	}
}

void pack(unsigned char *buff, int leng)
{
	buff[0] = ((ZERO >> 24) & 0xff);
	buff[1] = ((leng >> 16) & 0xff);
	buff[2] = ((leng >>  8) & 0xff);
	buff[3] = ((leng >>  0) & 0xff);
}

void unpk(unsigned char *buff, int *leng)
{
	*leng = ((buff[1] << 16) | (buff[2] <<  8) | (buff[3] <<  0));
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

struct netp *neti(int maxb)
{
	struct netp *objc = malloc(1 * sizeof(struct netp));
	bzero(objc, 1 * sizeof(struct netp));
	objc->maxb = (maxb - SUBS);
	objc->buff = malloc(maxb * sizeof(unsigned char));
	return objc;
}

int rall(int sock, unsigned char *buff, int leng, struct netp *hold)
{
	int size, left;
	unsigned char *pntr, *rptr;
	if ((hold->size < BONE) && (hold->leng >= OFFS))
	{
		unpk(hold->buff, &(hold->size));
		if ((hold->size < OFFS) || (leng < hold->size)) { return -3; }
	}
	while ((hold->leng < OFFS) || ((hold->size > ZERO) && (hold->leng < hold->size)))
	{
		left = (hold->maxb - hold->leng);
		if (left < BONE) { return -1; }
		pntr = (hold->buff + hold->leng);
		size = recv(sock, pntr, left, 0);
		if (size < BONE) { return -2; }
		hold->leng += size;
		if ((hold->size < BONE) && (hold->leng >= OFFS))
		{
			unpk(hold->buff, &(hold->size));
			if ((hold->size < OFFS) || (leng < hold->size)) { return -4; }
		}
	}
	if ((hold->size > ZERO) && (hold->leng >= hold->size))
	{
		pntr = (hold->buff + OFFS);
		size = (hold->size - OFFS);
		bcopy(pntr, buff, size);
		left = (size + OFFS);
		pntr = (hold->buff + left);
		left = (hold->leng - left);
		rptr = hold->buff;
		hold->leng = left;
		hold->size = ZERO;
		while (left > 0)
		{
			*rptr = *pntr;
			++rptr; ++pntr; --left;
		}
		return size;
	}
	return -9;
}

int sall(int sock, unsigned char *buff, int leng)
{
	int wlen;
	if (sock < 1) { return -1; }
	if (leng < 1) { return -2; }
	while (leng > 0)
	{
		wlen = send(sock, buff, leng, 0);
		if (wlen < 0) { return -3; }
		buff += wlen; leng -= wlen;
	}
	return 1;
}
