/* gcc -Wall -O3 -fPIC -shared -o net.o lib/net.c */

#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define SUBS 9
#define OFFS 4
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
	buff[0] = ((ZERO >>  8) & 0xff);
	buff[1] = ((ZERO >>  0) & 0xff);
	buff[2] = ((leng >>  8) & 0xff);
	buff[3] = ((leng >>  0) & 0xff);
}

void unpk(unsigned char *buff, int *leng)
{
	*leng = ((buff[2] <<  8) | (buff[3] <<  0));
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

int rall(int sock, unsigned char *buff, int leng, struct netp *hold)
{
	int plen, rlen;
	int maxb = hold->maxb;
	int *hlen = &(hold->leng), *hsiz = &(hold->size);
	unsigned char *pntr, *ptrc;
	unsigned char *data = hold->buff;
	if ((*hlen >= OFFS) && (*hsiz < 1))
	{
		unpk(data, hsiz);
		if ((*hsiz < 1) || (leng < *hsiz)) { return -1; }
	}
	while ((*hlen < OFFS) || ((*hsiz > ZERO) && (*hlen < (*hsiz + OFFS))))
	{
		plen = ((maxb - SUBS) - *hlen);
		if (plen < SUBS) { return -2; }
		pntr = (data + *hlen);
		rlen = recv(sock, pntr, plen, 0);
		if (rlen < 1) { return -3; }
		*hlen += rlen;
		if ((*hlen >= OFFS) && (*hsiz < 1))
		{
			unpk(data, hsiz);
			if ((*hsiz < 1) || (leng < *hsiz)) { return -4; }
		}
	}
	if ((*hsiz > ZERO) && (*hlen >= (*hsiz + OFFS)))
	{
		pntr = (data + OFFS); rlen = *hsiz;
		bcopy(pntr, buff, rlen); rlen += OFFS;
		*hlen = (*hlen - rlen);
		pntr = (data + rlen); plen = *hlen;
		ptrc = data; *hsiz = ZERO;
		while (plen > ZERO)
		{
			*ptrc = *pntr;
			++pntr; ++ptrc; --plen;
		}
		return (rlen - OFFS);
	}
	return -5;
}

int sall(int sock, unsigned char *buff, int leng)
{
	int wlen;
	if (leng < 1) { return -1; }
	while (leng > 0)
	{
		wlen = send(sock, buff, leng, 0);
		if (wlen < 0) { return -2; }
		buff += wlen; leng -= wlen;
	}
	return 1;
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
