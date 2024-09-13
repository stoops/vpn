/* gcc -Wall -O3 -fPIC -shared -o rnd.o lib/rnd.c */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define RNDL 11

unsigned char SEED[RNDL];

int urnd()
{
	int fdes = open("/dev/urandom", O_RDONLY);
	int erro = read(fdes, SEED, RNDL);
	if (erro < 0) { /* no-op */ }
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
	if (erro < 0) { /* no-op */ }
	unsigned int init = ((SEED[0] << 24) | (SEED[1] << 16) | (SEED[2] <<  8) | (SEED[3] <<  0));
	srand(init);
	for (int x = 0; x < RNDL; ++x)
	{
		SEED[x] = (SEED[x] ^ crnd());
	}
	return init;
}

unsigned char rrnd()
{
	unsigned char r = crnd();
	for (int x = 0; x < RNDL; ++x)
	{
		r = (r ^ SEED[x]);
		SEED[x] = (SEED[x] ^ crnd());
	}
	return r;
}
