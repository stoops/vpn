/* gcc -Wall -O3 -fPIC -shared -o enc.o lib/enc.c */

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifndef RNDL
#include "rnd.c"
#endif

#define ARCF 256
#define ARCM 255
#define ARCO 96
#define ARCK 32
#define ARCL 5

struct keyp
{
	int stat, klen, idxi, idxj, idxk, idxv;
	unsigned char init[ARCF], knum[ARCF], hash[ARCF];
	unsigned char xoro[ARCF], skey[ARCF], keys[ARCF];
};

void gadd(unsigned char *a, int l)
{
	int o = 1;
	for (int x = (l - 1); x >= 0; --x)
	{
		if (o == 0) { break; }
		a[x] = (a[x] + o); o = 0;
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

void gdup(unsigned char *d, int l, int n)
{
	for (int x = l; x < n; ++x)
	{
		d[x] = d[x % l];
	}
}

int gini(struct keyp *arck, unsigned char *inpt, int ilen, char mode)
{
	int x = 0, o = 0, z = 0;
	unsigned char rchr = rrnd();
	if (mode == 'e')
	{
		if ((arck->stat & 1) == 0)
		{
			arck->knum[0] = 0;
			arck->knum[1] = 0; arck->knum[2] = 0; arck->knum[3] = 0; arck->knum[4] = 1;
			arck->stat |= 1;
		}
		if ((arck->stat & 2) == 0)
		{
			gadd(arck->knum, ARCL);
			for (x = 0; x < ARCK; ++x)
			{
				if (x < (ARCK - ARCL))
				{
					arck->init[x] = (rchr ^ crnd());
				}
				else
				{
					arck->init[x] = arck->knum[o]; ++o;
				}
			}
		}
		if ((arck->stat & 8) == 0)
		{
			o = (ARCK - ARCL);
			for (x = 0; x < ilen; ++x)
			{
				z = (x & ARCM);
				arck->init[x % o] = (arck->init[x % o] ^ (z ^ inpt[x]));
			}
			arck->stat |= 8;
		}
	}
	if (mode == 'd')
	{
		if ((arck->stat & 1) == 0)
		{
			arck->stat |= 1;
		}
	}
	return 1;
}

int ksga(struct keyp *arck, char mode)
{
	int i = 0, j = 0, k = 0, v = 0, x = 0, y = 0;
	int leng = arck->klen;
	unsigned char s = 0;
	gdup(arck->init, ARCK, ARCF);
	if ((arck->stat & 4) == 0)
	{
		for (x = 0; x < ARCF; ++x)
		{
			arck->keys[x] = x;
			arck->xoro[x] = 0;
		}
		for (x = 0; x < (3 * ARCF); ++x)
		{
			y = (x % leng);
			i = ((i + 1) & ARCM);
			k = (((k ^ i) + (arck->init[i] ^ 0x13)) & ARCM);
			v = (((v ^ i) + (arck->skey[y] ^ 0x37)) & ARCM);
			j = ((k + v) & ARCM);
			s = arck->keys[i]; arck->keys[i] = arck->keys[j]; arck->keys[j] = s;
		}
		arck->idxi = 0; arck->idxj = 0; arck->idxk = 0; arck->idxv = 0;
		arck->stat |= 4;
	}
	return 1;
}

void core(int *olen, int *ilen, unsigned char *outp, unsigned char *inpt, int leng, struct keyp *arck, char mode)
{
	int i = arck->idxi, j = arck->idxj, k = arck->idxk, v = arck->idxv;
	int n = *olen, l = *ilen;
	unsigned char s = 0;
	unsigned char ochr = 0, ichr = 0, xoro = 0, ckey = 0;
	while (leng > 0)
	{
		i = ((i + 1) & ARCM);
		k = (((k ^ i) + (arck->init[i] ^ 0x13)) & ARCM);
		v = (((v ^ i) + (arck->xoro[j] ^ 0x37)) & ARCM);
		j = ((k + v) & ARCM);
		s = arck->keys[i]; arck->keys[i] = arck->keys[j]; arck->keys[j] = s;
		ichr = inpt[l]; ckey = (arck->keys[i] ^ arck->keys[j]);
		if (mode == 'e')
		{
			ochr = ((ichr ^ xoro) ^ ckey); outp[n] = ochr;
			xoro = ochr; arck->xoro[j] = ochr;
		}
		else
		{
			ochr = ((ichr ^ ckey) ^ xoro); outp[n] = ochr;
			xoro = ichr; arck->xoro[j] = ichr;
		}
		++l; ++n; --leng;
	}
	arck->idxi = i; arck->idxj = j; arck->idxk = k; arck->idxv = v;
	*olen = n; *ilen = l;
}

int ciph(unsigned char *outp, unsigned char *inpt, int leng, struct keyp *arck, char mode)
{
	int ilen = 0, olen = 0, tlen = 0;
	unsigned char *ptra, *ptrb;
	if (mode == 'e')
	{
		gini(arck, inpt, leng, mode);
		ksga(arck, mode);
		bcopy(arck->init, outp, ARCK);
		olen += ARCK;
	}
	else
	{
		ptra = (inpt + (ARCK - ARCL));
		if (gcmp(ptra, arck->knum, ARCL) != 1) { return -1; }
		bcopy(inpt, arck->init, ARCK);
		ilen += ARCK; leng -= (2 * ARCK);
		if (leng < 1) { return -2; }
		ksga(arck, mode);
	}
	core(&olen, &ilen, outp, inpt, leng, arck, mode);
	if (mode == 'e')
	{
		ptrb = arck->init; ilen = 0;
		core(&olen, &ilen, outp, ptrb, ARCK, arck, mode);
	}
	else
	{
		ptrb = arck->hash; tlen = 0;
		core(&tlen, &ilen, ptrb, inpt, ARCK, arck, mode);
		if (memcmp(ptrb, inpt, ARCK) != 0) { return -3; }
		bcopy(ptra, arck->knum, ARCL);
		gini(arck, inpt, leng, mode);
	}
	return olen;
}
