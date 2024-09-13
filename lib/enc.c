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

int gini(struct keyp *argk, char mode)
{
	int x = 0, o = 0;
	unsigned char rchr = rrnd();
	if (mode == 'e')
	{
		if ((argk->stat & 1) == 0)
		{
			argk->knum[0] = 0;
			argk->knum[1] = 0; argk->knum[2] = 0; argk->knum[3] = 0; argk->knum[4] = 1;
			argk->stat |= 1;
		}
		if ((argk->stat & 2) == 0)
		{
			gadd(argk->knum, ARCL);
			for (x = 0; x < ARCK; ++x)
			{
				if (x < (ARCK - ARCL))
				{
					argk->init[x] = (rchr ^ crnd());
				}
				else
				{
					argk->init[x] = argk->knum[o]; ++o;
				}
			}
		}
	}
	if (mode == 'd')
	{
		if ((argk->stat & 1) == 0)
		{
			argk->stat |= 1;
		}
	}
	return 1;
}

int ksga(struct keyp *argk, char mode)
{
	int i = 0, j = 0, k = 0, v = 0, x = 0, y = 0;
	int leng = argk->klen;
	unsigned char s = 0;
	gdup(argk->init, ARCK, ARCF);
	if ((argk->stat & 4) == 0)
	{
		for (x = 0; x < ARCF; ++x)
		{
			argk->keys[x] = x;
			argk->xoro[x] = 0;
		}
		for (x = 0; x < (3 * ARCF); ++x)
		{
			y = (x % leng);
			i = ((i + 1) & ARCM);
			k = (((k ^ i) + (argk->init[i] ^ 0x13)) & ARCM);
			v = (((v ^ i) + (argk->skey[y] ^ 0x37)) & ARCM);
			j = ((k + v) & ARCM);
			s = argk->keys[i]; argk->keys[i] = argk->keys[j]; argk->keys[j] = s;
		}
		argk->idxi = 0; argk->idxj = 0; argk->idxk = 0; argk->idxv = 0;
		argk->stat |= 4;
	}
	return 1;
}

void core(int *olen, int *ilen, unsigned char *outp, unsigned char *inpt, int leng, struct keyp *argk, char mode)
{
	int i = argk->idxi, j = argk->idxj, k = argk->idxk, v = argk->idxv;
	int n = *olen, l = *ilen;
	unsigned char s = 0;
	unsigned char ochr = 0, ichr = 0, xoro = 0, ckey = 0;
	while (leng > 0)
	{
		i = ((i + 1) & ARCM);
		k = (((k ^ i) + (argk->init[i] ^ 0x13)) & ARCM);
		v = (((v ^ i) + (argk->xoro[j] ^ 0x37)) & ARCM);
		j = ((k + v) & ARCM);
		s = argk->keys[i]; argk->keys[i] = argk->keys[j]; argk->keys[j] = s;
		ichr = inpt[l]; ckey = (argk->keys[i] ^ argk->keys[j]);
		if (mode == 'e')
		{
			ochr = ((ichr ^ xoro) ^ ckey); outp[n] = ochr;
			xoro = ochr; argk->xoro[j] = ochr;
		}
		else
		{
			ochr = ((ichr ^ ckey) ^ xoro); outp[n] = ochr;
			xoro = ichr; argk->xoro[j] = ichr;
		}
		++l; ++n; --leng;
	}
	argk->idxi = i; argk->idxj = j; argk->idxk = k; argk->idxv = v;
	*olen = n; *ilen = l;
}

int ciph(unsigned char *outp, unsigned char *inpt, int leng, struct keyp *argk, char mode)
{
	int ilen = 0, olen = 0, tlen = 0;
	unsigned char *ptra, *ptrb;
	if (mode == 'e')
	{
		gini(argk, mode);
		ksga(argk, mode);
		bcopy(argk->init, outp, ARCK);
		olen += ARCK;
	}
	else
	{
		ptra = (inpt + (ARCK - ARCL));
		if (gcmp(ptra, argk->knum, ARCL) != 1) { return -1; }
		bcopy(inpt, argk->init, ARCK);
		ilen += ARCK; leng -= (2 * ARCK);
		if (leng < 1) { return -2; }
		ksga(argk, mode);
	}
	core(&olen, &ilen, outp, inpt, leng, argk, mode);
	if (mode == 'e')
	{
		ptrb = argk->init; ilen = 0;
		core(&olen, &ilen, outp, ptrb, ARCK, argk, mode);
	}
	else
	{
		ptrb = argk->hash; tlen = 0;
		core(&tlen, &ilen, ptrb, inpt, ARCK, argk, mode);
		if (memcmp(ptrb, inpt, ARCK) != 0) { return -3; }
		bcopy(ptra, argk->knum, ARCL);
		gini(argk, mode);
	}
	return olen;
}
