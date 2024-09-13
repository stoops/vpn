/* gcc -DECK -s -o key.o key.c -lcrypto */

#define KDLY 1
#define KTRY 3
#define KSEC 5
#define KEXL 768

#ifndef ECK

struct keyp xchg(int sock, char *skey, char mode, int indx)
{
	int maxl = (KEXL - ARCO);
	int mlen = (ARCK + ARCL);
	int klen = (ARCL + ZERO);

	int slen, rlen, auth = 0;
	char *hexl = "0123456789abcdef";
	unsigned char init[KEXL], inpt[KEXL], encr[KEXL], decr[KEXL];
	unsigned char *pntr;
	time_t snum = time(NULL);
	struct pollfd pfds[1];
	struct keyp ekey, dkey, keys;
	struct netp *hold = neti(MAXB);

	bzero(&keys, 1 * sizeof(struct keyp));
	bzero(&ekey, 1 * sizeof(struct keyp));
	bzero(&dkey, 1 * sizeof(struct keyp));
	ekey.klen = hexs(ekey.skey, skey, ARCK);
	dkey.klen = hexs(dkey.skey, skey, ARCK);
	itoc(ekey.knum, snum + KSEC, 1);
	itoc(dkey.knum, snum - KSEC, 1);
	ekey.stat = 1; dkey.stat = 1;

	bcopy("auth-", init, klen);
	for (int x = klen; x < mlen; ++x)
	{
		init[x] = rrnd();
	}

	for (int z = 0; z < 2; ++z)
	{
		if (((mode == 'c') && (z == 0)) || ((mode == 's') && (z == 1)))
		{
			pntr = (encr + OFFS);
			rlen = ciph(pntr, init, mlen, &ekey, 'e');
			rlen = (rlen + OFFS);
			pack(encr, rlen);
			slen = sall(sock, encr, rlen);
			if (slen < 1) { /* no-op */ }
			printf("%s INFO xchg auth thread-[%d][%c] {S} <%lu>\n", date(), indx + 1, mode, snum); fflush(stdout);
		}

		if (((mode == 'c') && (z == 1)) || ((mode == 's') && (z == 0)))
		{
			for (int x = 0; (x < KTRY) && (auth != 1); ++x)
			{
				bzero(&(pfds), 1 * sizeof(struct pollfd));
				pfds[0].fd = sock; pfds[0].events = POLLIN;
				rlen = poll(pfds, 1, KDLY * 1000);
				if ((rlen > 0) && (pfds[0].revents & POLLIN))
				{
					rlen = rall(sock, encr, maxl, hold);
					if (rlen > 0)
					{
						bzero(decr, KEXL);
						slen = ciph(decr, encr, rlen, &dkey, 'd');
						if ((slen == mlen) && (memcmp(decr, "auth-", klen) == 0) && (memcmp(decr, init, mlen) != 0))
						{
							printf("%s INFO xchg auth thread-[%d][%c] {R} <%lu>\n", date(), indx + 1, mode, snum); fflush(stdout);
							bcopy(decr, inpt, mlen);
							auth = 1;
						}
					}
				}
			}
		}
	}

	if (auth == 1)
	{
		char outh[KEXL];
		bzero(outh, KEXL);
		for (int x = 0; x < ARCK; ++x)
		{
			int i = (x + klen);
			keys.skey[x] = (init[i] ^ inpt[i]);
			int j = (x * 2);
			if (x < 12)
			{
				outh[j+0] = hexl[(keys.skey[x]>>4)&0xf];
				outh[j+1] = hexl[(keys.skey[x]>>0)&0xf];
			}
		}
		keys.klen = ARCK;
		printf("%s INFO xchg auth thread-[%d][%c] {X} <0x%s>\n", date(), indx + 1, mode, outh); fflush(stdout);
	}
	else
	{
		printf("%s ERRO xchg fail thread-[%d][%c] {E} <%lu>\n", date(), indx + 1, mode, snum); fflush(stdout);
	}

	free(hold->buff);

	return keys;
}

#else

#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

typedef unsigned char uchar;

void rnds(unsigned char *b, int l)
{
	int f = open("/dev/urandom", O_RDONLY);
	int r = read(f, b, l);
	if (r < 1) { /* no-op */ }
	close(f);
}

uchar *hash(char *ixno, char *iyno)
{
	char *lets = "0123456789abcdef";
	char outh[EVP_MAX_MD_SIZE*4];
	unsigned int hlen = 0;
	unsigned char data[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *ctxh = EVP_MD_CTX_new();

	EVP_DigestInit_ex(ctxh, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctxh, ixno, strlen(ixno));
	EVP_DigestUpdate(ctxh, iyno, strlen(iyno));
	EVP_DigestFinal_ex(ctxh, data, &hlen);
	EVP_MD_CTX_free(ctxh);

	bzero(outh, EVP_MAX_MD_SIZE*4);
	for (int x = 0; x < 32; ++x)
	{
		outh[(x*2)+0] = lets[(data[x] >> 4) & 0xf];
		outh[(x*2)+1] = lets[(data[x] >> 0) & 0xf];
	}

	return (uchar *)strdup(outh);
}

int EC_POINT_sub(const EC_GROUP *g, EC_POINT *r, const EC_POINT *p, const EC_POINT *q, BN_CTX *ctx)
{
	int good = 0;
	EC_POINT *n = EC_POINT_new(g);
	if (n == NULL) { return 0; }
	if (!EC_POINT_copy(n, q)) { goto erro; }
	if (!EC_POINT_invert(g, n, ctx)) { goto erro; }
	if (!EC_POINT_add(g, r, p, n, ctx)) { goto erro; }
	good = 1;

erro:

	EC_POINT_free(n);
	return good;
}

uchar *pnum(char *pstr, BIGNUM *bnum)
{
	char *a = BN_bn2hex(bnum);
	return (uchar *)a;
}

void ppnt(char *pstr, EC_POINT *ecpt, EC_GROUP *ecgr, BN_CTX *bctx)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, ecpt, x, y, bctx);
	char *a = BN_bn2hex(x);
	char *b = BN_bn2hex(y);
	OPENSSL_free(a);
	OPENSSL_free(b);
	BN_free(x);
	BN_free(y);
}

void ekpe(uchar **mk, uchar **cx, uchar **cy, uchar **ex, uchar **ey, uchar **mh, char *pstr, uchar *kx, uchar *ky, EC_GROUP *ecgr, BN_CTX *bctx)
{
	BIGNUM *xpnt = NULL, *ypnt = NULL;
	BN_hex2bn(&xpnt, (char *)kx);
	BN_hex2bn(&ypnt, (char *)ky);
	EC_POINT *qpnt = EC_POINT_new(ecgr);
	EC_POINT_set_affine_coordinates(ecgr, qpnt, xpnt, ypnt, bctx);

	unsigned char mint[32];
	rnds(mint, 32);
	BIGNUM *mnum = BN_bin2bn(mint, 32, NULL);
	EC_POINT *mpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, mpnt, mnum, NULL, NULL, bctx);

	unsigned char rint[32];
	rnds(rint, 32);
	BIGNUM *rnum = BN_bin2bn(rint, 32, NULL);
	EC_POINT *cpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, cpnt, rnum, NULL, NULL, bctx);

	EC_POINT *epnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, epnt, NULL, qpnt, rnum, bctx);
	EC_POINT_add(ecgr, epnt, epnt, mpnt, bctx);

	uchar *mx = NULL, *my = NULL;
	BIGNUM *mxno = BN_new(), *myno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, mpnt, mxno, myno, bctx);
	mx = pnum(NULL, mxno);
	my = pnum(NULL, myno);
	*mh = hash((char *)mx, (char *)my);

	uchar *rn = NULL;
	*mk = pnum("m", mnum);
	rn = pnum("r", rnum);

	BIGNUM *exno = BN_new(), *eyno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, epnt, exno, eyno, bctx);
	*ex = pnum(NULL, exno);
	*ey = pnum(NULL, eyno);

	BIGNUM *cxno = BN_new(), *cyno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, cpnt, cxno, cyno, bctx);
	*cx = pnum(NULL, cxno);
	*cy = pnum(NULL, cyno);

	OPENSSL_free(rn); OPENSSL_free(mx); OPENSSL_free(my);
	BN_free(mxno); BN_free(myno);
	BN_free(exno); BN_free(eyno); BN_free(cxno); BN_free(cyno);
	BN_free(xpnt); BN_free(ypnt); BN_free(mnum); BN_free(rnum);
	EC_POINT_free(cpnt); EC_POINT_free(epnt); EC_POINT_free(qpnt); EC_POINT_free(mpnt);
}

void ekpd(uchar **mk, uchar **sx, uchar **sy, char *pstr, uchar *cx, uchar *cy, uchar *ex, uchar *ey, uchar *mh, uchar *kn, EC_GROUP *ecgr, BN_CTX *bctx)
{
	BIGNUM *cxno = NULL, *cyno = NULL;
	BN_hex2bn(&cxno, (char *)cx);
	BN_hex2bn(&cyno, (char *)cy);
	EC_POINT *cpnt = EC_POINT_new(ecgr);
	EC_POINT_set_affine_coordinates(ecgr, cpnt, cxno, cyno, bctx);

	BIGNUM *exno = NULL, *eyno = NULL;
	BN_hex2bn(&exno, (char *)ex);
	BN_hex2bn(&eyno, (char *)ey);
	EC_POINT *epnt = EC_POINT_new(ecgr);
	EC_POINT_set_affine_coordinates(ecgr, epnt, exno, eyno, bctx);

	BIGNUM *knum = NULL;
	BN_hex2bn(&knum, (char *)kn);
	EC_POINT *dpnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, dpnt, NULL, cpnt, knum, bctx);

	EC_POINT *mpnt = EC_POINT_new(ecgr);
	EC_POINT_sub(ecgr, mpnt, epnt, dpnt, bctx);

	BIGNUM *mkno = NULL;
	BN_hex2bn(&mkno, (char *)*mk);
	EC_POINT *spnt = EC_POINT_new(ecgr);
	EC_POINT_mul(ecgr, spnt, NULL, mpnt, mkno, bctx);

	uchar *hh = NULL;
	uchar *mx = NULL, *my = NULL;
	BIGNUM *mxno = BN_new(), *myno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, mpnt, mxno, myno, bctx);
	mx = pnum(NULL, mxno);
	my = pnum(NULL, myno);
	hh = hash((char *)mx, (char *)my);

	uchar *mn = NULL;
	mn = pnum("m", mkno);

	BIGNUM *sxno = BN_new(), *syno = BN_new();
	EC_POINT_get_affine_coordinates(ecgr, spnt, sxno, syno, bctx);
	if ((strlen((char *)mh) != 64) || (strlen((char *)hh) != strlen((char *)mh)) || (strncmp((char *)hh, (char *)mh, 64) != 0))
	{
		printf("!: [%s] != [%s]\n", mh, hh);
		*sx = NULL; *sy = NULL;
	}
	else
	{
		*sx = pnum(NULL, sxno); *sy = pnum(NULL, syno);
	}

	OPENSSL_free(mn); OPENSSL_free(mx); OPENSSL_free(my); OPENSSL_free(hh);
	BN_free(mxno); BN_free(myno);
	BN_free(cxno); BN_free(cyno); BN_free(exno); BN_free(eyno);
	BN_free(sxno); BN_free(syno); BN_free(mkno); BN_free(knum);
	EC_POINT_free(cpnt); EC_POINT_free(epnt); EC_POINT_free(dpnt); EC_POINT_free(mpnt); EC_POINT_free(spnt);
}

struct keyp xchg(int sock, char *skey, char mode, int indx)
{
	int maxl = (KEXL - SUBS);

	int leng, rlen;
	uchar buff[KEXL];
	char *temp, *pnts, *pntr = (char *)buff;
	struct pollfd pfds[1];
	struct keyp keys;

	bzero(&keys, sizeof(struct keyp));

	BN_CTX *bctx = BN_CTX_new();
	EC_GROUP *ecgr = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	uchar *ck, *cx, *cy;
	uchar *cmkn, *csxn, *csyn;

	uchar *ccxn, *ccyn, *cexn, *ceyn, *chsh;
	uchar *scxn, *scyn, *sexn, *seyn, *shsh;

	FILE *file = fopen(skey, "r");
	bzero(buff, KEXL); temp = fgets(pntr, maxl, file); ck = (uchar *)strdup(pntr);
	bzero(buff, KEXL); temp = fgets(pntr, maxl, file); cx = (uchar *)strdup(pntr);
	bzero(buff, KEXL); temp = fgets(pntr, maxl, file); cy = (uchar *)strdup(pntr);
	fclose(file); if (temp == NULL) { /* no-op */ }

	ekpe(&cmkn, &ccxn, &ccyn, &cexn, &ceyn, &chsh, "a->b", cx, cy, ecgr, bctx);

	bzero(buff, KEXL);
	strcat(pntr, (char *)ccxn); strcat(pntr, (char *)" ");
	strcat(pntr, (char *)ccyn); strcat(pntr, (char *)" ");
	strcat(pntr, (char *)cexn); strcat(pntr, (char *)" ");
	strcat(pntr, (char *)ceyn); strcat(pntr, (char *)" ");
	strcat(pntr, (char *)chsh); strcat(pntr, (char *)" ");

	sall(sock, buff, maxl);

	bzero(buff, KEXL); leng = 0;
	for (int x = 0; (x < KTRY) && (leng < maxl); ++x)
	{
		bzero(&(pfds), 1 * sizeof(struct pollfd));
		pfds[0].fd = sock; pfds[0].events = POLLIN;
		rlen = poll(pfds, 1, KDLY * 1000);
		if ((rlen > 0) && (pfds[0].revents & POLLIN))
		{
			rlen = recv(sock, buff + leng, maxl - leng, 0);
			if (rlen < 1) { break; }
			leng += rlen;
		}
	}

	if (leng == maxl)
	{
		buff[512] = 0; bzero(buff + 512, 16); pnts = (char *)buff;
		temp = strchr(pnts, ' '); if (temp != NULL) { *temp = 0; scxn = (uchar *)strdup(pnts); pnts = (temp + 1); } else { scxn = (uchar *)strdup("0"); }
		temp = strchr(pnts, ' '); if (temp != NULL) { *temp = 0; scyn = (uchar *)strdup(pnts); pnts = (temp + 1); } else { scyn = (uchar *)strdup("0"); }
		temp = strchr(pnts, ' '); if (temp != NULL) { *temp = 0; sexn = (uchar *)strdup(pnts); pnts = (temp + 1); } else { sexn = (uchar *)strdup("0"); }
		temp = strchr(pnts, ' '); if (temp != NULL) { *temp = 0; seyn = (uchar *)strdup(pnts); pnts = (temp + 1); } else { seyn = (uchar *)strdup("0"); }
		temp = strchr(pnts, ' '); if (temp != NULL) { *temp = 0; shsh = (uchar *)strdup(pnts); pnts = (temp + 1); } else { shsh = (uchar *)strdup("0"); }

		ekpd(&cmkn, &csxn, &csyn, "a<-b", scxn, scyn, sexn, seyn, shsh, ck, ecgr, bctx);

		if ((csxn == NULL) || (csyn == NULL))
		{
			printf("E: [%s]\n", shsh);
			csxn = (uchar *)strdup("0");
			csyn = (uchar *)strdup("0");
		}
		else
		{
			bzero(buff, KEXL);
			strcat(pntr, (char *)csxn); strcat(pntr, (char *)csyn);
			printf("K: [%s]\n", pntr);
			keys.klen = hexs(keys.skey, pntr, strlen(pntr));
		}
	}

	OPENSSL_free(cmkn); OPENSSL_free(csxn); OPENSSL_free(csyn);
	OPENSSL_free(ck); OPENSSL_free(cx); OPENSSL_free(cy);

	OPENSSL_free(ccxn); OPENSSL_free(ccyn); OPENSSL_free(cexn); OPENSSL_free(ceyn); OPENSSL_free(chsh);
	OPENSSL_free(scxn); OPENSSL_free(scyn); OPENSSL_free(sexn); OPENSSL_free(seyn); OPENSSL_free(shsh);

	BN_CTX_free(bctx);
	EC_GROUP_free(ecgr);

	return keys;
}

#endif
