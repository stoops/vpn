
#define VLEN 16
#define ILEN 24
#define LINE 96
#define BUDP 1500
#define BTCP 9500
#define BMAX 9900
#define BONE 1

#define UPACK16(a, b) { a = ((b[0] << 8) | (b[1] & 0xff)); }
#define UPACK32(a, b) { a = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]); }
#define PACKU16(a, b) { a[0] = ((b >>  8) & 0xff); a[1] = (b & 0xff); }
#define PACKU32(a, b) { a[0] = ((b >> 24) & 0xff); a[1] = ((b >> 16) & 0xff); a[2] = ((b >> 8) & 0xff); a[3] = (b & 0xff); }

typedef unsigned  int numb_u;
typedef unsigned char char_u;

typedef struct header_cipher {
	char_u p, k, l[2], c[8], i[16];
} ciph_h;

typedef struct object_cipher {
	int l;
	char *q;
	char_u i, j, k;
	char_u v[96], s[256];
	char_u *p;
	numb_u c;
	ciph_h h;
} ciph_o;

int maxs(int a, int b) {
	if (a > b) { return a; }
	return b;
}

int maxm(int a, int b, int c) {
	if (a > b) { return c; }
	return a;
}

int numb(char *strs) {
	if (strs == NULL) { return -1; }
	return atoi(strs);
}

char *repl(char *strs, char find) {
	char *pntr = NULL;
	if (strs == NULL) { return pntr; }
	if ((pntr = strchr(strs, find)) != NULL) {
		*pntr = '\0';
		return (pntr + 1);
	}
	return pntr;
}

void fins(int *fdes, int shut) {
	if (*fdes > 0) {
		if (shut != 0) {
			shutdown(*fdes, 2);
		}
		close(*fdes);
	}
	*fdes = -1;
}

int comd(char *dest, int *dprt, int leng, char *cmds, char *prot, char *addr, int port) {
	char inpt[LINE], outp[LINE];
	char *pntr, *args[] = { cmds, addr, inpt, prot, NULL };
	int erro, link[2];
	pid_t pidn;
	if (cmds == NULL) { return 0; }
	if ((erro = pipe(link)) < 0) { return 0; }
	if ((pidn = fork()) == 0) {
		bzero(inpt, LINE);
		snprintf(inpt, LINE - 8, "%d", port);
		dup2(link[1], STDOUT_FILENO); /* dup2(link[1], STDERR_FILENO); */
		close(link[0]); close(link[1]);
		execv(args[0], args);
	} else {
		close(link[1]);
		waitpid(pidn, NULL, 0);
		bzero(outp, LINE);
		erro = read(link[0], outp, LINE - 8);
		if ((pntr = repl(outp, ':')) != NULL) {
			memcpy(dest, outp, leng);
			*dprt = numb(pntr);
		}
		close(link[0]);
	}
	return 0;
}

int init(ciph_o *c) {
	if (c->q == NULL) { return -1; }
	c->p = (char_u *)c->q;
	c->l = strlen(c->q);
	c->i = 0; c->j = 0; c->k = 0;
	keys(c->s, 384, c->v, 16, c->p, c->l);
	return 0;
}

int wrap(ciph_o *cptr, unsigned char *data, int maxl, unsigned char *buff, int leng, char mode) {
	char_u *ptra = data, *ptrb = buff;
	ciph_h *head = &(cptr->h);
	int elen = leng, dlen = leng, size = leng;
	int hlen = sizeof(ciph_h);
	int clen = sizeof(head->c);
	char_u csum[clen];
	if (cptr->q == NULL) { return 0; }
	if (mode == 'e') {
		for (int x = 0; x < VLEN; ++x) {
			cptr->v[x] = (rand() & 0xff);
		}
		bcopy(cptr->v, head->i, VLEN);
		ptra += hlen; elen += hlen;
	} else {
		bcopy(buff, head, hlen);
		bcopy(head->i, cptr->v, VLEN);
		ptrb += hlen; size -= hlen;
		UPACK16(dlen, head->l);
		if (dlen != leng) { return -9; }
	}
	if ((elen < BONE) || (maxl < elen) || (dlen < BONE) || (maxl < dlen)) {
		return -11;
	}
	init(cptr);
	ciph(ptra, ptrb, size, &(cptr->i), &(cptr->j), &(cptr->k), cptr->s, mode);
	sums(csum, clen, cptr->i, cptr->j, cptr->k, cptr->s);
	if (mode == 'e') {
		head->p = 9; head->k = 9;
		size = elen;
		PACKU16(head->l, size);
		bcopy(csum, head->c, clen);
		bcopy(head, data, hlen);
	} else {
		if (bcmp(csum, head->c, clen) != 0) {
			return -12;
		}
	}
	return size;
}
