
#define ILEN 24
#define LINE 96
#define BUDP 1500
#define BTCP 9500

#define UPACK16(a, b) { a = ((b[0] << 8) | (b[1] & 0xff)); }
#define UPACK32(a, b) { a = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]); }
#define PACKU16(a, b) { a[0] = ((b >>  8) & 0xff); a[1] = (b & 0xff); }
#define PACKU32(a, b) { a[0] = ((b >> 24) & 0xff); a[1] = ((b >> 16) & 0xff); a[2] = ((b >> 8) & 0xff); a[3] = (b & 0xff); }

typedef unsigned  int numb_u;
typedef unsigned char char_u;

typedef struct header_cipher {
	char_u i[16], c[4], l[2];
} ciph_h;

typedef struct object_cipher {
	int i, j, k, l;
	char *q;
	char_u v[96], s[256];
	char_u *p;
	numb_u c;
	ciph_h h;
} ciph_o;

int LLEN = 64;
char *LETS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-+";

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

int endp(char *dest, int *dprt, int leng, char mode, char *prot, char *addr, int port) {
	int sock;
	int rlen, slen = sizeof(struct sockaddr_in);
	char sepr = ' ';
	char inpt[LINE], outp[LINE];
	char *ptra, *ptrb;

	struct sockaddr_in locl = { 0 };
	locl.sin_family = AF_INET;
	locl.sin_port = htons(31337);
	locl.sin_addr.s_addr = inet_addr("127.0.0.1");

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) { return 0; }
	if (connect(sock, (struct sockaddr *)&(locl), slen) != 0) { close(sock); return 0; }

	if (mode == 'g') {
		bzero(inpt, LINE);
		snprintf(inpt, LINE - 8, "get%c%s:%s:%d%c", sepr, prot, addr, port, sepr);
		//rlen = sendto(sock, inpt, strlen(inpt), 0, (struct sockaddr *)&(locl), slen);
		rlen = send(sock, inpt, strlen(inpt), 0);

		bzero(inpt, LINE);
		//rlen = recvfrom(sock, inpt, LINE - 8, 0, (struct sockaddr *)&(locl), (unsigned int *)&(slen));
		rlen = recv(sock, inpt, LINE - 8, 0);

		bcopy(inpt, outp, LINE);
		if ((ptra = repl(outp, ':')) != NULL) {
			ptrb = repl(ptra, ':');
			if (ptrb) { /* no-op */ }
			memcpy(dest, outp, leng);
			*dprt = numb(ptra);
		}
	}

	if (mode == 's') {
		if (dest[0] != 0) {
			bzero(inpt, LINE);
			snprintf(inpt, LINE - 8, "set%c%s:%s:%d%c%s:%d:0", sepr, prot, addr, port, sepr, dest, *dprt);
			rlen = sendto(sock, inpt, strlen(inpt), 0, (struct sockaddr *)&(locl), slen);
			if (rlen) { /* no-op */ }
		}
	}

	close(sock);
	return 0;
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
		} else {
			endp(dest, dprt, leng, 'g', prot, addr, port);
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
	for (int x = 0; x < 256; ++x) { c->s[x] = x; }
	keys(c->s, 256, c->v, 16, c->p, c->l);
	return 0;
}

int wrap(ciph_o *cptr, unsigned char *data, unsigned char *buff, int leng, char mode) {
	numb_u csum, hsum;
	char_u *ptra = data, *ptrb = buff;
	ciph_h *head = &(cptr->h);
	int size = leng, olen = leng;
	int hlen = sizeof(ciph_h);
	if (cptr->q == NULL) { return 0; }
	if (mode == 'e') {
		for (int x = 0; x < 16; ++x) {
			cptr->v[x] = LETS[rand()%LLEN];
		}
		bcopy(cptr->v, head->i, 16);
		ptra += hlen; size += hlen;
	} else {
		bcopy(buff, head, hlen);
		bcopy(head->i, cptr->v, 16);
		ptrb += hlen; size -= hlen;
		UPACK16(leng, head->l); size = leng;
	}
	if ((size < 1) || (BUDP < size) || (leng < 1) || (BUDP < leng)) {
		return -1;
	}
	init(cptr);
	ciph(ptra, ptrb, leng, &(cptr->i), &(cptr->j), &(cptr->k), cptr->s, mode);
	sums(&(csum), cptr->s, cptr->i, cptr->j, cptr->k);
	if (mode == 'e') {
		PACKU32(head->c, csum);
		PACKU16(head->l, olen);
		bcopy(head, data, hlen);
	} else {
		UPACK32(hsum, head->c);
		if (csum != hsum) {
			return -2;
		}
	}
	return size;
}
