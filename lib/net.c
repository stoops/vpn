
#define DLEN 8
#define LIST 16
#define LSTN 96
#define HEDL 128

typedef struct header_packet {
	char_u prot, kind, leng[2], sadr[4], sprt[2], dadr[4], dprt[2];
} pckt_h;

typedef struct list_inet {
	numb_u init, addr, mask;
} inet_l;

typedef struct list_bufs {
	int stat, port, indx, leng;
	char adrs[LINE];
	unsigned char buff[BMAX];
	time_t last;
	struct sockaddr_in addr;
} bufs_l;

typedef struct list_cons {
	int stat, midx, indx, leng;
	int *sock, *rpwp;
	int port[2];
	char adrs[2][LINE];
	unsigned char *buff;
	time_t last, lock[2];
	struct sockaddr_in addr[2];
	pckt_h head;
	ciph_o cryp[2];
} cons_l;

typedef struct object_buff {
	int sock, size, indx, leng;
	unsigned char *pbuf;
	unsigned char buff[BMAX];
} buff_o;

typedef struct object_args {
	int lprt, eprt, rprt, dprt;
	char mode;
	char *comd, *skey, *nots, *dest;
	char *larg, *rarg, *ladr, *radr;
} args_o;

typedef struct object_process {
	int indx;
	int *sock;
	pthread_t thro;
	bufs_l *bufs;
	cons_l *cons;
} proc_o;

typedef struct object_thread {
	int stat, indx;
	int *rpwp, *csoc, *ssoc;
	int *lsoc, *esoc, *rsoc;
	pthread_t thro;
	args_o *args;
	bufs_l *bufs;
	cons_l *cons;
	inet_l *nots;
	proc_o *proc;
} thro_o;

int DIDX = 0;
char DOBJ[DLEN][LINE];
pthread_mutex_t MUTX[2];

char *gett() {
	DIDX = ((DIDX + 1) % DLEN);
	char *pntr = DOBJ[DIDX];
	char temp[LINE];
	time_t rsec;
	struct tm *dobj;
	struct timespec nobj;
	time(&(rsec));
	dobj = localtime(&(rsec));
	clock_gettime(CLOCK_MONOTONIC_RAW, &(nobj));
	bzero(temp, LINE);
	strftime(temp, LINE - 8, "%Y/%m/%d-%H:%M:%S", dobj);
	bzero(pntr, LINE);
	snprintf(pntr, LINE - 8, "%s.%09ld", temp, nobj.tv_nsec);
	return pntr;
}

void copy(char *a, char *b, int n, int m) {
	int c = 0;
	while ((*b != 0) && (c < n)) {
		*a++ = *b++; ++c;
	}
	while (c < m) {
		*a++ = 0; ++c;
	}
}

void inet(inet_l *objc, char *addr) {
	char *pntr = repl(addr, '/');
	numb_u mask = 0;
	numb_u inum = inet_addr(addr);
	if (pntr != NULL) { mask = atoi(pntr); }
	objc->mask = 0xffffffff;
	if ((0 < mask) && (mask < 32)) {
		objc->mask = (objc->mask - ((1 << (32 - mask)) - 1));
	}
	objc->addr = (((inum & 0xff) << 24) | ((inum & 0xff00) << 8) | ((inum & 0xff0000) >> 8) | ((inum & 0xff000000) >> 24));
	objc->addr = (objc->addr & objc->mask);
	objc->init = 1;
}

int isin(inet_l *objc, char *addr) {
	numb_u nadr;
	inet_l iadr;
	inet(&(iadr), addr);
	for (int x = 0; x < LIST; ++x) {
		if (objc[x].init != 1) { continue; }
		nadr = (iadr.addr & objc[x].mask);
		if (nadr == objc[x].addr) { return 1; }
	}
	return 0;
}

void load(inet_l *objc, char *nots) {
	int leng = 0;
	char info[LINE];
	if (nots != NULL) {
		FILE *fobj = fopen(nots, "r");
		while (1) {
			bzero(info, LINE);
			if (fgets(info, LINE - 8, fobj) == NULL) { break; }
			if ((info[0] == '\0') || (info[0] == ' ') || (info[0] == '#')) { continue; }
			if ((info[0] == '\t') || (info[0] == '\r') || (info[0] == '\n')) { continue; }
			if (leng < LIST) {
				inet(&(objc[leng]), info);
				leng += 1;
			}
		}
		fclose(fobj);
	}
}

int senz(int sock, unsigned char *buff, int leng) {
	int numb = 0, size = 0;
	while (leng > 0) {
		size = leng;
		if (size > 8192) { size = 8192; }
		numb = send(sock, buff, size, MSG_NOSIGNAL);
		if (numb < BONE) { break; }
		buff += numb; leng -= numb;
	}
	return numb;
}

int sent(int sock, unsigned char *buff, int leng, int midx) {
	int r;
	pthread_mutex_lock(&(MUTX[midx]));
	r = senz(sock, buff, leng);
	pthread_mutex_unlock(&(MUTX[midx]));
	return r;
}

int recw(buff_o *buff) {
	int diff, rlen, leng = 0, size = 4;
	int minl = BONE, maxl = (BTCP + HEDL);
	unsigned char *pntr;
	buff->leng = -4; buff->size = 0;
	buff->pbuf = buff->buff;
	while ((leng < size) || (buff->leng < buff->size)) {
		if (leng < size) {
			diff = (size - leng);
		} else {
			if (buff->size < BONE) {
				buff->leng = leng;
				pntr = (buff->buff + 2);
				UPACK16(buff->size, pntr);
				if ((buff->size < minl) || (maxl < buff->size)) {
					return -1;
				}
			}
			diff = (buff->size - buff->leng);
		}
		if ((diff < minl) || (maxl < diff)) {
			return -2;
		}
		if (buff->sock < 1) { return -3; }
		rlen = read(buff->sock, buff->pbuf, diff);
		if (rlen < minl) { return -4; }
		if (leng < size) { leng += rlen; }
		else { buff->leng += rlen; }
		buff->pbuf += rlen;
		if ((buff->size > 0) && (buff->leng > buff->size)) {
			return -5;
		}
	}
	if ((buff->size > 0) && (buff->leng == buff->size)) {
		return 1;
	}
	return -6;
}
