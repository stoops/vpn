
#define MGMA 1
#define MGMB 3
#define DLEN 8
#define LIST 16
#define LSTN 96
#define HEDL 128
#define ENDL 31337
#define CHKL 43210
#define USLA 357000
#define USLB 753000

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
	int stat, midx, leng;
	int indx, tidx;
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
	char mode, conz;
	char *comd, *skey, *nots, *dest;
	char *larg, *rarg, *ladr, *radr;
} args_o;

typedef struct object_process {
	int stat;
	int indx, tidx;
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
int NUMC = 64, EXPC = 15;
char *LOCL = "127.0.0.1";
pthread_mutex_t *MUTX;

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
	strftime(temp, LINE - 8, "%Y-%m-%d_%H:%M:%S", dobj);
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

int recu(int sock, unsigned char *buff, int size, struct sockaddr_in *addr) {
	int leng = 0;
	int slen = sizeof(struct sockaddr_in);
	if (sock > 0) {
		leng = recvfrom(sock, buff, size, 0, (struct sockaddr *)addr, (unsigned int *)&(slen));
	}
	return leng;
}

int senu(int sock, unsigned char *buff, int size, struct sockaddr_in *addr) {
	int leng = 0;
	int slen = sizeof(struct sockaddr_in);
	if (sock > 0) {
		leng = sendto(sock, buff, size, 0, (struct sockaddr *)addr, slen);
	}
	return leng;
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
					return -22;
				}
			}
			diff = (buff->size - buff->leng);
		}
		if ((diff < minl) || (maxl < diff)) {
			return -33;
		}
		if (buff->sock < 1) { return -44; }
		rlen = read(buff->sock, buff->pbuf, diff);
		if (rlen < minl) {
			/*printf("erro [%s]\n", strerror(errno));*/
			return rlen;
		}
		if (leng < size) { leng += rlen; }
		else { buff->leng += rlen; }
		buff->pbuf += rlen;
		if ((buff->size > 0) && (buff->leng > buff->size)) {
			return -66;
		}
	}
	if ((buff->size > 0) && (buff->leng == buff->size)) {
		return 1;
	}
	return -77;
}

int senz(int sock, unsigned char *buff, int leng) {
	int numb = 0, size = 0, maxl = 8192;
	while ((sock > 0) && (leng > 0)) {
		size = leng;
		if (size > maxl) { size = maxl; }
		numb = send(sock, buff, size, MSG_NOSIGNAL);
		if (numb < BONE) { break; }
		buff += numb; leng -= numb;
	}
	return numb;
}

int sent(int sock, unsigned char *buff, int leng, int midx) {
	int retl = 0;
	pthread_mutex_lock(&(MUTX[midx]));
	retl = senz(sock, buff, leng);
	pthread_mutex_unlock(&(MUTX[midx]));
	return retl;
}

void join(pthread_t thro, char *name, int idno) {
	printf("[%s] info join prep [%s] [%d]\n", gett(), name, idno);
	pthread_join(thro, NULL);
	printf("[%s] info join post [%s] [%d]\n", gett(), name, idno);
}

int icon(int sock, struct sockaddr_in *dest) {
	int erro, fdes, leng = sizeof(struct sockaddr_in);
	if (sock < 1) {
		if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			printf("[%s] warn icon conn sock\n", gett()); close(fdes);
		} else if ((erro = connect(fdes, (struct sockaddr *)dest, leng)) != 0) {
			printf("[%s] warn icon conn conn\n", gett()); close(fdes);
		} else { sock = fdes; }
	}
	return sock;
}

void fcon(int sock, int midx, pckt_h *head, ciph_o *cryp, int leng) {
	int erro = 1;
	int hlen = sizeof(pckt_h);
	int size = (hlen + 1);
	int maxl = (BTCP + HEDL);
	unsigned char temp[BMAX], data[BMAX];
	unsigned char *pntr;
	pckt_h heds;
	if (sock > 0) {
		bcopy(head, &(heds), hlen);
		PACKU16(heds.leng, leng);
		bcopy(&(heds), data, hlen); pntr = data;
		erro = wrap(cryp, temp, maxl, data, size, 'e');
		if (erro > 0) { pntr = temp; size = erro; }
		erro = sent(sock, pntr, size, midx);
	}
}

int sels(fd_set *fptr, int soca, int socb) {
	int erro, fmax = 0, tims = 0, timm = USLB;
	struct timeval tval, *tptr = NULL;
	FD_ZERO(fptr);
	if (soca > 0) { FD_SET(soca, fptr); }
	if (socb > 0) { FD_SET(socb, fptr); }
	if ((tims > 0) || (timm > 0)) {
		tval.tv_sec = tims;
		tval.tv_usec = timm;
		tptr = &(tval);
	}
	fmax = (maxs(soca, socb) + 1);
	if ((erro = select(fmax, fptr, NULL, NULL, tptr)) < 0) {
		printf("[%s] erro sels [%d]\n", gett(), erro);
		return -1;
	}
	return 0;
}

int sets(cons_l *conn, proc_o *proc, pckt_h *head, char *skey, int *rpwp, int *ssoc, int *csoc, int indx, int tidx, int kind) {
	int hlen = sizeof(pckt_h);
	int fdes = -1, zero = 0, good = 1, port, rwfd[2];
	int *sock = &(ssoc[indx]);
	struct sockaddr_in *padr;
	time_t secs = time(NULL);
	rwfd[0] = -1; rwfd[1] = -1;
	if (kind == 1) {
		fdes = socket(AF_INET, SOCK_DGRAM, 0);
	} else {
		socketpair(AF_UNIX, SOCK_STREAM, 0, rwfd);
		if ((rwfd[0] > 0) && (rwfd[1] > 0)) {
			rpwp[0] = rwfd[0]; rpwp[1] = rwfd[1];
			fdes = socket(AF_INET, SOCK_STREAM, 0);
		}
	}
	if (fdes < 1) {
		close(rwfd[0]); close(rwfd[1]);
		return fdes;
	}
	*sock = fdes;
	UPACK16(port, head->sprt);
	conn->port[0] = port;
	padr = &(conn->addr[0]);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(port);
	UPACK32(padr->sin_addr.s_addr, head->sadr);
	UPACK16(port, head->dprt);
	conn->port[1] = port;
	padr = &(conn->addr[1]);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(port);
	UPACK32(padr->sin_addr.s_addr, head->dadr);
	memcpy(&(conn->head), head, hlen);
	copy(conn->adrs[0], inet_ntoa(conn->addr[0].sin_addr), ILEN, LINE);
	copy(conn->adrs[1], inet_ntoa(conn->addr[1].sin_addr), ILEN, LINE);
	conn->cryp[0].q = skey;
	conn->cryp[1].q = skey;
	conn->lock[0] = zero;
	conn->lock[1] = zero;
	conn->last = secs;
	conn->midx = tidx;
	conn->indx = indx;
	conn->tidx = tidx;
	conn->sock = sock;
	conn->rpwp = rpwp;
	conn->stat = good;
	proc->indx = indx;
	proc->tidx = tidx;
	proc->sock = csoc;
	proc->cons = conn;
	proc->stat = good;
	return fdes;
}
