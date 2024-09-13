
void *udpc_recv(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int *esoc = argp->esoc;
	int *rsoc = argp->rsoc;

	int erro = 1, stat = 1;
	int lsoc = *(argp->lsoc);
	int hlen = sizeof(pckt_h);
	int slen = sizeof(struct sockaddr_in);
	int leng, size, fdes, fmax, sprt, cprt;
	unsigned char temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	fd_set rfds;
	struct timeval tval;
	struct sockaddr_in addr;
	struct sockaddr_in *padr, *cadr;

	buff_o buff[2];
	pckt_h pobj;
	ciph_o cobj;
	pckt_h *head = &(pobj);
	ciph_o *cryp = &(cobj);

	bzero(buff, 2 * sizeof(buff_o));
	cryp->q = args->skey;

	while (stat == 1) {
		FD_ZERO(&(rfds));
		fdes = *(esoc);
		buff[0].sock = 0;
		if (args->nots != NULL) {
			if (fdes > 0) {
				buff[0].sock = fdes;
				FD_SET(fdes, &(rfds));
			}
		}
		fdes = *(rsoc);
		buff[1].sock = 0;
		if (fdes > 0) {
			buff[1].sock = fdes;
			FD_SET(fdes, &(rfds));
		}
		if ((buff[0].sock == 0) && (buff[1].sock == 0)) {
			printf("[%s] warn udpc_recv socs [%d][%d]\n", gett(), *esoc, *rsoc);
			usleep(500000);
			continue;
		}
		fmax = (maxs(buff[0].sock, buff[1].sock) + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro udpc_recv sels [%d]\n", gett(), erro);
			stat = -1; break;
		}
		if (argp->stat != 1) {
			stat = -8; break;
		}
		secs = time(NULL);
		for (int x = 0; x < 2; ++x) {
			if ((buff[x].sock > 0) && (FD_ISSET(buff[x].sock, &(rfds)))) {
				size = recw(&(buff[x]));
				if (size < 1) {
					if (size < 0) { printf("[%s] warn udpc_recv size [%d] [%d] [%d]\n", gett(), x, size, buff[x].sock); }
					if (x == 0) { fins(argp->esoc, 1); }
					else { fins(argp->rsoc, 1); }
					continue;
				}
				size = buff[x].size;
				pntr = buff[x].buff;
				erro = wrap(cryp, temp, BMAX, pntr, size, 'd');
				if (erro > 0) { pntr = temp; size = erro; }
				if (erro < 0) {
					printf("[%s] warn udpc_recv ciph [%d]\n", gett(), erro);
					continue;
				}
				bcopy(pntr, head, hlen);
				UPACK16(leng, head->leng);
				leng -= hlen; pntr += hlen;
				if ((leng < 1) || (BTCP < leng)) {
					printf("[%s] warn udpc_recv head [%d]\n", gett(), leng);
					continue;
				}
				padr = &(addr);
				UPACK16(sprt, head->sprt);
				UPACK32(padr->sin_addr.s_addr, head->sadr);
				for (int cidx = 0; cidx < NUMC; ++cidx) {
					cprt = cons[cidx].port[0];
					cadr = &(cons[cidx].addr[0]);
					if ((cprt > 0) && (cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
						erro = sendto(lsoc, pntr, leng, 0, (struct sockaddr *)cadr, slen);
						cons[cidx].last = secs;
						if ((secs - cons[cidx].lock[1]) > 1) {
							printf("[%s] info udpc_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
							cons[cidx].lock[1] = secs;
						}
					}
				}
			}
		}
	}

	fins(argp->esoc, 1);
	fins(argp->rsoc, 1);
	argp->stat = -1;

	printf("[%s] info udpc_recv fins [%d]\n", gett(), stat);

	return NULL;
}

void *udpc_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	bufs_l *bufs = argp->bufs;
	cons_l *cons = argp->cons;

	int erro = 1, stat = 1;
	int indx, leng, size, cidx, fidx, midx, sock;
	int llen = sizeof(struct sockaddr_in);
	int hlen = sizeof(pckt_h);
	char *prot = "udp";
	unsigned char data[BMAX], temp[BMAX], ssiz[LINE];
	unsigned char *pntr;
	time_t secs;
	struct sockaddr_in *padr, *cadr;

	pckt_h *head;
	ciph_o *cryp;

	while (stat == 1) {
		ssiz[0] = 0; ssiz[1] = 0;
		leng = read(argp->rpwp[0], ssiz, 2);
		if (leng != 2) {
			printf("[%s] erro udpc_send pipe [%d] [%d]\n", gett(), leng, argp->rpwp[0]);
			stat = -1; break;
		}
		if (argp->stat != 1) {
			stat = -8; break;
		}
		UPACK16(indx, ssiz);
		if ((indx < 0) || (NUMC < indx)) {
			printf("[%s] erro udpc_send indx [%d]\n", gett(), indx);
			stat = -2; break;
		}
		padr = &(bufs[indx].addr);
		cidx = -1; fidx = -1;
		secs = time(NULL);
		for (int x = 0; x < NUMC; ++x) {
			cadr = &(cons[x].addr[0]);
			if ((cons[x].stat != 0) && ((secs - cons[x].last) >= EXPC)) {
				printf("[%s] info udpc_send fins [%d] [%s:%d]\n", gett(), x, cons[x].adrs[0], cons[x].port[0]);
				bzero(&(cons[x]), sizeof(cons_l));
			}
			if (cons[x].stat == 0) {
				fidx = x;
			}
			if ((cons[x].port[0] == bufs[indx].port) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
				cidx = x; break;
			}
		}
		if ((cidx < 0) && (fidx > -1)) {
			bzero(cons[fidx].adrs[1], LINE);
			if (args->dest == NULL) {
				comd(cons[fidx].adrs[1], &(cons[fidx].port[1]), ILEN, args->comd, prot, bufs[indx].adrs, bufs[indx].port);
			} else {
				strncpy(cons[fidx].adrs[1], args->dest, ILEN); cons[fidx].port[1] = args->dprt;
			}
			if (cons[fidx].adrs[1][0] != 0) {
				if (isin(argp->nots, cons[fidx].adrs[1]) == 1) {
					cons[fidx].midx = 0;
					cons[fidx].sock = argp->esoc;
				} else {
					cons[fidx].midx = 1;
					cons[fidx].sock = argp->rsoc;
				}
				cons[fidx].port[0] = bufs[indx].port;
				copy(cons[fidx].adrs[0], bufs[indx].adrs, ILEN, LINE);
				memcpy(&(cons[fidx].addr[0]), padr, llen);
				cons[fidx].addr[1].sin_family = AF_INET;
				cons[fidx].addr[1].sin_port = htons(cons[fidx].port[1]);
				cons[fidx].addr[1].sin_addr.s_addr = inet_addr(cons[fidx].adrs[1]);
				cons[fidx].cryp[0].q = args->skey;
				cons[fidx].cryp[1].q = args->skey;
				cons[fidx].buff = bufs[indx].buff;
				cons[fidx].leng = bufs[indx].leng;
				cons[fidx].lock[0] = 0;
				cons[fidx].lock[1] = 0;
				cons[fidx].stat = 1;
				head = &(cons[fidx].head);
				head->prot = 1; head->kind = 1;
				PACKU32(head->sadr, cons[fidx].addr[0].sin_addr.s_addr); PACKU16(head->sprt, cons[fidx].port[0]);
				PACKU32(head->dadr, cons[fidx].addr[1].sin_addr.s_addr); PACKU16(head->dprt, cons[fidx].port[1]);
				cidx = fidx;
			} else {
				printf("[%s] warn udpc_send comd [%s:%d]\n", gett(), bufs[indx].adrs, bufs[indx].port);
				cidx = -1;
			}
		}
		if ((cidx < 0) || (cons[cidx].stat < 1)) {
			printf("[%s] warn udpc_send indx [%d]\n", gett(), cidx);
		} else {
			sock = *(cons[cidx].sock);
			if (sock < 1) {
				printf("[%s] warn udpc_send conn [%d]\n", gett(), sock);
			} else {
				midx = cons[fidx].midx;
				head = &(cons[cidx].head);
				cryp = &(cons[cidx].cryp[0]);
				leng = cons[cidx].leng; size = (hlen + leng);
				PACKU16(head->leng, size);
				bcopy(head, data, hlen); pntr = (data + hlen);
				bcopy(cons[cidx].buff, pntr, leng); pntr = data;
				erro = wrap(cryp, temp, BMAX, data, size, 'e');
				if (erro > 0) { pntr = temp; size = erro; }
				if (erro < 0) { printf("[%s] warn udpc_send ciph [%d]\n", gett(), erro); }
				erro = sent(sock, pntr, size, midx);
				if (erro < 1) { printf("[%s] warn udpc_send sent [%d]\n", gett(), erro); }
				cons[cidx].last = secs;
				if ((secs - cons[cidx].lock[0]) > 1) {
					printf("[%s] info udpc_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, size);
					cons[cidx].lock[0] = secs;
				}
			}
		}
		bufs[indx].stat = 0;
	}

	argp->stat = -1;

	printf("[%s] info udpc_send fins [%d]\n", gett(), stat);

	return NULL;
}

void udpc_serv(args_o *args) {
	int indx, fdes, fmax;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1, esoc = -1, rsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int elen = sizeof(struct sockaddr_in);
	int rlen = sizeof(struct sockaddr_in);
	int rpwp[2];
	int *plen, *pnum;
	char *pntr;
	char *adrs = "127.0.0.1";
	unsigned char ssiz[LINE];
	unsigned char *pbuf;
	struct sockaddr_in ladr, eadr, radr;
	struct sockaddr_in *padr;
	struct timeval tval;
	fd_set rfds;
	time_t secs, last;
	pthread_t thrs, thrr;

	bufs_l *bufs = malloc(NUMC * sizeof(bufs_l));
	cons_l *cons = malloc(NUMC * sizeof(cons_l));
	inet_l *nots = malloc(LIST * sizeof(inet_l));
	thro_o thro;

	srand(time(NULL));

	padr = &(ladr);
	bzero(padr, llen);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(args->lprt);
	padr->sin_addr.s_addr = inet_addr(args->ladr);
	lsoc = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(lsoc, SOL_SOCKET, SO_REUSEADDR, (const char *)&reus, sizeof(reus));
	setsockopt(lsoc, SOL_SOCKET, SO_REUSEPORT, (const char *)&reus, sizeof(reus));
	bind(lsoc, (struct sockaddr *)padr, llen);

	padr = &(eadr);
	bzero(padr, elen);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(args->rprt);
	padr->sin_addr.s_addr = inet_addr(adrs);

	padr = &(radr);
	bzero(padr, rlen);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(args->rprt);
	padr->sin_addr.s_addr = inet_addr(args->radr);

	bzero(bufs, NUMC * sizeof(bufs_l));
	bzero(cons, NUMC * sizeof(cons_l));
	bzero(nots, LIST * sizeof(inet_l));
	load(nots, args->nots);
	socketpair(AF_UNIX, SOCK_STREAM, 0, rpwp);

	thro.rpwp = rpwp; thro.nots = nots;
	thro.args = args; thro.bufs = bufs; thro.cons = cons;
	thro.lsoc = &(lsoc); thro.esoc = &(esoc); thro.rsoc = &(rsoc);

	indx = 0;
	last = 0;
	thro.stat = 1;
	pthread_create(&(thrs), NULL, udpc_send, &(thro));
	pthread_create(&(thrr), NULL, udpc_recv, &(thro));
	while (stat == 1) {
		secs = time(NULL);
		if ((secs - last) >= 5) {
			if (args->nots != NULL) {
				if (esoc < 1) {
					if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
						printf("[%s] warn udpc_recv sock locl\n", gett()); close(fdes);
					} else if ((erro = connect(fdes, (struct sockaddr *)&(eadr), elen)) != 0) {
						printf("[%s] warn udpc_recv conn locl\n", gett()); close(fdes);
					} else { esoc = fdes; }
				}
			}
			if (rsoc < 1) {
				if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
					printf("[%s] warn udpc_recv sock remo\n", gett()); close(fdes);
				} else if ((erro = connect(fdes, (struct sockaddr *)&(radr), rlen)) != 0) {
					printf("[%s] warn udpc_recv conn remo\n", gett()); close(fdes);
				} else { rsoc = fdes; }
			}
			last = secs;
		}
		FD_ZERO(&(rfds));
		FD_SET(lsoc, &(rfds));
		fmax = (lsoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro udpc_serv sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		if (FD_ISSET(lsoc, &(rfds))) {
			indx = ((indx + 1) % NUMC);
			if (bufs[indx].stat != 0) {
				printf("[%s] warn udpc_serv indx\n", gett());
				usleep(500000);
				continue;
			}
			llen = sizeof(struct sockaddr_in);
			pntr = bufs[indx].adrs;
			pbuf = bufs[indx].buff;
			pnum = &(bufs[indx].port);
			padr = &(bufs[indx].addr);
			plen = &(bufs[indx].leng);
			*plen = recvfrom(lsoc, pbuf, BUDP, 0, (struct sockaddr *)padr, (unsigned int *)&(llen));
			if (*plen < BONE) {
				printf("[%s] erro udpc_serv leng\n", gett());
				stat = 0; break;
			}
			bufs[indx].last = time(NULL);
			bufs[indx].stat = 1;
			copy(pntr, inet_ntoa(padr->sin_addr), ILEN, LINE);
			*pnum = ntohs(padr->sin_port);
			PACKU16(ssiz, indx);
			erro = write(rpwp[1], ssiz, 2);
			if (erro < 1) {
				printf("[%s] erro udpc_serv pipe\n", gett());
				stat = 0; break;
			}
		}
	}

	fins(&(rpwp[1]), 0);
	fins(&(rpwp[0]), 0);

	free(nots);
	free(cons);
	free(bufs);
}
