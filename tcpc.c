
void *tcpc_recv(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int *csoc = argp->csoc;
	int *esoc = argp->esoc;
	int *rsoc = argp->rsoc;

	int sock, sprt, cprt, olen;
	int leng, size, fdes, fmax;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int maxl = (BTCP + HEDL);
	unsigned char temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	struct sockaddr_in addr;
	struct sockaddr_in *padr, *cadr;
	struct timeval tval;
	fd_set rfds;

	buff_o buff[2];
	pckt_h pobj[2];
	ciph_o cobj[2];
	pckt_h *head;
	ciph_o *cryp;

	for (int x = 0; x < 2; ++x) {
		bzero(&(buff[x]), sizeof(buff_o));
		bzero(&(pobj[x]), sizeof(pckt_h));
		bzero(&(cobj[x]), sizeof(ciph_o));
		cobj[x].q = args->skey;
	}

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
			printf("[%s] warn tcpc_recv socs [%d][%d]\n", gett(), *esoc, *rsoc);
			usleep(500000);
			continue;
		}
		fmax = (maxs(buff[0].sock, buff[1].sock) + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro tcpc_recv sels [%d]\n", gett(), erro);
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
					if (size < 0) { printf("[%s] warn tcpc_recv size [%d] [%d][%d]\n", gett(), x, size, buff[x].sock); }
					if (x == 0) { fins(argp->esoc, 1); }
					else { fins(argp->rsoc, 1); }
					continue;
				}
				cryp = &(cobj[x]);
				size = buff[x].size;
				pntr = buff[x].buff;
				erro = wrap(cryp, temp, maxl, pntr, size, 'd');
				if (erro > 0) { pntr = temp; size = erro; }
				if (erro < 0) {
					printf("[%s] warn tcpc_recv ciph [%d]\n", gett(), erro);
					continue;
				}
				head = &(pobj[x]);
				bcopy(pntr, head, hlen);
				UPACK16(leng, head->leng); olen = leng;
				leng -= hlen; pntr += hlen;
				if ((olen != 31337) && ((leng < 1) || (BTCP < leng))) {
					printf("[%s] warn tcpc_recv head [%d]\n", gett(), leng);
					continue;
				}
				padr = &(addr);
				UPACK16(sprt, head->sprt);
				UPACK32(padr->sin_addr.s_addr, head->sadr);
				for (int cidx = 0; cidx < NUMC; ++cidx) {
					sock = csoc[cidx];
					cprt = cons[cidx].port[0];
					cadr = &(cons[cidx].addr[0]);
					if ((cprt > 0) && (cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
						if (olen == 31337) {
							cons[cidx].stat = 9;
							fins(&(csoc[cidx]), 1);
						} else {
							erro = senz(sock, pntr, leng);
							cons[cidx].last = secs;
							if ((secs - cons[cidx].lock[1]) > 1) {
								printf("[%s] info tcpc_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
								cons[cidx].lock[1] = secs;
							}
						}
					}
				}
			}
		}
	}

	fins(argp->esoc, 1);
	fins(argp->rsoc, 1);
	argp->stat = -1;

	printf("[%s] info tcpc_recv fins [%d]\n", gett(), stat);

	return NULL;
}

void *tcpc_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;

	int leng, size, csoc, dsoc, midx, fdes, fmax;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int maxl = (BTCP + HEDL);
	char *prot = "tcp";
	unsigned char temp[BMAX], data[BMAX];
	unsigned char *pntr;
	time_t secs;
	struct timeval tval;
	fd_set rfds;

	pckt_h pobj;
	ciph_o cobj;
	pckt_h *head = &(pobj);
	ciph_o *cryp = &(cobj);

	bzero(head, sizeof(pckt_h));
	bzero(cryp, sizeof(ciph_o));
	copy(cons->adrs[0], inet_ntoa(cons->addr[0].sin_addr), ILEN, LINE);
	cons->port[0] = ntohs(cons->addr[0].sin_port);
	bzero(cons->adrs[1], LINE);
	if (args->dest == NULL) {
		comd(cons->adrs[1], &(cons->port[1]), ILEN, args->comd, prot, cons->adrs[0], cons->port[0]);
	} else {
		strncpy(cons->adrs[1], args->dest, ILEN); cons->port[1] = args->dprt;
	}
	if (cons->adrs[1][0] != 0) {
		if (isin(argp->nots, cons->adrs[1]) == 1) {
			cons->midx = 0;
			cons->sock = &(argp->esoc[argp->indx]);
		} else {
			cons->midx = 1;
			cons->sock = &(argp->rsoc[argp->indx]);
		}
		cons->addr[1].sin_addr.s_addr = inet_addr(cons->adrs[1]);
		cons->addr[1].sin_port = htons(cons->port[0]);
		head->prot = 1; head->kind = 1;
		PACKU32(head->sadr, cons->addr[0].sin_addr.s_addr); PACKU16(head->sprt, cons->port[0]);
		PACKU32(head->dadr, cons->addr[1].sin_addr.s_addr); PACKU16(head->dprt, cons->port[1]);
	} else {
		printf("[%s] erro tcpc_send comd [%s:%d]\n", gett(), cons->adrs[0], cons->port[0]);
		stat = -1;
	}

	cryp->q = args->skey;
	while (stat == 1) {
		FD_ZERO(&(rfds));
		fdes = *(argp->csoc);
		if (fdes < 0) {
			stat = -2; break;
		} else {
			csoc = fdes;
		}
		FD_SET(csoc, &(rfds));
		fmax = (csoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro tcpc_send sels [%d]\n", gett(), erro);
			stat = -3; break;
		}
		if ((argp->stat != 1) || (cons->stat != 1)) {
			stat = -8; break;
		}
		secs = time(NULL);
		if (FD_ISSET(csoc, &(rfds))) {
			dsoc = *(cons->sock);
			if (dsoc < 1) {
				printf("[%s] warn tcpc_send conn [%d]\n", gett(), dsoc);
			} else {
				leng = read(csoc, temp, BTCP);
				if (leng < 1) { stat = -4; break; }
				midx = cons->midx;
				size = (hlen + leng);
				PACKU16(head->leng, size);
				bcopy(head, data, hlen); pntr = (data + hlen);
				bcopy(temp, pntr, leng); pntr = data;
				erro = wrap(cryp, temp, maxl, data, size, 'e');
				if (erro > 0) { pntr = temp; size = erro; }
				if (erro < 0) { printf("[%s] warn tcpc_send ciph [%d]\n", gett(), erro); }
				erro = sent(dsoc, pntr, size, midx);
				if (erro < 1) { printf("[%s] warn tcpc_send sent [%d]\n", gett(), erro); }
				cons->last = secs;
				if ((secs - cons->lock[0]) > 1) {
					printf("[%s] info tcpc_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], -1, size);
					cons->lock[0] = secs;
				}
			}
		}
		if ((secs - cons->last) >= EXPC) {
			stat = -5; break;
		}
	}

	midx = cons->midx;
	dsoc = *(cons->sock);
	size = (hlen + 1);
	PACKU16(head->leng, 31337);
	bcopy(head, data, hlen); pntr = data;
	erro = wrap(cryp, temp, maxl, data, size, 'e');
	if (erro > 0) { pntr = temp; size = erro; }
	if (erro < 0) { printf("[%s] warn tcpc_send ciph [%d]\n", gett(), erro); }
	erro = sent(dsoc, pntr, size, midx);

	fins(argp->csoc, 1);
	cons->stat = -1;
	argp->stat = -1;

	printf("[%s] info tcpc_send fins [%d]\n", gett(), stat);

	return NULL;
}

void tcpc_serv(args_o *args) {
	int indx, tidx, fdes, fmax;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int elen = sizeof(struct sockaddr_in);
	int rlen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], esoc[NUMC], rsoc[NUMC];
	char *adrs = "127.0.0.1";
	struct sockaddr_in ladr, eadr, radr;
	struct sockaddr_in *padr;
	struct timeval tval;
	time_t secs, last;
	fd_set rfds;

	cons_l *cons = malloc(NUMC * sizeof(cons_l));
	inet_l *nots = malloc(LIST * sizeof(inet_l));
	thro_o thrr[NUMC], thrs[NUMC];

	srand(time(NULL));

	padr = &(ladr);
	bzero(padr, llen);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(args->lprt);
	padr->sin_addr.s_addr = inet_addr(args->ladr);
	lsoc = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(lsoc, SOL_SOCKET, SO_REUSEADDR, (const char *)&reus, sizeof(reus));
	setsockopt(lsoc, SOL_SOCKET, SO_REUSEPORT, (const char *)&reus, sizeof(reus));
	bind(lsoc, (struct sockaddr *)padr, llen);
	listen(lsoc, LSTN);

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

	bzero(csoc, NUMC * sizeof(int));
	bzero(esoc, NUMC * sizeof(int));
	bzero(rsoc, NUMC * sizeof(int));
	bzero(thrs, NUMC * sizeof(thro_o));
	bzero(thrr, NUMC * sizeof(thro_o));
	bzero(cons, NUMC * sizeof(cons_l));
	bzero(nots, LIST * sizeof(inet_l));
	load(nots, args->nots);
	for (int x = 0; x < NUMC; ++x) {
		thrs[x].args = args; thrs[x].cons = &(cons[x]); thrs[x].nots = nots;
		thrs[x].lsoc = &(lsoc); thrs[x].csoc = &(csoc[x]);
		thrs[x].esoc = esoc; thrs[x].rsoc = rsoc;
		thrr[x].args = args; thrr[x].cons = cons;
		thrr[x].lsoc = &(lsoc); thrr[x].csoc = csoc;
		thrr[x].esoc = &(esoc[x]); thrr[x].rsoc = &(rsoc[x]);
	}

	tidx = 0;
	last = 0;
	thrr[tidx].stat = 1;
	thrr[tidx].indx = tidx;
	pthread_create(&(thrr[tidx].thro), NULL, tcpc_recv, &(thrr[tidx]));
	while (stat == 1) {
		secs = time(NULL);
		if ((secs - last) >= 5) {
			if (args->nots != NULL) {
				if (esoc[tidx] < 1) {
					if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
						printf("[%s] warn tcpc_recv sock locl\n", gett()); close(fdes);
					} else if ((erro = connect(fdes, (struct sockaddr *)&(eadr), elen)) != 0) {
						printf("[%s] warn tcpc_recv conn locl\n", gett()); close(fdes);
					} else { esoc[tidx] = fdes; }
				}
			}
			if (rsoc[tidx] < 1) {
				if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
					printf("[%s] warn tcpc_recv sock remo\n", gett()); close(fdes);
				} else if ((erro = connect(fdes, (struct sockaddr *)&(radr), rlen)) != 0) {
					printf("[%s] warn tcpc_recv conn remo\n", gett()); close(fdes);
				} else { rsoc[tidx] = fdes; }
			}
			last = secs;
		}
		indx = -1;
		for (int x = 0; x < NUMC; ++x) {
			if (csoc[x] < 0) {
				if (thrs[x].stat == 1) {
					thrs[x].stat = 2;
				} else if (thrs[x].stat == -1) {
					pthread_join(thrs[x].thro, NULL);
					thrs[x].stat = 0;
				}
			}
			if (thrs[x].stat == 0) {
				bzero(&(thrs[x].thro), sizeof(pthread_t));
				bzero(&(cons[x]), sizeof(cons_l));
				csoc[x] = 0;
				indx = x;
			}
		}
		FD_ZERO(&(rfds));
		FD_SET(lsoc, &(rfds));
		fmax = (lsoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro tcpc_serv sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		if (FD_ISSET(lsoc, &(rfds))) {
			if ((indx < 0) || (csoc[indx] != 0)) {
				printf("[%s] warn tcpc_serv indx [%d]\n", gett(), indx);
				usleep(500000);
				continue;
			}
			slen = sizeof(struct sockaddr_in);
			padr = &(cons[indx].addr[0]);
			fdes = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (fdes < 1) {
				printf("[%s] erro tcpc_serv conn [%d]\n", gett(), fdes);
				stat = 0; break;
			}
			csoc[indx] = fdes;
			thrs[indx].indx = tidx;
			thrs[indx].stat = 1;
			cons[indx].stat = 1;
			pthread_create(&(thrs[indx].thro), NULL, tcpc_send, &(thrs[indx]));
		}
	}

	free(nots);
	free(cons);
}
