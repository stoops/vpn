
void *tcpc_recv(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int *csoc = argp->csoc;

	int sock, sprt, cprt;
	int leng, size, fdes, fmax;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
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
		buff[x].pbuf = buff[x].buff;
		cobj[x].q = args->skey;
	}

	while (stat == 1) {
		FD_ZERO(&(rfds));
		fdes = *(argp->esoc);
		if (fdes < 1) { fdes = 0; }
		else { FD_SET(fdes, &(rfds)); }
		buff[0].sock = fdes;
		fdes = *(argp->rsoc);
		if (fdes < 1) { fdes = 0; }
		else { FD_SET(fdes, &(rfds)); }
		buff[1].sock = fdes;
		fmax = (maxs(buff[0].sock, buff[1].sock) + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if (buff[1].sock < 1) {
			printf("[%s] warn tcpc_recv sock\n", gett());
			usleep(500000);
			continue;
		}
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro tcpc_recv sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		secs = time(NULL);
		for (int x = 0; x < 2; ++x) {
			if ((buff[x].sock > 0) && (FD_ISSET(buff[x].sock, &(rfds)))) {
				size = recw(&(buff[x]));
				if (size < 1) {
					printf("[%s] warn tcpc_recv size [%d] [%d] [%d]\n", gett(), x, size, buff[x].sock);
					buff[x].sock = -9;
				} else if ((buff[x].leng > 0) && (buff[x].leng == buff[x].size)) {
					cryp = &(cobj[x]);
					size = buff[x].size;
					pntr = buff[x].buff;
					erro = wrap(cryp, temp, BMAX, pntr, size, 'd');
					if (erro > 0) { pntr = temp; size = erro; }
					if (erro < 0) { printf("[%s] warn tcpc_recv ciph [%d]\n", gett(), erro); }
					else {
						head = &(pobj[x]);
						bcopy(pntr, head, hlen);
						UPACK16(leng, head->leng);
						leng -= hlen; pntr += hlen;
						if ((leng < 1) || (BTCP < leng)) { printf("[%s] warn tcpc_recv head [%d]\n", gett(), leng); }
						else {
							padr = &(addr);
							UPACK16(sprt, head->sprt);
							UPACK32(padr->sin_addr.s_addr, head->sadr);
							for (int cidx = 0; cidx < NUMC; ++cidx) {
								sock = csoc[cidx];
								cprt = cons[cidx].port[0];
								cadr = &(cons[cidx].addr[0]);
								if ((cprt > 0) && (cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
									erro = senz(sock, pntr, leng);
									cons[cidx].last = secs;
									if ((secs - cons[cidx].lock[1]) > 1) {
										printf("[%s] tcpc_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
										cons[cidx].lock[1] = secs;
									}
								}
							}
						}
					}
					buff[x].leng = 0; buff[x].size = 0;
					buff[x].pbuf = buff[x].buff;
				}
			}
			if (buff[x].sock == -9) {
				if (x == 0) { fins(argp->esoc, 1); }
				else { fins(argp->rsoc, 1); }
				buff[x].leng = 0; buff[x].size = 0;
				buff[x].pbuf = buff[x].buff;
			}
		}
	}

	fins(argp->esoc, 1);
	fins(argp->rsoc, 1);

	printf("[%s] tcpc_recv fins\n", gett());

	return NULL;
}

void *tcpc_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;

	int leng, size, csoc, dsoc, midx, fdes, fmax;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
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
	comd(cons->adrs[1], &(cons->port[1]), ILEN, args->comd, prot, cons->adrs[0], cons->port[0]);
	if (cons->adrs[1][0] != 0) {
		if (isin(argp->nots, cons->adrs[1]) == 1) {
			cons->midx = 0;
			cons->sock = argp->esoc;
		} else {
			cons->midx = 1;
			cons->sock = argp->rsoc;
		}
		cons->addr[1].sin_addr.s_addr = inet_addr(cons->adrs[1]);
		cons->addr[1].sin_port = htons(cons->port[0]);
		head->prot = 1; head->kind = 1;
		PACKU32(head->sadr, cons->addr[0].sin_addr.s_addr); PACKU16(head->sprt, cons->port[0]);
		PACKU32(head->dadr, cons->addr[1].sin_addr.s_addr); PACKU16(head->dprt, cons->port[1]);
	} else {
		printf("[%s] erro tcpc_send comd [%s:%d]\n", gett(), cons->adrs[0], cons->port[0]);
		stat = 0;
	}

	cryp->q = args->skey;
	while (stat == 1) {
		FD_ZERO(&(rfds));
		fdes = *(argp->csoc);
		if (fdes < 0) { fdes = 0; stat = 0; break; }
		csoc = fdes;
		FD_SET(csoc, &(rfds));
		fmax = (csoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro tcpc_send sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		secs = time(NULL);
		if (FD_ISSET(csoc, &(rfds))) {
			leng = read(csoc, temp, BTCP);
			if (leng < 1) { stat = 0; break; }
			midx = cons->midx;
			dsoc = *(cons->sock);
			size = (hlen + leng);
			PACKU16(head->leng, size);
			bcopy(head, data, hlen); pntr = (data + hlen);
			bcopy(temp, pntr, leng); pntr = data;
			erro = wrap(cryp, temp, BMAX, data, size, 'e');
			if (erro > 0) { pntr = temp; size = erro; }
			if (erro < 0) { printf("[%s] warn tcpc_send ciph [%d]\n", gett(), erro); }
			erro = sent(dsoc, pntr, size, midx);
			if (erro < 1) { printf("[%s] warn tcpc_send sent [%d]\n", gett(), erro); }
			cons->last = secs;
			if ((secs - cons->lock[0]) > 1) {
				printf("[%s] tcpc_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], -1, size);
				cons->lock[0] = secs;
			}
		}
		if ((secs - cons->last) >= EXPC) {
			stat = 0; break;
		}
	}

	midx = cons->midx;
	dsoc = *(cons->sock);
	size = (hlen + 1);
	PACKU16(head->leng, 31337);
	bcopy(head, data, hlen); pntr = data;
	erro = wrap(cryp, temp, BMAX, data, size, 'e');
	if (erro > 0) { pntr = temp; size = erro; }
	if (erro < 0) { printf("[%s] warn tcpc_send ciph [%d]\n", gett(), erro); }
	erro = sent(dsoc, pntr, size, midx);

	fins(argp->csoc, 1);

	printf("[%s] tcpc_send fins\n", gett());

	return NULL;
}

void tcpc_serv(args_o *args) {
	int indx, fdes, fmax;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1, esoc = -1, rsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int elen = sizeof(struct sockaddr_in);
	int rlen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC];
	char *adrs = "127.0.0.1";
	struct sockaddr_in ladr, eadr, radr;
	struct sockaddr_in *padr;
	struct timeval tval;
	fd_set rfds;

	cons_l *cons = malloc(NUMC * sizeof(cons_l));
	inet_l *nots = malloc(LIST * sizeof(inet_l));
	thro_o thro, thrl[NUMC];

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

	bzero(&(thro), sizeof(thro_o));
	bzero(csoc, NUMC * sizeof(int));
	bzero(thrl, NUMC * sizeof(thro_o));
	bzero(cons, NUMC * sizeof(cons_l));
	bzero(nots, LIST * sizeof(inet_l));
	load(nots, args->nots);
	for (int x = 0; x < NUMC; ++x) {
		thrl[x].args = args; thrl[x].cons = &(cons[x]); thrl[x].nots = nots;
		thrl[x].lsoc = &(lsoc); thrl[x].csoc = &(csoc[x]);
		thrl[x].esoc = &(esoc); thrl[x].rsoc = &(rsoc);
	}
	thro.args = args; thro.cons = cons;
	thro.lsoc = &(lsoc); thro.csoc = csoc;
	thro.esoc = &(esoc); thro.rsoc = &(rsoc);

	indx = 0;
	pthread_create(&(thro.thro), NULL, tcpc_recv, &(thro));
	while (stat == 1) {
		if ((args->nots != NULL) && (esoc < 0)) {
			if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				printf("[%s] warn tcpc_serv sock locl\n", gett()); close(fdes);
			} else if ((erro = connect(fdes, (struct sockaddr *)&(eadr), elen)) != 0) {
				printf("[%s] warn tcpc_serv conn locl\n", gett()); close(fdes);
			} else { esoc = fdes; }
		}
		if (rsoc < 0) {
			if ((fdes = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				printf("[%s] warn tcpc_serv sock remo\n", gett()); close(fdes);
			} else if ((erro = connect(fdes, (struct sockaddr *)&(radr), rlen)) != 0) {
				printf("[%s] warn tcpc_serv conn remo\n", gett()); close(fdes);
			} else { rsoc = fdes; }
		}
		if (rsoc < 0) {
			printf("[%s] warn tcpc_serv sock\n", gett());
			usleep(500000);
			continue;
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
			indx = ((indx + 1) % NUMC);
			if (csoc[indx] < 0) {
				pthread_join(thrl[indx].thro, NULL);
				bzero(&(thrl[indx].thro), sizeof(pthread_t));
				bzero(&(cons[indx]), sizeof(cons_l));
				csoc[indx] = 0;
			}
			if (csoc[indx] != 0) {
				printf("[%s] warn tcpc_serv indx [%d]\n", gett(), indx);
				usleep(500000);
				continue;
			}
			padr = &(cons[indx].addr[0]);
			erro = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (erro < 1) {
				printf("[%s] erro tcpc_serv conn [%d]\n", gett(), erro);
				stat = 0; break;
			}
			csoc[indx] = erro;
			pthread_create(&(thrl[indx].thro), NULL, tcpc_send, &(thrl[indx]));
		}
	}

	free(nots);
	free(cons);
}
