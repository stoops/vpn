
void *tcpc_recv(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int *csoc = argp->csoc;
	int *esoc = argp->esoc;
	int *rsoc = argp->rsoc;

	int sock, sprt, cprt, olen;
	int leng, size, fdes, flag;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int maxl = (BTCP + HEDL);
	unsigned char temp[BMAX];
	unsigned char *pntr;
	time_t secs, lock;
	struct sockaddr_in addr;
	struct sockaddr_in *padr, *cadr;
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

	lock = 0;
	while (stat == 1) {
		fdes = *(esoc);
		buff[0].sock = 0;
		if (args->nots != NULL) {
			if (fdes > 0) {
				buff[0].sock = fdes;
			}
		}
		fdes = *(rsoc);
		buff[1].sock = 0;
		if (fdes > 0) {
			buff[1].sock = fdes;
		}
		if ((buff[0].sock == 0) && (buff[1].sock == 0)) {
			printf("[%s] warn tcpc_recv socs [%d][%d]\n", gett(), *esoc, *rsoc);
			if (args->conz == 1) { stat = -9; break; }
			usleep(USLA);
			continue;
		}
		if (argp->stat != 1) {
			stat = -2; break;
		}
		if ((erro = sels(&(rfds), buff[0].sock, buff[1].sock)) < 0) {
			printf("[%s] erro tcpc_recv sels [%d]\n", gett(), erro);
			stat = -3; break;
		}
		secs = time(NULL);
		for (int x = 0; x < 2; ++x) {
			if ((buff[x].sock > 0) && (FD_ISSET(buff[x].sock, &(rfds)))) {
				flag = 0;
				head = &(pobj[x]);
				cryp = &(cobj[x]);
				size = recw(&(buff[x]));
				if (size < 1) {
					if (args->conz != 1) {
						printf("[%s] warn tcpc_recv recw [%d] [%d] [%d]\n", gett(), x, size, buff[x].sock);
					}
					if (args->conz == 1) { stat = -4; break; }
					flag = 1;
				}
				if (flag == 0) {
					size = buff[x].size;
					pntr = buff[x].buff;
					erro = wrap(cryp, temp, maxl, pntr, size, 'd');
					if (erro > 0) { pntr = temp; size = erro; }
					if (erro < 0) {
						printf("[%s] warn tcpc_recv ciph [%d]\n", gett(), erro);
						if (args->conz == 1) { stat = -9; break; }
						flag = 1;
					}
				}
				if (flag == 0) {
					bcopy(pntr, head, hlen);
					UPACK16(leng, head->leng); olen = leng;
					leng -= hlen; pntr += hlen;
					if ((olen != ENDL) && ((leng < BONE) || (BTCP < leng))) {
						printf("[%s] warn tcpc_recv head [%d]\n", gett(), leng);
						if (args->conz == 1) { stat = -9; break; }
						flag = 1;
					}
				}
				if (flag == 0) {
					padr = &(addr);
					UPACK16(sprt, head->sprt);
					UPACK32(padr->sin_addr.s_addr, head->sadr);
					int indx = -1;
					for (int cidx = 0; cidx < NUMC; ++cidx) {
						sock = csoc[cidx];
						cprt = cons[cidx].port[0];
						cadr = &(cons[cidx].addr[0]);
						if (cons[cidx].stat == 0) {
							/* no-op */
						} else if (cons[cidx].stat == 1) {
							if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
								if (olen == ENDL) {
									cons[cidx].stat = 6;
									if (args->conz == 1) { stat = -6; break; }
								} else {
									erro = senz(sock, pntr, leng);
									if (erro < 1) { printf("[%s] warn tcpc_recv senz [%d]\n", gett(), erro); }
									cons[cidx].last = secs;
									if ((secs - cons[cidx].lock[1]) > 1) {
										printf("[%s] info tcpc_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
										cons[cidx].lock[1] = secs;
									}
								}
								indx = cidx;
							}
						}
					}
					if (indx < 0) {
						if ((olen != ENDL) && ((secs - lock) >= 1)) {
							printf("[%s] warn tcpc_recv fcon [%d.%d.%d.%d:%d] [%d] [%d]\n", gett(), head->sadr[3], head->sadr[2], head->sadr[1], head->sadr[0], sprt, indx, stat);
							fcon(buff[x].sock, NUMC + x + 1, head, cryp, ENDL);
							lock = secs;
						}
						if (args->conz == 1) { stat = -7; break; }
					}
				}
				if (flag == 1) {
					if (x == 0) { fins(esoc, 1); }
					else { fins(rsoc, 1); }
				}
			}
		}
	}

	argp->stat = -1;

	if (args->conz == 1) {
		printf("[%s] info tcpc_recv ends [%d]\n", gett(), stat);
	} else {
		printf("[%s] warn tcpc_recv ends [%d]\n", gett(), stat);
	}

	return NULL;
}

void *tcpc_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int indx = argp->indx;

	int leng, size, csoc, dsoc, midx, tidx, fdes;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int maxl = (BTCP + HEDL);
	char *prot = "tcp";
	unsigned char temp[BMAX], data[BMAX];
	unsigned char *pntr;
	time_t secs;
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
			cons->sock = &(argp->esoc[indx]);
		} else {
			cons->midx = 1;
			cons->sock = &(argp->rsoc[indx]);
		}
		cons->addr[1].sin_addr.s_addr = inet_addr(cons->adrs[1]);
		cons->addr[1].sin_port = htons(cons->port[0]);
		head->prot = 2; head->kind = 1;
		PACKU32(head->sadr, cons->addr[0].sin_addr.s_addr); PACKU16(head->sprt, cons->port[0]);
		PACKU32(head->dadr, cons->addr[1].sin_addr.s_addr); PACKU16(head->dprt, cons->port[1]);
	} else {
		printf("[%s] erro tcpc_send dest [%s:%d]\n", gett(), cons->adrs[0], cons->port[0]);
		stat = -2;
	}

	midx = cons->midx;
	tidx = ((indx * 2) + midx);
	cryp->q = args->skey;
	while (stat == 1) {
		if ((argp->stat != 1) || (cons->stat != 1)) {
			stat = -3; break;
		}
		fdes = *(argp->csoc);
		if (fdes < 0) { stat = -4; break; }
		csoc = fdes;
		if ((erro = sels(&(rfds), csoc, 0)) < 0) {
			printf("[%s] erro tcpc_send sels [%d]\n", gett(), erro);
			stat = -5; break;
		}
		secs = time(NULL);
		csoc = *(argp->csoc);
		if ((csoc > 0) && FD_ISSET(csoc, &(rfds))) {
			dsoc = *(cons->sock);
			if (dsoc < 1) {
				printf("[%s] warn tcpc_send conn [%d]\n", gett(), dsoc);
				if (args->conz == 1) { stat = -9; break; }
				usleep(USLA);
			} else {
				leng = read(csoc, temp, BTCP);
				if (leng < BONE) {
					if (leng < 0) { printf("[%s] erro tcpc_send read [%d] [%d] [%s]\n", gett(), leng, csoc, strerror(errno)); }
					stat = leng; break;
				}
				size = (hlen + leng);
				PACKU16(head->leng, size);
				bcopy(head, data, hlen); pntr = (data + hlen);
				bcopy(temp, pntr, leng); pntr = data;
				erro = wrap(cryp, temp, maxl, data, size, 'e');
				if (erro > 0) { pntr = temp; size = erro; }
				if (erro < 0) { printf("[%s] warn tcpc_send ciph [%d]\n", gett(), erro); }
				erro = sent(dsoc, pntr, size, tidx);
				if (erro < 1) { printf("[%s] warn tcpc_send sent [%d]\n", gett(), erro); }
				cons->last = secs;
				if ((secs - cons->lock[0]) > 1) {
					printf("[%s] info tcpc_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], indx, size);
					cons->lock[0] = secs;
				}
			}
		}
	}

	if (cons->adrs[1][0] != 0) {
		dsoc = *(cons->sock);
		fcon(dsoc, tidx, head, cryp, ENDL);
	}

	cons->stat = -1;
	argp->stat = -1;

	printf("[%s] info tcpc_send ends [%d]\n", gett(), stat);

	return NULL;
}

void *tcpc_mgmt(void *argv) {
	thro_o **thrp = (thro_o **)argv;
	thro_o *thrr = thrp[0];
	thro_o *thrs = thrp[1];
	args_o *args = thrs->args;
	cons_l *cons = thrr->cons;
	int *esoc = thrs->esoc;
	int *rsoc = thrs->rsoc;
	int *csoc = thrr->csoc;

	time_t secs, last[2];
	int elen = sizeof(struct sockaddr_in);
	int rlen = sizeof(struct sockaddr_in);
	struct sockaddr_in eadr, radr;
	struct sockaddr_in *padr;

	padr = &(eadr);
	bzero(padr, elen);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(args->rprt);
	padr->sin_addr.s_addr = inet_addr(LOCL);

	padr = &(radr);
	bzero(padr, rlen);
	padr->sin_family = AF_INET;
	padr->sin_port = htons(args->rprt);
	padr->sin_addr.s_addr = inet_addr(args->radr);

	last[0] = 0; last[1] = 0;
	while (1) {
		secs = time(NULL);
		if ((secs - last[1]) >= MGMB) {
			for (int x = 0; x < NUMC; ++x) {
				int idxt = thrr[x].indx;
				if (thrr[idxt].stat != 1) { continue; }
				if (args->nots != NULL) {
					esoc[idxt] = icon(esoc[idxt], &(eadr));
				}
				rsoc[idxt] = icon(rsoc[idxt], &(radr));
			}
			last[1] = secs;
		}
		if ((secs - last[0]) >= MGMA) {
			for (int x = 0; x < NUMC; ++x) {
				if (cons[x].stat == 1) {
					if ((secs - cons[x].last) >= EXPC) {
						cons[x].stat = -2;
					}
				}
				if (cons[x].stat < 0) {
					cons[x].stat = 0;
				}
				if (thrr[x].stat < 0) {
					printf("[%s] info tcpc_serv endt [%d] [%d]\n", gett(), x, thrr[x].stat);
					fins(&(esoc[x]), 1);
					fins(&(rsoc[x]), 1);
					join(thrr[x].thro, "tcpc_serv thrr", x);
					thrr[x].stat = 0;
				}
				if (thrs[x].stat < 0) {
					if (args->conz == 1) {
						int idxt = thrs[x].indx;
						if (thrr[idxt].stat == 1) {
							thrr[idxt].stat = 2;
						}
						printf("[%s] info tcpc_serv socs [%d] [%d]\n", gett(), idxt, thrr[idxt].stat);
						fins(&(esoc[idxt]), 1);
						fins(&(rsoc[idxt]), 1);
					}
					fins(&(csoc[x]), 1);
					join(thrs[x].thro, "tcpc_serv thrs", x);
					thrs[x].stat = 0;
				}
			}
			last[0] = secs;
		}
		usleep(USLB);
	}

	return NULL;
}

void tcpc_serv(args_o *args) {
	int indx, tidx, fdes;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int elen = sizeof(struct sockaddr_in);
	int rlen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], esoc[NUMC], rsoc[NUMC];
	struct sockaddr_in ladr, eadr, radr;
	struct sockaddr_in *padr;
	time_t secs;
	fd_set rfds;
	pthread_t mgmt;

	cons_l *cons = malloc(NUMC * sizeof(cons_l));
	inet_l *nots = malloc(LIST * sizeof(inet_l));
	thro_o **thrp = malloc(2 * sizeof(thro_o *));
	thro_o thrr[NUMC], thrs[NUMC];
	thrp[0] = thrr; thrp[1] = thrs;

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
	padr->sin_addr.s_addr = inet_addr(LOCL);

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
	bzero(&(mgmt), sizeof(pthread_t));
	pthread_create(&(mgmt), NULL, tcpc_mgmt, thrp);
	while (stat == 1) {
		indx = -1;
		for (int x = 0; (indx < 0) && (x < NUMC); ++x) {
			if ((thrs[x].stat == 0) && (cons[x].stat == 0)) {
				if ((thrr[x].stat == 0) || (thrr[x].stat == 1)) {
					indx = x;
				}
			}
		}
		if ((erro = sels(&(rfds), lsoc, 0)) < 0) {
			printf("[%s] erro tcpc_serv sels [%d]\n", gett(), erro);
			stat = -2; break;
		}
		secs = time(NULL);
		if (FD_ISSET(lsoc, &(rfds))) {
			if (indx < 0) {
				printf("[%s] warn tcpc_serv indx [%d]\n", gett(), indx);
				usleep(USLA);
				continue;
			}
			slen = sizeof(struct sockaddr_in);
			padr = &(cons[indx].addr[0]);
			fdes = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (fdes < 1) {
				printf("[%s] erro tcpc_serv conn [%d]\n", gett(), fdes);
				stat = -3; break;
			}
			if (args->conz == 1) {
				tidx = indx;
			}
			if (args->nots != NULL) {
				esoc[tidx] = icon(esoc[tidx], &(eadr));
			}
			rsoc[tidx] = icon(rsoc[tidx], &(radr));
			if (thrr[tidx].stat == 0) {
				bzero(&(thrr[tidx].thro), sizeof(pthread_t));
				pthread_create(&(thrr[tidx].thro), NULL, tcpc_recv, &(thrr[tidx]));
			}
			csoc[indx] = fdes;
			cons[indx].last = secs;
			thrr[tidx].indx = tidx;
			thrs[indx].indx = tidx;
			thrr[tidx].stat = 1;
			thrs[indx].stat = 1;
			cons[indx].stat = 1;
			bzero(&(thrs[indx].thro), sizeof(pthread_t));
			pthread_create(&(thrs[indx].thro), NULL, tcpc_send, &(thrs[indx]));
		}
	}

	free(nots);
	free(cons);
	free(thrp);
}
