
void *tcps_recv(void *argv) {
	proc_o *argq = (proc_o *)argv;
	cons_l *cons = argq->cons;
	int cidx = argq->indx;

	int leng, size;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int plen = sizeof(struct sockaddr_in);
	int maxl = (BTCP + HEDL);
	unsigned char data[BMAX], temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	fd_set rfds;

	int midx = cons->midx;
	int rpip = cons->rpwp[0];
	int csoc = *(argq->sock);
	int ssoc = *(cons->sock);
	struct sockaddr_in *padr = &(cons->addr[1]);
	pckt_h *head = &(cons->head);
	ciph_o *cryp = &(cons->cryp[1]);

	if (ssoc > 0) {
		if ((erro = connect(ssoc, (struct sockaddr *)padr, plen)) != 0) {
			printf("[%s] erro tcps_recv syns [%d] [%d][%s] [%s:%d]->[%s:%d]\n", gett(), cidx, ssoc, strerror(errno), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1]);
			stat = -8;
		}
	} else { stat = -9; }

	while (stat == 1) {
		csoc = *(argq->sock);
		if ((argq->stat != 1) || (cons->stat != 1) || (csoc < 1)) {
			stat = -2; break;
		}
		rpip = cons->rpwp[0];
		ssoc = *(cons->sock);
		if ((rpip < 1) || (ssoc < 1)) {
			stat = -3; break;
		}
		if ((erro = sels(&(rfds), rpip, ssoc)) < 0) {
			printf("[%s] erro tcps_recv sels [%d]\n", gett(), erro);
			stat = -4; break;
		}
		secs = time(NULL);
		if (FD_ISSET(rpip, &(rfds))) {
			leng = read(rpip, data, BTCP);
			if (leng < BONE) { stat = -5; break; }
			erro = senz(ssoc, data, leng);
			if (erro < 1) { printf("[%s] warn tcps_recv senz [%d]\n", gett(), erro); }
		}
		ssoc = *(cons->sock);
		if ((ssoc > 0) && (FD_ISSET(ssoc, &(rfds)))) {
			leng = read(ssoc, temp, BTCP);
			if (leng < BONE) {
				if (leng < 0) { printf("[%s] erro tcps_recv read [%d][%d] [%d][%s]\n", gett(), leng, cidx, ssoc, strerror(errno)); }
				stat = leng; break;
			}
			size = (hlen + leng);
			PACKU16(head->leng, size);
			bcopy(head, data, hlen); pntr = (data + hlen);
			bcopy(temp, pntr, leng); pntr = data;
			erro = wrap(cryp, temp, maxl, data, size, 'e');
			if (erro > 0) { pntr = temp; size = erro; }
			if (erro < 0) { printf("[%s] warn tcps_recv ciph [%d]\n", gett(), erro); }
			erro = sent(csoc, pntr, size, midx);
			if (erro < 1) { printf("[%s] warn tcps_recv sent [%d]\n", gett(), erro); }
			cons->ping[1] = secs;
			cons->last = secs;
			if ((secs - cons->lock[1]) > 1) {
				printf("[%s] info tcps_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], cidx, size);
				cons->lock[1] = secs;
			}
		}
		if ((secs - cons->ping[1]) >= (MGMC * 3)) {
			csoc = *(argq->sock);
			fcon(csoc, midx, head, cryp, CHKL);
			cons->ping[1] = secs;
		}
	}

	csoc = *(argq->sock);
	fcon(csoc, midx, head, cryp, ENDL);

	cons->stat = -1;
	argq->stat = -1;

	printf("[%s] info tcps_recv ends [%d] [%d] [%d]\n", gett(), stat, cidx, ssoc);

	return NULL;
}

void *tcps_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	proc_o *proc = argp->proc;
	int indx = argp->indx;
	int *csoc = &(argp->csoc[indx]);
	int *ssoc = argp->ssoc;

	int leng, size, cidx, fidx, sprt, cprt, fdes, zidx;
	int erro = 1, stat = 1, olen = 1;
	int maxl = (BTCP + HEDL);
	int hlen = sizeof(pckt_h);
	unsigned char temp[BMAX];
	unsigned char *pntr;
	time_t secs, lock;
	struct sockaddr_in addr;
	struct sockaddr_in *padr, *cadr;

	buff_o buff;
	pckt_h pobj;
	ciph_o cobj;
	pckt_h *head = &(pobj);
	ciph_o *cryp = &(cobj);

	bzero(&(buff), sizeof(buff_o));
	bzero(&(pobj), sizeof(pckt_h));
	bzero(&(cobj), sizeof(ciph_o));

	lock = 0;
	buff.sock = *(csoc);
	cryp->q = args->skey;
	while (stat == 1) {
		if (argp->stat != 1) {
			stat = -2; break;
		}
		size = recw(&(buff));
		if (size < 1) {
			if (args->conz != 1) {
				printf("[%s] warn tcps_send recw [%d] [%d] [%d]\n", gett(), indx, size, buff.sock);
			}
			stat = size; break;
		}
		size = buff.size;
		pntr = buff.buff;
		erro = wrap(cryp, temp, maxl, pntr, size, 'd');
		if (erro > 0) { pntr = temp; size = erro; }
		if (erro < 0) {
			printf("[%s] warn tcps_send ciph [%d]\n", gett(), erro);
			stat = -9; break;
		}
		bcopy(pntr, head, hlen);
		UPACK16(leng, head->leng); olen = leng;
		leng -= hlen; pntr += hlen;
		if ((olen != ENDL) && (olen != CHKL) && ((leng < BONE) || (BTCP < leng))) {
			printf("[%s] warn tcps_send head [%d]\n", gett(), leng);
			stat = -9; break;
		}
		secs = time(NULL);
		UPACK16(sprt, head->sprt);
		padr = &(addr);
		padr->sin_family = AF_INET;
		padr->sin_port = htons(sprt);
		UPACK32(padr->sin_addr.s_addr, head->sadr);
		cidx = -1; fidx = -1; zidx = -1;
		for (int x = 0; x < NUMC; ++x) {
			cprt = cons[x].port[0];
			cadr = &(cons[x].addr[0]);
			if ((cons[x].stat == 0) && (proc[x].stat == 0)) {
				if (fidx < 0) { fidx = x; }
			} else if ((cons[x].stat == 1) && (proc[x].stat == 1)) {
				if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
					cidx = x; break;
				}
			} else {
				if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
					zidx = x; break;
				}
			}
		}
		if ((olen != ENDL) && (cidx < 0) && (fidx > -1) && (zidx < 0)) {
			if ((fdes = sets(&(cons[fidx]), &(proc[fidx]), head, args->skey, cons[fidx].rpwp, ssoc, csoc, fidx, indx, 2)) < 1) {
				printf("[%s] warn tcps_send sock [%d]\n", gett(), fidx);
			} else {
				cidx = fidx;
				bzero(&(proc[cidx].thro), sizeof(pthread_t));
				pthread_create(&(proc[cidx].thro), NULL, tcps_recv, &(proc[cidx]));
			}
		}
		if ((cidx < 0) || (proc[cidx].stat != 1) || (cons[cidx].stat != 1)) {
			if ((olen != ENDL) && ((secs - lock) >= 1)) {
				printf("[%s] warn tcps_send fcon [%d.%d.%d.%d:%d] [%d] [%d]\n", gett(), head->sadr[3], head->sadr[2], head->sadr[1], head->sadr[0], sprt, cidx, stat);
				fcon(buff.sock, NUMC + 1, head, cryp, ENDL);
				lock = secs;
			}
			if (args->conz == 1) { stat = -7; break; }
		} else {
			if (olen == ENDL) {
				if (proc[cidx].stat == 1) { proc[cidx].stat = 8; }
				if (cons[cidx].stat == 1) { cons[cidx].stat = 8; }
				if (args->conz == 1) { stat = -6; break; }
			} else if (olen == CHKL) {
				cons[cidx].ping[0] = secs;
			} else {
				erro = write(cons[cidx].rpwp[1], pntr, leng);
				cons[cidx].ping[0] = secs;
				cons[cidx].last = secs;
				if ((secs - cons[cidx].lock[0]) > 1) {
					printf("[%s] info tcps_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
					cons[cidx].lock[0] = secs;
				}
			}
		}
	}

	argp->stat = -1;

	if (args->conz == 1) {
		printf("[%s] info tcps_send ends [%d] [%d]\n", gett(), stat, indx);
	} else {
		printf("[%s] warn tcps_send ends [%d] [%d]\n", gett(), stat, indx);
	}

	return NULL;
}

void *tcps_mgmt(void *argv) {
	thro_o *thrl = (thro_o *)argv;
	args_o *args = thrl->args;
	cons_l *cons = thrl->cons;
	proc_o *proc = thrl->proc;
	int *csoc = thrl->csoc;

	time_t secs, last[3];

	last[0] = 0; last[1] = 0; last[2] = 0;
	while (1) {
		secs = time(NULL);
		if ((secs - last[2]) >= MGMC) {
			for (int x = 0; x < NUMC; ++x) {
				if (cons[x].stat == 1) {
					if (((secs - cons[x].ping[0]) >= EXPP) || ((secs - cons[x].ping[1]) >= EXPP)) {
						printf("[%s] warn tcps_mgmt ping [%d][%ld] [%ld][%ld]\n", gett(), x, secs, cons[x].ping[0], cons[x].ping[1]);
						cons[x].stat = -3;
					}
				}
			}
			last[2] = secs;
		}
		if ((secs - last[0]) >= MGMA) {
			for (int x = 0; x < NUMC; ++x) {
				if (cons[x].stat == 1) {
					if ((secs - cons[x].last) >= EXPC) {
						cons[x].stat = 2;
					}
				}
				if (cons[x].stat < 0) {
					if (args->conz == 1) {
						int idxt = cons[x].tidx;
						if (thrl[idxt].stat == 1) {
							thrl[idxt].stat = 2;
						}
					}
					if (proc[x].stat == 1) {
						proc[x].stat = 2;
					}
					fins(cons[x].sock, 1);
					fins(&(cons[x].rpwp[1]), 0);
					fins(&(cons[x].rpwp[0]), 0);
					cons[x].tidx = 0;
					cons[x].indx = 0;
					cons[x].stat = 0;
				}
				if (proc[x].stat < 0) {
					if (args->conz == 1) {
						int idxt = proc[x].tidx;
						if (thrl[idxt].stat == 1) {
							thrl[idxt].stat = 2;
						}
					}
					if (cons[x].stat != 0) {
						cons[x].stat = -2;
					}
					join(proc[x].thro, "tcps_serv proc", x);
					proc[x].tidx = 0;
					proc[x].indx = 0;
					proc[x].stat = 0;
				}
				if (thrl[x].stat < 0) {
					fins(&(csoc[x]), 1);
					join(thrl[x].thro, "tcps_serv thrl", x);
					thrl[x].stat = 0;
				}
			}
			last[0] = secs;
		}
		usleep(USLB);
	}

	return NULL;
}

void tcps_serv(args_o *args) {
	int indx, fdes;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], ssoc[NUMC];
	int rpwp[NUMC][2];
	struct sockaddr_in ladr, cadr;
	struct sockaddr_in *padr;
	fd_set rfds;
	pthread_t mgmt;

	cons_l *cons = malloc(NUMC * sizeof(cons_l));
	proc_o proc[NUMC];
	thro_o thrl[NUMC];

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

	bzero(csoc, NUMC * sizeof(int));
	bzero(ssoc, NUMC * sizeof(int));
	bzero(cons, NUMC * sizeof(cons_l));
	bzero(proc, NUMC * sizeof(proc_o));
	bzero(thrl, NUMC * sizeof(thro_o));
	for (int x = 0; x < NUMC; ++x) {
		rpwp[x][0] = 0; rpwp[x][1] = 0; cons[x].rpwp = rpwp[x];
		thrl[x].indx = x; thrl[x].args = args; thrl[x].cons = cons;
		thrl[x].proc = proc; thrl[x].csoc = csoc; thrl[x].ssoc = ssoc; thrl[x].lsoc = &(lsoc);
	}

	bzero(&(mgmt), sizeof(pthread_t));
	pthread_create(&(mgmt), NULL, tcps_mgmt, thrl);
	while (stat == 1) {
		indx = -1;
		for (int x = 0; (indx < 0) && (x < NUMC); ++x) {
			if (thrl[x].stat == 0) {
				indx = x;
			}
		}
		if ((erro = sels(&(rfds), lsoc, 0)) < 0) {
			printf("[%s] erro tcps_serv sels [%d]\n", gett(), erro);
			stat = -2; break;
		}
		if (FD_ISSET(lsoc, &(rfds))) {
			if (indx < 0) {
				printf("[%s] warn tcps_serv indx [%d]\n", gett(), indx);
				usleep(USLA);
				continue;
			}
			padr = &(cadr);
			fdes = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (fdes < 1) {
				printf("[%s] erro tcps_serv conn [%d]\n", gett(), fdes);
				stat = -3; break;
			}
			csoc[indx] = fdes;
			thrl[indx].indx = indx;
			thrl[indx].stat = 1;
			bzero(&(thrl[indx].thro), sizeof(pthread_t));
			pthread_create(&(thrl[indx].thro), NULL, tcps_send, &(thrl[indx]));
			printf("[%s] info tcps_serv accp [%s:%d]\n", gett(), inet_ntoa(padr->sin_addr), ntohs(padr->sin_port));
		}
	}

	free(cons);
}
