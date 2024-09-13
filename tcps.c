
void *tcps_recv(void *argv) {
	proc_o *argq = (proc_o *)argv;
	bufs_l *bufs = argq->bufs;
	cons_l *cons = argq->cons;
	int cidx = argq->indx;

	int leng, size, fmax, schk;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int plen = sizeof(struct sockaddr_in);
	unsigned char data[BMAX], temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	fd_set rfds;
	struct timeval tval;

	int midx = cons->midx;
	int csoc = *(argq->sock);
	int ssoc = *(cons->sock);
	struct sockaddr_in *padr = &(cons->addr[1]);
	pckt_h *head = &(cons->head);
	ciph_o *cryp = &(cons->cryp[1]);

	if ((erro = connect(ssoc, (struct sockaddr *)padr, plen)) != 0) {
		printf("[%s] erro tcps_recv conn\n", gett()); stat = 0;
	}
	fmax = 0; leng = 1;
	secs = time(NULL);
	while ((fmax == 0) || (leng == 1)) {
		leng = 0;
		for (int x = 0; x < NUMC; ++x) {
			if ((bufs[x].stat == 1) && (bufs[x].indx == cidx)) {
				leng = bufs[x].leng;
				pntr = bufs[x].buff;
				erro = senz(ssoc, pntr, leng);
				bufs[x].stat = 0;
				cons->last = secs;
				fmax = 1;
				if ((secs - cons->lock[0]) > 1) {
					printf("[%s] tcps_recv sock [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], cidx, leng);
					cons->lock[0] = secs;
				}
			}
		}
	}

	cons->stat = 1;

	while (stat == 1) {
		FD_ZERO(&(rfds));
		FD_SET(ssoc, &(rfds));
		fmax = (ssoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro tcps_recv sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		schk = cons->stat;
		csoc = *(argq->sock);
		if ((schk == 9) || (csoc < 1)) {
			stat = 0; break;
		}
		secs = time(NULL);
		if (FD_ISSET(ssoc, &(rfds))) {
			leng = read(ssoc, temp, BTCP);
			if (leng < BONE) {
				printf("[%s] erro tcps_recv read\n", gett());
				stat = 0; break;
			}
			size = (hlen + leng);
			PACKU16(head->leng, size);
			bcopy(head, data, hlen); pntr = (data + hlen);
			bcopy(temp, pntr, leng); pntr = data;
			erro = wrap(cryp, temp, BMAX, data, size, 'e');
			if (erro > 0) { pntr = temp; size = erro; }
			if (erro < 0) { printf("[%s] warn tcps_recv ciph [%d]\n", gett(), erro); }
			erro = sent(csoc, pntr, size, midx);
			if (erro < 1) { printf("[%s] warn tcps_recv sent [%d]\n", gett(), erro); }
			cons->last = secs;
			if ((secs - cons->lock[1]) > 1) {
				printf("[%s] tcps_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], cidx, size);
				cons->lock[1] = secs;
			}
		}
		if ((secs - cons->last) >= EXPC) {
			stat = 0; break;
		}
	}

	fins(&(ssoc), 1);
	cons->stat = -1;

	printf("[%s] tcps_recv fins [%d]\n", gett(), cidx);

	return NULL;
}

void *tcps_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	bufs_l *bufs = argp->bufs;
	cons_l *cons = argp->cons;
	proc_o *proc = argp->proc;
	int *ssoc = argp->ssoc;

	int leng, size, cidx, fidx, sprt, cprt, olen;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int slen = sizeof(struct sockaddr_in);
	unsigned char temp[BMAX];
	unsigned char *pntr;
	time_t secs;
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

	buff.sock = *(argp->csoc);
	buff.pbuf = buff.buff;
	cryp->q = args->skey;
	while (stat == 1) {
		size = recw(&(buff));
		if (size < 1) {
			printf("[%s] warn tcps_send size [%d] [%d]\n", gett(), size, buff.sock);
			stat = 0; break;
		} else if ((buff.leng > 0) && (buff.leng == buff.size)) {
			size = buff.size;
			pntr = buff.buff;
			erro = wrap(cryp, temp, BMAX, pntr, size, 'd');
			if (erro > 0) { pntr = temp; size = erro; }
			if (erro < 0) { printf("[%s] warn tcps_send ciph [%d]\n", gett(), erro); }
			else {
				bcopy(pntr, head, hlen);
				UPACK16(leng, head->leng); olen = leng;
				leng -= hlen; pntr += hlen;
				if ((olen != 31337) && ((leng < 1) || (BTCP < leng))) {
					printf("[%s] warn tcps_send head [%d]\n", gett(), leng);
				} else {
					secs = time(NULL);
					UPACK16(sprt, head->sprt);
					padr = &(addr);
					padr->sin_family = AF_INET;
					padr->sin_port = htons(sprt);
					UPACK32(padr->sin_addr.s_addr, head->sadr);
					cidx = -1; fidx = -1;
					for (int x = 0; x < NUMC; ++x) {
						cprt = cons[x].port[0];
						cadr = &(cons[x].addr[0]);
						if (cons[x].stat == -1) {
							pthread_join(proc[x].thro, NULL);
							bzero(&(proc[x]), sizeof(proc_o));
							bzero(&(cons[x]), sizeof(cons_l));
						}
						if (cons[x].stat == 0) {
							fidx = x;
						}
						if ((cprt > 0) && (cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
							cidx = x; break;
						}
					}
					if ((cidx < 0) && (fidx > -1)) {
						ssoc[fidx] = socket(AF_INET, SOCK_STREAM, 0);
						if (ssoc[fidx] < 1) {
							printf("[%s] warn tcps_send sock [%d]\n", gett(), fidx);
						} else {
							cons[fidx].port[0] = sprt;
							memcpy(&(cons[fidx].addr[0]), padr, slen);
							UPACK16(cprt, head->dprt);
							cons[fidx].port[1] = cprt;
							padr = &(cons[fidx].addr[1]);
							padr->sin_family = AF_INET;
							padr->sin_port = htons(cprt);
							UPACK32(padr->sin_addr.s_addr, head->dadr);
							memcpy(&(cons[fidx].head), head, hlen);
							copy(cons[fidx].adrs[0], inet_ntoa(cons[fidx].addr[0].sin_addr), ILEN, LINE);
							copy(cons[fidx].adrs[1], inet_ntoa(cons[fidx].addr[1].sin_addr), ILEN, LINE);
							cons[fidx].sock = &(ssoc[fidx]);
							cons[fidx].cryp[0].q = args->skey;
							cons[fidx].cryp[1].q = args->skey;
							cons[fidx].lock[0] = 0;
							cons[fidx].lock[1] = 0;
							cons[fidx].midx = 0;
							cons[fidx].stat = 2;
							cidx = fidx;
							proc[cidx].indx = cidx;
							proc[cidx].sock = argp->csoc;
							proc[cidx].bufs = bufs;
							proc[cidx].cons = &(cons[cidx]);
							pthread_create(&(proc[cidx].thro), NULL, tcps_recv, &(proc[cidx]));
						}
					}
					if ((cidx < 0) || (cons[cidx].stat < 1)) {
						printf("[%s] warn tcps_send indx [%d]\n", gett(), cidx);
					} else {
						if (olen == 31337) {
							cons[cidx].stat = 9;
						} else if (cons[cidx].stat == 2) {
							for (int y = 0; y < NUMC; ++y) {
								if ((bufs[y].stat != 0) && ((secs - bufs[y].last) >= 5)) {
									bufs[y].stat = 0;
								}
								if (bufs[y].stat == 0) {
									printf("[%s] tcps_send buff [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
									memcpy(bufs[y].buff, pntr, leng);
									bufs[y].last = secs;
									bufs[y].leng = leng;
									bufs[y].indx = cidx;
									bufs[y].stat = 1;
									break;
								}
							}
						} else if (cons[cidx].stat == 1) {
							erro = senz(ssoc[cidx], pntr, leng);
							cons[cidx].last = secs;
							if ((secs - cons[cidx].lock[0]) > 1) {
								printf("[%s] tcps_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
								cons[cidx].lock[0] = secs;
							}
						}
					}
				}
			}
			buff.leng = 0; buff.size = 0;
			buff.pbuf = buff.buff;
		}
	}

	fins(argp->csoc, 1);

	for (int x = 0; x < NUMC; ++x) {
		if (cons[x].stat != 0) {
			printf("[%s] tcps_send stop [%d]\n", gett(), x);
			pthread_join(proc[x].thro, NULL);
			bzero(&(proc[x]), sizeof(proc_o));
			bzero(&(cons[x]), sizeof(cons_l));
		}
	}

	printf("[%s] tcps_send fins\n", gett());

	return NULL;
}

void tcps_serv(args_o *args) {
	int indx;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], ssoc[NUMC];
	struct sockaddr_in ladr, cadr;
	struct sockaddr_in *padr;

	bufs_l *bufs = malloc(NUMC * sizeof(bufs_l));
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
	bzero(bufs, NUMC * sizeof(bufs_l));
	bzero(cons, NUMC * sizeof(cons_l));
	bzero(proc, NUMC * sizeof(proc_o));
	bzero(thrl, NUMC * sizeof(thro_o));
	for (int x = 0; x < NUMC; ++x) {
		thrl[x].args = args; thrl[x].bufs = bufs; thrl[x].cons = cons; thrl[x].proc = proc;
		thrl[x].lsoc = &(lsoc); thrl[x].csoc = &(csoc[x]); thrl[x].ssoc = ssoc;
	}

	indx = 0;
	while (stat == 1) {
		indx = ((indx + 1) % NUMC);
		if (csoc[indx] < 0) {
			pthread_join(thrl[indx].thro, NULL);
			bzero(&(thrl[indx].thro), sizeof(pthread_t));
			csoc[indx] = 0;
		}
		if (csoc[indx] != 0) {
			printf("[%s] warn tcps_serv indx [%d]\n", gett(), indx);
			usleep(500000);
			continue;
		}
		padr = &(cadr);
		erro = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
		if (erro < 1) {
			printf("[%s] erro tcps_serv conn [%d]\n", gett(), erro);
			stat = 0; break;
		}
		csoc[indx] = erro;
		pthread_create(&(thrl[indx].thro), NULL, tcps_send, &(thrl[indx]));
	}

	free(cons);
	free(bufs);
}
