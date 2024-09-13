
void *udps_recv(void *argv) {
	proc_o *argq = (proc_o *)argv;
	cons_l *cons = argq->cons;
	int cidx = argq->indx;

	int leng, size;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	unsigned char data[BMAX], temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	fd_set rfds;
	struct sockaddr_in cadr;

	int midx = cons->midx;
	int csoc = *(argq->sock);
	int ssoc = *(cons->sock);
	pckt_h *head = &(cons->head);
	ciph_o *cryp = &(cons->cryp[1]);

	while (stat == 1) {
		csoc = *(argq->sock);
		ssoc = *(cons->sock);
		if ((argq->stat != 1) || (cons->stat != 1) || (csoc < 1) || (ssoc < 1)) {
			stat = -2; break;
		}
		if ((erro = sels(&(rfds), ssoc, 0)) < 0) {
			printf("[%s] erro udps_recv sels [%d]\n", gett(), erro);
			stat = -3; break;
		}
		secs = time(NULL);
		if (FD_ISSET(ssoc, &(rfds))) {
			leng = recu(ssoc, temp, BUDP, &(cadr));
			if (leng < BONE) {
				if (leng < 0) { printf("[%s] erro udps_recv recu [%d][%d] [%d][%s]\n", gett(), leng, cidx, ssoc, strerror(errno)); }
				stat = leng; break;
			}
			size = (hlen + leng);
			PACKU16(head->leng, size);
			bcopy(head, data, hlen); pntr = (data + hlen);
			bcopy(temp, pntr, leng); pntr = data;
			erro = wrap(cryp, temp, BMAX, data, size, 'e');
			if (erro > 0) { pntr = temp; size = erro; }
			if (erro < 0) { printf("[%s] warn udps_recv ciph [%d]\n", gett(), erro); }
			erro = sent(csoc, pntr, size, midx);
			if (erro < 1) { printf("[%s] warn udps_recv sent [%d]\n", gett(), erro); }
			cons->last = secs;
			if ((secs - cons->lock[1]) > 1) {
				printf("[%s] info udps_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], cidx, size);
				cons->lock[1] = secs;
			}
		}
	}

	cons->stat = -1;
	argq->stat = -1;

	printf("[%s] info udps_recv ends [%d] [%d] [%s:%d]\n", gett(), stat, cidx, cons->adrs[0], cons->port[0]);

	return NULL;
}

void *udps_send(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	proc_o *proc = argp->proc;
	int indx = argp->indx;
	int *csoc = &(argp->csoc[indx]);
	int *ssoc = argp->ssoc;

	int leng, size, cidx, fidx, sprt, cprt, fdes;
	int erro = 1, stat = 1, lsoc = 1;
	int hlen = sizeof(pckt_h);
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

	buff.sock = *(csoc);
	cryp->q = args->skey;
	while (stat == 1) {
		if (argp->stat != 1) {
			if (args->conz != 1) {
				printf("[%s] warn udps_send stat [%d] [%d] [%d]\n", gett(), indx, stat, argp->stat);
			}
			stat = argp->stat; break;
		}
		size = recw(&(buff));
		if (size < 1) {
			if (args->conz != 1) {
				printf("[%s] warn udps_send recw [%d] [%d] [%d]\n", gett(), indx, size, buff.sock);
			}
			stat = size; break;
		}
		size = buff.size;
		pntr = buff.buff;
		erro = wrap(cryp, temp, BMAX, pntr, size, 'd');
		if (erro > 0) { pntr = temp; size = erro; }
		if (erro < 0) {
			printf("[%s] warn udps_send ciph [%d]\n", gett(), erro);
			stat = -9; break;
		}
		bcopy(pntr, head, hlen);
		UPACK16(leng, head->leng);
		leng -= hlen; pntr += hlen;
		if ((leng < BONE) || (BTCP < leng)) {
			printf("[%s] warn udps_send head [%d]\n", gett(), leng);
			stat = -9; break;
		}
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
			if ((cons[x].stat == 0) && (proc[x].stat == 0)) {
				if (fidx < 0) { fidx = x; }
			} else if ((cons[x].stat == 1) && (proc[x].stat == 1)) {
				if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
					cidx = x; break;
				}
			}
		}
		if ((cidx < 0) && (fidx > -1)) {
			if ((fdes = sets(&(cons[fidx]), &(proc[fidx]), head, args->skey, NULL, ssoc, csoc, fidx, indx, 1)) < 1) {
				printf("[%s] warn udps_send sock [%d]\n", gett(), fidx);
			} else {
				cidx = fidx;
				bzero(&(proc[cidx].thro), sizeof(pthread_t));
				pthread_create(&(proc[cidx].thro), NULL, udps_recv, &(proc[cidx]));
			}
		}
		if ((cidx < 0) || (cons[cidx].stat != 1)) {
			printf("[%s] warn udps_send indx [%d]\n", gett(), cidx);
		} else {
			lsoc = ssoc[cidx];
			padr = &(cons[cidx].addr[1]);
			erro = senu(lsoc, pntr, leng, padr);
			cons[cidx].last = secs;
			if ((secs - cons[cidx].lock[0]) > 1) {
				printf("[%s] info udps_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
				cons[cidx].lock[0] = secs;
			}
		}
	}

	for (int x = 0; x < NUMC; ++x) {
		if ((cons[x].indx == indx) && (cons[x].stat == 1)) {
			printf("[%s] info udps_send stop conn [%d][%d] [%d][%d]\n", gett(), indx, x, stat, cons[x].stat);
			cons[x].stat = 9;
		}
		if ((proc[x].indx == indx) && (proc[x].stat == 1)) {
			printf("[%s] info udps_send stop proc [%d][%d] [%d][%d]\n", gett(), indx, x, stat, proc[x].stat);
			proc[x].stat = 9;
		}
	}

	argp->stat = -1;

	if (args->conz == 1) {
		printf("[%s] info udps_send ends [%d] [%d]\n", gett(), stat, indx);
	} else {
		printf("[%s] warn udps_send ends [%d] [%d]\n", gett(), stat, indx);
	}

	return NULL;
}

void udps_serv(args_o *args) {
	int indx, fdes;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], ssoc[NUMC];
	struct sockaddr_in ladr, cadr;
	struct sockaddr_in *padr;
	fd_set rfds;
	time_t secs, last[2];

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
		thrl[x].args = args; thrl[x].cons = cons; thrl[x].proc = proc;
		thrl[x].lsoc = &(lsoc); thrl[x].csoc = csoc; thrl[x].ssoc = ssoc;
	}

	last[0] = 0; last[1] = 0;
	while (stat == 1) {
		secs = time(NULL);
		if ((secs - last[0]) >= 3) {
			for (int x = 0; x < NUMC; ++x) {
				if (cons[x].stat == 1) {
					if ((secs - cons[x].last) >= EXPC) {
						cons[x].stat = 2;
					}
				}
				if (cons[x].stat < 0) {
					fins(cons[x].sock, 0);
					cons[x].tidx = 0;
					cons[x].indx = 0;
					cons[x].stat = 0;
				}
				if (proc[x].stat < 0) {
					if (cons[x].stat != 0) {
						cons[x].stat = -2;
					}
					join(proc[x].thro, "udps_serv proc", x);
					proc[x].tidx = 0;
					proc[x].indx = 0;
					proc[x].stat = 0;
				}
				if (thrl[x].stat < 0) {
					fins(&(csoc[x]), 1);
					join(thrl[x].thro, "udps_serv thrl", x);
					thrl[x].stat = 0;
				}
			}
			last[0] = secs;
		}
		indx = -1;
		for (int x = 0; (indx < 0) && (x < NUMC); ++x) {
			if (thrl[x].stat == 0) {
				indx = x;
			}
		}
		if ((erro = sels(&(rfds), lsoc, 0)) < 0) {
			printf("[%s] erro udps_serv sels [%d]\n", gett(), erro);
			stat = -2; break;
		}
		if (FD_ISSET(lsoc, &(rfds))) {
			if (indx < 0) {
				printf("[%s] warn udps_serv indx [%d]\n", gett(), indx);
				usleep(500000);
				continue;
			}
			padr = &(cadr);
			fdes = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (fdes < 1) {
				printf("[%s] erro udps_serv conn [%d]\n", gett(), fdes);
				stat = -3; break;
			}
			csoc[indx] = fdes;
			thrl[indx].indx = indx;
			thrl[indx].stat = 1;
			bzero(&(thrl[indx].thro), sizeof(pthread_t));
			pthread_create(&(thrl[indx].thro), NULL, udps_send, &(thrl[indx]));
		}
	}

	free(cons);
}
