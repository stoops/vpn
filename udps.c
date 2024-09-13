
void *udps_recv(void *argv) {
	proc_o *argq = (proc_o *)argv;
	cons_l *cons = argq->cons;
	int cidx = argq->indx;

	int leng, size, fmax, schk;
	int erro = 1, stat = 1;
	int hlen = sizeof(pckt_h);
	int clen = sizeof(struct sockaddr_in);
	unsigned char data[BMAX], temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	fd_set rfds;
	struct timeval tval;
	struct sockaddr_in cadr;

	int midx = cons->midx;
	int csoc = *(argq->sock);
	int ssoc = *(cons->sock);
	pckt_h *head = &(cons->head);
	ciph_o *cryp = &(cons->cryp[1]);

	while (stat == 1) {
		FD_ZERO(&(rfds));
		FD_SET(ssoc, &(rfds));
		fmax = (ssoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro udps_recv sels [%d]\n", gett(), erro);
			stat = -1; break;
		}
		schk = cons->stat;
		csoc = *(argq->sock);
		if ((schk != 1) || (csoc < 1)) {
			stat = -2; break;
		}
		secs = time(NULL);
		if (FD_ISSET(ssoc, &(rfds))) {
			clen = sizeof(struct sockaddr_in);
			leng = recvfrom(ssoc, temp, BUDP, 0, (struct sockaddr *)&(cadr), (unsigned int *)&(clen));
			if (leng < BONE) {
				printf("[%s] erro udps_recv read [%d] [%d]\n", gett(), leng, ssoc);
				stat = -3; break;
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
		csoc = *(argq->sock);
		if (csoc < 1) {
			stat = -4; break;
		}
		if ((secs - cons->last) >= EXPC) {
			stat = -5; break;
		}
	}

	fins(&(ssoc), 1);

	cons->stat = -1;

	printf("[%s] info udps_recv fins [%d] [%d]\n", gett(), stat, cidx);

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

	int leng, size, cidx, fidx, sprt, cprt;
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

	buff.sock = *(csoc);
	cryp->q = args->skey;
	while (stat == 1) {
		size = recw(&(buff));
		if (size < 1) {
			if (size < 0) { printf("[%s] warn udps_send size [%d] [%d][%d]\n", gett(), indx, size, buff.sock); }
			stat = -1; break;
		}
		size = buff.size;
		pntr = buff.buff;
		erro = wrap(cryp, temp, BMAX, pntr, size, 'd');
		if (erro > 0) { pntr = temp; size = erro; }
		if (erro < 0) {
			printf("[%s] warn udps_send ciph [%d]\n", gett(), erro);
			continue;
		}
		bcopy(pntr, head, hlen);
		UPACK16(leng, head->leng);
		leng -= hlen; pntr += hlen;
		if ((leng < 1) || (BTCP < leng)) {
			printf("[%s] warn udps_send head [%d]\n", gett(), leng);
			continue;
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
			ssoc[fidx] = socket(AF_INET, SOCK_DGRAM, 0);
			if (ssoc[fidx] < 1) {
				printf("[%s] warn udps_send sock [%d]\n", gett(), fidx);
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
				cons[fidx].indx = indx;
				cons[fidx].sock = &(ssoc[fidx]);
				cons[fidx].cryp[0].q = args->skey;
				cons[fidx].cryp[1].q = args->skey;
				cons[fidx].lock[0] = 0;
				cons[fidx].lock[1] = 0;
				cons[fidx].midx = 0;
				cons[fidx].stat = 1;
				cidx = fidx;
				proc[cidx].indx = cidx;
				proc[cidx].sock = csoc;
				proc[cidx].cons = &(cons[cidx]);
				pthread_create(&(proc[cidx].thro), NULL, udps_recv, &(proc[cidx]));
			}
		}
		if ((cidx < 0) || (cons[cidx].stat < 1)) {
			printf("[%s] warn udps_send indx [%d]\n", gett(), cidx);
		} else {
			erro = sendto(ssoc[cidx], pntr, leng, 0, (struct sockaddr *)padr, slen);
			cons[cidx].last = secs;
			if ((secs - cons[cidx].lock[0]) > 1) {
				printf("[%s] info udps_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
				cons[cidx].lock[0] = secs;
			}
		}
	}

	fins(csoc, 1);

	for (int x = 0; x < NUMC; ++x) {
		if ((cons[x].stat != 0) && (cons[x].indx == indx)) {
			printf("[%s] info udps_send stop [%d][%d]\n", gett(), x, indx);
			cons[x].stat = 9;
			fins(cons[x].sock, 1);
			pthread_join(proc[x].thro, NULL);
			bzero(&(proc[x]), sizeof(proc_o));
			bzero(&(cons[x]), sizeof(cons_l));
		}
	}

	printf("[%s] info udps_send fins [%d][%d]\n", gett(), stat, indx);

	return NULL;
}

void udps_serv(args_o *args) {
	int indx, fmax;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], ssoc[NUMC];
	struct sockaddr_in ladr, cadr;
	struct sockaddr_in *padr;
	struct timeval tval;
	fd_set rfds;

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
		thrl[x].indx = x; thrl[x].lsoc = &(lsoc); thrl[x].csoc = csoc; thrl[x].ssoc = ssoc;
	}

	indx = 0;
	while (stat == 1) {
		indx = ((indx + 1) % NUMC);
		if (csoc[indx] < 0) {
			pthread_join(thrl[indx].thro, NULL);
			bzero(&(thrl[indx].thro), sizeof(pthread_t));
			csoc[indx] = 0;
		}
		FD_ZERO(&(rfds));
		FD_SET(lsoc, &(rfds));
		fmax = (lsoc + 1);
		tval.tv_sec = 5;
		tval.tv_usec = 0;
		if ((erro = select(fmax, &(rfds), NULL, NULL, &(tval))) < 0) {
			printf("[%s] erro udps_serv sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		if (FD_ISSET(lsoc, &(rfds))) {
			if (csoc[indx] != 0) {
				printf("[%s] warn udps_serv indx [%d]\n", gett(), indx);
				usleep(500000);
				continue;
			}
			padr = &(cadr);
			erro = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (erro < 1) {
				printf("[%s] erro udps_serv conn [%d]\n", gett(), erro);
				stat = 0; break;
			}
			csoc[indx] = erro;
			pthread_create(&(thrl[indx].thro), NULL, udps_send, &(thrl[indx]));
		}
	}

	free(cons);
}
