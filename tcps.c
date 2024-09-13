
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
			stat = -2;
		}
	} else { stat = -9; }

	while (stat == 1) {
		csoc = *(argq->sock);
		if ((argq->stat != 1) || (cons->stat != 1) || (csoc < 1)) {
			stat = -8; break;
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
			if (leng < 1) { stat = -5; break; }
			erro = senz(ssoc, data, leng);
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
			cons->last = secs;
			if ((secs - cons->lock[1]) > 1) {
				printf("[%s] info tcps_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons->adrs[0], cons->port[0], cons->adrs[1], cons->port[1], cidx, size);
				cons->lock[1] = secs;
			}
		}
		if ((secs - cons->last) >= EXPC) {
			stat = 0; break;
		}
	}

	csoc = *(argq->sock);
	if (csoc > 0) {
		size = (hlen + 1);
		PACKU16(head->leng, ENDL);
		bcopy(head, data, hlen); pntr = data;
		erro = wrap(cryp, temp, maxl, data, size, 'e');
		if (erro > 0) { pntr = temp; size = erro; }
		erro = sent(csoc, pntr, size, midx);
	}

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

	int leng, size, cidx, fidx, sprt, cprt, fdes;
	int erro = 1, stat = 1, olen = 1, last = 1;
	int maxl = (BTCP + HEDL);
	int hlen = sizeof(pckt_h);
	int rpwp[NUMC][2];
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
			stat = 0; break;
		}
		size = recw(&(buff));
		if (size < 1) {
			if (size < 0) { printf("[%s] warn tcps_send recw [%d] [%d] [%d]\n", gett(), indx, size, buff.sock); }
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
		if ((olen != ENDL) && ((leng < 1) || (BTCP < leng))) {
			printf("[%s] warn tcps_send head [%d]\n", gett(), leng);
			stat = -9; break;
		}
		secs = time(NULL);
		UPACK16(sprt, head->sprt);
		padr = &(addr);
		padr->sin_family = AF_INET;
		padr->sin_port = htons(sprt);
		UPACK32(padr->sin_addr.s_addr, head->sadr);
		cidx = -1; fidx = -1; last = 0;
		for (int x = 0; x < NUMC; ++x) {
			cprt = cons[x].port[0];
			cadr = &(cons[x].addr[0]);
			if ((cons[x].stat == 0) && (proc[x].stat == 0)) {
				fidx = x;
			} else if ((cons[x].stat == 1) && (proc[x].stat == 1)) {
				if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
					cidx = x; break;
				}
				if (cons[x].last < cons[last].last) {
					last = x;
				}
			} else {
				if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
					olen = ENDL; break;
					if (args->conz == 1) { stat = -9; break; }
				}
			}
		}
		if ((olen != ENDL) && (cidx < 0) && (fidx > -1)) {
			if ((fdes = sets(&(cons[fidx]), &(proc[fidx]), head, args->skey, rpwp[fidx], ssoc, csoc, fidx, indx, 2)) < 1) {
				printf("[%s] warn tcps_send sock [%d]\n", gett(), fidx);
			} else {
				cidx = fidx;
				bzero(&(proc[cidx].thro), sizeof(pthread_t));
				pthread_create(&(proc[cidx].thro), NULL, tcps_recv, &(proc[cidx]));
			}
		}
		if ((cidx < 0) || (proc[cidx].stat != 1) || (cons[cidx].stat != 1)) {
			if (olen != ENDL) {
				printf("[%s] warn tcps_send indx [%d]\n", gett(), cidx);
				if (cidx > -1) { last = cidx; }
				if (proc[last].stat == 1) { proc[last].stat = 7; }
				if (cons[last].stat == 1) { cons[last].stat = 7; }
				if (args->conz == 1) { stat = -9; break; }
			}
		} else {
			if (olen == ENDL) {
				if (proc[cidx].stat == 1) { proc[cidx].stat = 8; }
				if (cons[cidx].stat == 1) { cons[cidx].stat = 8; }
				if (args->conz == 1) { stat = -9; break; }
			} else {
				erro = write(cons[cidx].rpwp[1], pntr, leng);
				cons[cidx].last = secs;
				if ((secs - cons[cidx].lock[0]) > 1) {
					printf("[%s] info tcps_send data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
					cons[cidx].lock[0] = secs;
				}
			}
		}
	}

	sleep(3);
	for (int x = 0; x < NUMC; ++x) {
		if ((cons[x].indx == indx) && (cons[x].stat == 1)) {
			printf("[%s] info tcps_send stop conn [%d][%d] [%d]\n", gett(), indx, x, cons[x].stat);
			cons[x].stat = 9;
		}
		if ((proc[x].indx == indx) && (proc[x].stat == 1)) {
			printf("[%s] info tcps_send stop proc [%d][%d] [%d]\n", gett(), indx, x, proc[x].stat);
			proc[x].stat = 9;
		}
	}
	sleep(3);
	for (int x = 0; x < NUMC; ++x) {
		if ((cons[x].indx == indx) && (cons[x].stat > 0)) {
			printf("[%s] warn tcps_send endp conn [%d][%d] [%d]\n", gett(), indx, x, cons[x].stat);
		}
		if ((proc[x].indx == indx) && (proc[x].stat > 0)) {
			printf("[%s] warn tcps_send endp proc [%d][%d] [%d]\n", gett(), indx, x, proc[x].stat);
		}
	}

	argp->stat = -1;

	printf("[%s] info tcps_send ends [%d] [%d]\n", gett(), stat, indx);

	return NULL;
}

void tcps_serv(args_o *args) {
	int indx, fdes;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int slen = sizeof(struct sockaddr_in);
	int csoc[NUMC], ssoc[NUMC];
	struct sockaddr_in ladr, cadr;
	struct sockaddr_in *padr;
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

	while (stat == 1) {
		indx = -1;
		for (int x = 0; x < NUMC; ++x) {
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
				if (cons[x].stat == 1) {
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
			if (thrl[x].stat == 0) {
				indx = x;
			}
		}
		if ((erro = sels(&(rfds), lsoc, 0)) < 0) {
			printf("[%s] erro tcps_serv sels [%d]\n", gett(), erro);
			stat = 0; break;
		}
		if (FD_ISSET(lsoc, &(rfds))) {
			if (indx < 0) {
				printf("[%s] warn tcps_serv indx [%d]\n", gett(), indx);
				usleep(500000);
				continue;
			}
			padr = &(cadr);
			fdes = accept(lsoc, (struct sockaddr *)padr, (socklen_t *)&(slen));
			if (fdes < 1) {
				printf("[%s] erro tcps_serv conn [%d]\n", gett(), fdes);
				stat = 0; break;
			}
			csoc[indx] = fdes;
			thrl[indx].indx = indx;
			thrl[indx].stat = 1;
			bzero(&(thrl[indx].thro), sizeof(pthread_t));
			pthread_create(&(thrl[indx].thro), NULL, tcps_send, &(thrl[indx]));
		}
	}

	free(cons);
}
