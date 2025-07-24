
void *udpc_recv(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int *esoc = argp->esoc;
	int *rsoc = argp->rsoc;

	int flag;
	int erro = 1, stat = 1;
	int lsoc = *(argp->lsoc);
	int hlen = sizeof(pckt_h);
	int leng, size, fdes, sprt, cprt;
	unsigned char temp[BMAX];
	unsigned char *pntr;
	time_t secs;
	fd_set rfds;
	struct sockaddr_in addr;
	struct sockaddr_in *padr, *cadr;

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
		if (argp->stat != 1) {
			if (args->conz != 1) {
				printf("[%s] warn udpc_recv stat [%d] [%d]\n", gett(), stat, argp->stat);
			}
			stat = argp->stat; break;
		}
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
			printf("[%s] warn udpc_recv socs [%d][%d]\n", gett(), *esoc, *rsoc);
			usleep(USLA);
			continue;
		}
		if ((erro = sels(&(rfds), buff[0].sock, buff[1].sock)) < 0) {
			printf("[%s] erro udpc_recv sels [%d]\n", gett(), erro);
			usleep(USLA);
			continue;
		}
		for (int x = 0; x < 2; ++x) {
			if ((buff[x].sock > 0) && (FD_ISSET(buff[x].sock, &(rfds)))) {
				flag = 0;
				head = &(pobj[x]);
				cryp = &(cobj[x]);
				size = recw(&(buff[x]));
				if (size < 1) {
					if (args->conz != 1) {
						printf("[%s] warn udpc_recv recw [%d] [%d] [%d]\n", gett(), x, size, buff[x].sock);
					}
					flag = 1;
				}
				if (flag == 0) {
					size = buff[x].size;
					pntr = buff[x].buff;
					erro = wrap(cryp, temp, BMAX, pntr, size, 'd');
					if (erro > 0) { pntr = temp; size = erro; }
					if (erro < 0) {
						printf("[%s] warn udpc_recv ciph [%d]\n", gett(), erro);
						if (args->conz == 1) { stat = -9; break; }
						flag = 1;
					}
				}
				if (flag == 0) {
					bcopy(pntr, head, hlen);
					UPACK16(leng, head->leng);
					leng -= hlen; pntr += hlen;
					if ((leng < BONE) || (BTCP < leng)) {
						printf("[%s] warn udpc_recv head [%d]\n", gett(), leng);
						if (args->conz == 1) { stat = -9; break; }
						flag = 1;
					}
				}
				if (flag == 0) {
					padr = &(addr);
					UPACK16(sprt, head->sprt);
					padr->sin_family = AF_INET;
					padr->sin_port = htons(sprt);
					UPACK32(padr->sin_addr.s_addr, head->sadr);
					erro = senu(lsoc, pntr, leng, padr);
					if (erro < 1) { printf("[%s] warn udpc_recv senu [%d]\n", gett(), erro); }
					secs = time(NULL);
					for (int cidx = 0; cidx < NUMC; ++cidx) {
						cprt = cons[cidx].port[0];
						cadr = &(cons[cidx].addr[0]);
						if (cons[cidx].stat == 0) {
							/* no-op */
						} else if (cons[cidx].stat == 1) {
							if ((cprt == sprt) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
								cons[cidx].last = secs;
								if ((secs - cons[cidx].lock[1]) > 1) {
									printf("[%s] info udpc_recv data [%s:%d] -> [%s:%d] [%d] [%d]\n", gett(), cons[cidx].adrs[0], cons[cidx].port[0], cons[cidx].adrs[1], cons[cidx].port[1], cidx, leng);
									cons[cidx].lock[1] = secs;
								}
							}
						}
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
		printf("[%s] info udpc_recv ends [%d]\n", gett(), stat);
	} else {
		printf("[%s] warn udpc_recv ends [%d]\n", gett(), stat);
	}

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
		if (argp->stat != 1) {
			stat = -2; break;
		}
		ssiz[0] = 0; ssiz[1] = 0;
		leng = read(argp->rpwp[0], ssiz, 2);
		if (leng != 2) {
			printf("[%s] erro udpc_send pipe [%d] [%d]\n", gett(), leng, argp->rpwp[0]);
			usleep(USLA);
			continue;
		}
		UPACK16(indx, ssiz);
		if ((indx < 0) || (NUMC < indx)) {
			printf("[%s] erro udpc_send indx [%d]\n", gett(), indx);
			usleep(USLA);
			continue;
		}
		leng = bufs[indx].leng;
		if ((bufs[indx].stat != 1) || (leng < BONE) || (BTCP < leng)) {
			printf("[%s] erro udpc_send buff [%d]\n", gett(), indx);
			usleep(USLA);
			continue;
		}
		padr = &(bufs[indx].addr);
		cidx = -1; fidx = -1;
		secs = time(NULL);
		for (int x = 0; x < NUMC; ++x) {
			cadr = &(cons[x].addr[0]);
			if (cons[x].stat == 0) {
				if (fidx < 0) { fidx = x; }
			} else if (cons[x].stat == 1) {
				if ((cons[x].port[0] == bufs[indx].port) && (cadr->sin_addr.s_addr == padr->sin_addr.s_addr)) {
					cidx = x; break;
				}
			}
		}
		if ((cidx < 0) && (fidx > -1)) {
			bzero(cons[fidx].adrs[1], LINE);
			if (args->dest == NULL) {
				comd(cons[fidx].adrs[1], &(cons[fidx].port[1]), ILEN, args->comd, prot, bufs[indx].adrs, bufs[indx].port);
			} else {
				strncpy(cons[fidx].adrs[1], args->dest, ILEN); cons[fidx].port[1] = args->dprt;
			}
			if (cons[fidx].adrs[1][0] == 0) {
				printf("[%s] warn udpc_send dest [%s:%d]\n", gett(), bufs[indx].adrs, bufs[indx].port);
				cidx = -9;
			} else {
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
				cons[fidx].lock[0] = 0;
				cons[fidx].lock[1] = 0;
				cons[fidx].last = secs;
				cons[fidx].stat = 1;
				cidx = fidx;
				head = &(cons[cidx].head);
				head->prot = 1; head->kind = 1;
				PACKU32(head->sadr, cons[cidx].addr[0].sin_addr.s_addr); PACKU16(head->sprt, cons[cidx].port[0]);
				PACKU32(head->dadr, cons[cidx].addr[1].sin_addr.s_addr); PACKU16(head->dprt, cons[cidx].port[1]);
			}
		}
		if (cidx == -9) {
			/* no-op */
		} else if ((cidx < 0) || (cons[cidx].stat != 1)) {
			printf("[%s] warn udpc_send indx [%d]\n", gett(), cidx);
		} else {
			sock = *(cons[cidx].sock);
			if (sock < 1) {
				printf("[%s] warn udpc_send conn [%d]\n", gett(), sock);
			} else {
				midx = cons[cidx].midx;
				head = &(cons[cidx].head);
				cryp = &(cons[cidx].cryp[0]);
				size = (hlen + leng);
				PACKU16(head->leng, size);
				bcopy(head, data, hlen); pntr = (data + hlen);
				bcopy(bufs[indx].buff, pntr, leng); pntr = data;
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

	printf("[%s] info udpc_send ends [%d]\n", gett(), stat);

	return NULL;
}

void *udpc_mgmt(void *argv) {
	thro_o *argp = (thro_o *)argv;
	args_o *args = argp->args;
	cons_l *cons = argp->cons;
	int *esoc = argp->esoc;
	int *rsoc = argp->rsoc;

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
			if (args->nots != NULL) {
				*esoc = icon(*esoc, &(eadr));
			}
			*rsoc = icon(*rsoc, &(radr));
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
			}
		}
		usleep(USLB);
	}

	return NULL;
}

void udpc_serv(args_o *args) {
	int indx;
	int erro = 1, stat = 1, reus = 1;
	int lsoc = -1, esoc = -1, rsoc = -1;
	int llen = sizeof(struct sockaddr_in);
	int elen = sizeof(struct sockaddr_in);
	int rlen = sizeof(struct sockaddr_in);
	int rpwp[2];
	int *plen, *pnum;
	char *pntr;
	unsigned char ssiz[LINE];
	unsigned char *pbuf;
	struct sockaddr_in ladr, eadr, radr;
	struct sockaddr_in *padr;
	fd_set rfds;
	time_t secs;
	pthread_t thrr, thrs, mgmt;

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
	padr->sin_addr.s_addr = inet_addr(LOCL);

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

	thro.rpwp = rpwp; thro.nots = nots; thro.stat = 1;
	thro.args = args; thro.bufs = bufs; thro.cons = cons;
	thro.lsoc = &(lsoc); thro.esoc = &(esoc); thro.rsoc = &(rsoc);

	bzero(&(thrr), sizeof(pthread_t));
	pthread_create(&(thrr), NULL, udpc_recv, &(thro));
	bzero(&(thrs), sizeof(pthread_t));
	pthread_create(&(thrs), NULL, udpc_send, &(thro));

	bzero(&(mgmt), sizeof(pthread_t));
	pthread_create(&(mgmt), NULL, udpc_mgmt, &(thro));
	while (stat == 1) {
		indx = -1;
		for (int x = 0; (indx < 0) && (x < NUMC); ++x) {
			if (bufs[x].stat == 0) {
				indx = x;
			}
		}
		if ((erro = sels(&(rfds), lsoc, 0)) < 0) {
			printf("[%s] erro udpc_serv sels [%d]\n", gett(), erro);
			stat = -2; break;
		}
		secs = time(NULL);
		if (FD_ISSET(lsoc, &(rfds))) {
			if (indx < 0) {
				printf("[%s] warn udpc_serv indx [%d]\n", gett(), indx);
				usleep(USLA);
				continue;
			}
			pntr = bufs[indx].adrs;
			pbuf = bufs[indx].buff;
			pnum = &(bufs[indx].port);
			padr = &(bufs[indx].addr);
			plen = &(bufs[indx].leng);
			*plen = recu(lsoc, pbuf, BUDP, padr);
			if (*plen < BONE) {
				printf("[%s] erro udpc_serv leng\n", gett());
				stat = -3; break;
			}
			bufs[indx].last = secs;
			bufs[indx].stat = 1;
			copy(pntr, inet_ntoa(padr->sin_addr), ILEN, LINE);
			*pnum = ntohs(padr->sin_port);
			PACKU16(ssiz, indx);
			erro = write(rpwp[1], ssiz, 2);
			if (erro < 1) {
				printf("[%s] erro udpc_serv pipe\n", gett());
				stat = -4; break;
			}
		}
	}

	fins(&(rpwp[1]), 0);
	fins(&(rpwp[0]), 0);

	free(nots);
	free(cons);
	free(bufs);
}
