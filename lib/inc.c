/* gcc -Wall -O3 -fPIC -shared -o inc.o lib/inc.c */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define LINE 192
#define NUMD 9

int DIDX = 0;
char DOBJ[NUMD][LINE];
pthread_mutex_t LOCK = PTHREAD_MUTEX_INITIALIZER;

void mutx(pthread_mutex_t *pntr)
{
	pthread_mutex_init(pntr, NULL);
	pthread_mutex_lock(pntr);
}

char *date()
{
	time_t secs = time(NULL);
	struct tm *info = localtime(&secs);
	int modi = ((secs % (NUMD - 1)) + 1);
	if (modi != DIDX)
	{
		pthread_mutex_lock(&LOCK);
		bzero(DOBJ[modi], LINE * sizeof(char));
		strftime(DOBJ[modi], 50, "%Y-%m-%d_%H:%M:%S", info);
		DIDX = modi;
		pthread_mutex_unlock(&LOCK);
	}
	return DOBJ[DIDX];
}

int nums(char *strs, int mins, int maxs, int defs)
{
	if (strs == NULL) { return defs; }
	int temp = atoi(strs);
	if ((temp < mins) || (maxs < temp)) { return defs; }
	return temp;
}

void itoc(unsigned char *buff, unsigned int numb, int skip)
{
	int indx = 0, shif = (32 - 8);
	while (shif >= 0)
	{
		if (indx < skip) { buff[indx] = 0; }
		else { buff[indx] = ((numb >> shif) & 0xff); shif -= 8; }
		++indx;
	}
}

int hexs(unsigned char *a, char *b, int n)
{
	int c = 0, f = 0, y = 0;
	int l = strlen(b);
	for (int x = 0; (x < l) && (y < n); ++x)
	{
		if ((f == 0) && ('0' <= b[x]) && (b[x] <= '9'))
		{
			a[y] = ((a[y] << 4) | ((b[x] - '0') +  0));
		}
		else if ((f == 0) && ('A' <= b[x]) && (b[x] <= 'F'))
		{
			a[y] = ((a[y] << 4) | ((b[x] - 'A') + 10));
		}
		else if ((f == 0) && ('a' <= b[x]) && (b[x] <= 'f'))
		{
			a[y] = ((a[y] << 4) | ((b[x] - 'a') + 10));
		}
		else
		{
			a[y] = b[x]; f = 1;
		}
		c = ((x % 2) || (f == 1)) ? 1 : 0;
		y = (y + c);
	}
	return y;
}
