/* gcc -Wall -O2 -fPIC -shared -o /etc/c.so c.c */
void keys(unsigned char *s, int r, unsigned char *v, int n, unsigned char *k, int l) {
	int i = 0, j = 0, m = 256, t;
	for (int x = 0; x < r; ++x) {
		i = (x % m);
		j = ((j + s[i] + (v[i % n] * 5) + (k[i % l] * 7)) % m);
		t = s[i]; s[i] = s[j]; s[j] = t;
	}
}
void ciph(unsigned char *o, unsigned char *d, int l, int *a, int *b, int *c, unsigned char *s, char y) {
	int i = *a, j = *b, q = *c, m = 256, t, k;
	for (int x = 0; x < l; ++x) {
		i = ((i + 1) % m);
		j = ((j + s[i] + q) % m);
		t = s[i]; s[i] = s[j]; s[j] = t;
		k = ((s[i] + s[j]) % m);
		if (y == 'e') {
			o[x] = ((d[x] ^ q) ^ s[k]); q = d[x];
		} else {
			o[x] = ((d[x] ^ s[k]) ^ q); q = o[x];
		}
	}
	*a = i; *b = j; *c = q;
}
unsigned int mult(unsigned int a, unsigned int b) {
	unsigned int c = (a * b);
	unsigned int d = ((c >> 8) ^ (c & 0xff));
	return d;
}
void sums(unsigned char *o, int l, unsigned char *s, int a, int b, int c) {
	unsigned char t[l];
	unsigned char p[] = { 0xff, 0x13, 0x37, 0x11 };
	int i = 0, j = 0, n = 4, m = 256;
	int z = ((a + b + c) % m);
	for (int x = 0; x < l; ++x) {
		t[x] = (p[x % n] + ((x / n) * 3));
	}
	for (int x = 0; x < m; ++x) {
		i = (x % l);
		j = (mult(s[x], j + 1) % m);
		o[i] = ((t[i] ^ s[z]) ^ s[j]);
		z = s[z];
	}
}
