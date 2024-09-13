/* gcc -Wall -O2 -fPIC -shared -o c.so c.c */
void keys(unsigned char *s, int r, unsigned char *v, int n, unsigned char *k, int l) {
	int i = 0, j = 0, q = 0, m = 256;
	unsigned char t;
	for (int x = 0; x < m; ++x) { s[x] = x; }
	for (int x = 0; x < r; ++x) {
		i = (x % m);
		q = (((v[i % n] ^ 0x13) + q + (k[i % l] ^ 0x37)) % m);
		j = ((j + s[i] + q) % m);
		t = s[i]; s[i] = s[j]; s[j] = t;
	}
}
void ciph(unsigned char *o, unsigned char *d, int l, unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *s, char z) {
	int m = 256, k;
	unsigned char t, i = *a, j = *b, q = *c;
	for (int x = 0; x < l; ++x) {
		i = ((i + 1) % m);
		j = ((j + s[i] + q) % m);
		t = s[i]; s[i] = s[j]; s[j] = t;
		k = ((s[i] + s[j]) % m);
		if (z == 'e') {
			o[x] = ((d[x] ^ q) ^ s[k]); q = o[x];
		} else {
			o[x] = ((d[x] ^ s[k]) ^ q); q = d[x];
		}
	}
	*a = i; *b = j; *c = q;
}
void sums(unsigned char *o, int l, unsigned char a, unsigned char b, unsigned char c, unsigned char *s) {
	int r = 256, n = 4;
	unsigned char p[] = { 0xff, 0x13, 0x37, 0x11 };
	unsigned char i = a, j = b, k = c;
	unsigned char t[r], u[r];
	for (int x = 0; x < r; ++x) {
		t[x] = ((p[x % n] ^ (x / n)));
	}
	ciph(u, t, r, &i, &j, &k, s, 'e');
	for (int x = 0; x < l; ++x) {
		--r;
		o[x] = u[r];
	}
}
