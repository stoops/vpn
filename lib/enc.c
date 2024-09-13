/* gcc -Wall -O2 -fPIC -shared -o c.so c.c */
void keys(unsigned char *s, int r, unsigned char *v, int n, unsigned char *k, int l) {
	int i = 0, j = 0, m = 256, t;
	for (int x = 0; x < r; ++x) {
		i = (x % m);
		j = ((j + s[i] + (v[i % n] * 5) + (k[i % l] * 7)) % m);
		t = s[i]; s[i] = s[j]; s[j] = t;
	}
}
void ciph(unsigned char *o, unsigned char *d, int l, unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *s, char z) {
	int m = 256, t, k;
	unsigned char i = *a, j = *b, q = *c;
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
void sums(unsigned char *o, int l, unsigned char *s, unsigned char a, unsigned char b, unsigned char c) {
	unsigned char t[l];
	unsigned char p[] = { 0xff, 0x13, 0x37, 0x11 };
	int d = 4, e = 0;
	for (int x = 0; x < l; ++x) {
		e = ((p[x % d] + (x / d)) % 256);
		t[x] = e;
	}
	ciph(o, t, l, &a, &b, &c, s, 'e');
}
