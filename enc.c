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
unsigned int adds(unsigned int a, unsigned int b) {
	unsigned int c = 16;
	return (((a << c) ^ b) ^ (a >> c));
}
unsigned int mult(unsigned int a, unsigned int b) {
	unsigned int c = ((a + 1) * (b + 1));
	return ((c & 0xffff) ^ (c >> 16));
}
void sums(unsigned int *o, unsigned char *s, int a, int b, int c) {
	unsigned int t = 0;
	t = adds(t, mult(mult(a, 3), mult(s[a], 13)));
	t = adds(t, mult(mult(b, 5), mult(s[b], 15)));
	t = adds(t, mult(mult(c, 7), mult(s[c], 17)));
	for (int x = 0; x < 256; ++x) {
		t = adds(t, mult(mult(x, 9), mult(s[x], 19)));
	}
	*o = t;
}
