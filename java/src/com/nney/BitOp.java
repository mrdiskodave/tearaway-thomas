package com.nney;

public class BitOp {
	static boolean test(int x, int b) {
		return (x & mask(b)) !=0;
	}
	static int change(int x, int b) {
		return x ^ mask(b);
	}
	static int set(int x, int b) {
		return x | mask(b);
	}
	static int clear(int x, int b) {
		return x & ~mask(b);
	}
	static int mask(int b) {
		return 1<<b;
	}
}
