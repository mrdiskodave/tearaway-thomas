package com.nney;

public class BitOp {
	public static boolean test(int x, int b) {
		return (x & mask(b)) !=0;
	}
	public static int change(int x, int b) {
		return x ^ mask(b);
	}
	public static int set(int x, int b) {
		return x | mask(b);
	}
	public static int clear(int x, int b) {
		return x & ~mask(b);
	}
	public static int mask(int b) {
		return 1<<b;
	}
}
