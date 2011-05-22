package com.nney.utils;

public final class Math2 {
	public static final int roundUpDiv(int x, int y) {
		return (x + y - 1) / y;
	}

	public static final int limit(int min, int max, int value) {
		return Math.min(max, Math.max(min, value));
	}
	
	public static final boolean maskTest(int x, int mask) {
		return (x&mask)!=0;
	}
	
	public static final boolean bitTest(int x, int bit) {
		return maskTest(x, 1<<bit);
	}
}
