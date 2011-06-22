package com.nney.utils;

public final class Math2 {
	public static final int roundUpDiv(int x, int y) {
		return (x + y - 1) / y;
	}

	public static final int limit(int min, int max, int value) {
		return atMost(max, atLeast(min, value));
	}

	private static final int atMost(int max, int value) {
		return Math.min(max, value);
	}

	public static final int atLeast(int min, int value) {
		return Math.max(min, value);
	}
	
	public static final boolean maskTest(int x, int mask) {
		return (x&mask)!=0;
	}
	
	public static final boolean bitTest(int x, int bit) {
		return maskTest(x, 1<<bit);
	}
	
	public static final int signOf(int x) {
		if (x < 0) return -1;
		if (x > 0) return 1;
		return 0;
	}

	public static final int closer(int x, int target, int amount) {
		if (x<target) {
			x += amount;
			if (x>target) {
				x = target;
			}
		}
		else if (x>target) {
			x -= amount;
			if (x<target) {
				x = target;
			}
		}
		return x;
	}
}
