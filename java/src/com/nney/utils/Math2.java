package com.nney.utils;

public final class Math2 {
	public static final int fracMult(int x, int top, int bottom) {
		return x*top/bottom;
	}

	public static final int percent(int x, int percent) {
		return fracMult(x, percent, 100);
	}
	
	public static final int percent2(int x, int percent) {
		// slightly slower, on my machine, than percent()
		return (int) (x*(percent*0.01f));
	}
	
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

	public static int findPowerOfTwo(int v) {
		for (int x = 0; x < 32; x++) {
			int a = 1 << x;
			if (a == v) return x;
		}
		throw new RuntimeException(v+" was supposed to be a power of two");
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
