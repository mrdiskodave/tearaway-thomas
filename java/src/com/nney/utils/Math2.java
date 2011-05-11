package com.nney.utils;

public class Math2 {
	public static int roundUpDiv(int x, int y) {
		return (x + y - 1) / y;
	}
	
	public static int limit(int min, int max, int value) {
		return Math.min(max, Math.max(min, value));
	}
	
}
