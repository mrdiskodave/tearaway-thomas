package com.nney.tt.map;

public class BitArray {
	private final int[] content;

	public BitArray(int length) {
		content = new int[(length + 31) >> 5];
	}

	public void set(int x) {
		int offset = x >> 5;
		int mask = 1 << x;
		content[offset] |= mask;
	}

	public boolean test(int x) {
		int offset = x >> 5;
		int mask = 1 << x;
		return (content[offset] & mask) != 0;
	}
}
