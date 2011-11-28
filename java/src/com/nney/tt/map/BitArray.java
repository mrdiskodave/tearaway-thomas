package com.nney.tt.map;

public class BitArray {
	private final int[] content;
	private final int length;

	public BitArray(int length) {
		this.length = length;
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

	public int count() {
		int answer = 0;
		for (int c : content) {
			answer += Integer.bitCount(c);
		}
		return answer;
	}

	public int length() {
		return length;
	}
}
