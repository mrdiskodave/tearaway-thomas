package com.nney.tt.toygen;

class Range {
	public final int start;
	public final int end;

	public Range(int start, int length) {
		this.start = start;
		this.end = start + length;
	}

	boolean in(int x) {
		return start <= x && x < end;
	}

	int much(int x) {
		if (!in(x)) return -1;
		return x - start;
	}
}