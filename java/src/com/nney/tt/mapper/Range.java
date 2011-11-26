package com.nney.tt.mapper;

class Range {
	public final int start;
	public final int end;

	public Range(int start, int end) {
		this.start = start;
		this.end = end;
	}

	boolean in(int x) {
		return start <= x && x < end;
	}

	int much(int x) {
		if (!in(x)) return -1;
		return x - start;
	}
}