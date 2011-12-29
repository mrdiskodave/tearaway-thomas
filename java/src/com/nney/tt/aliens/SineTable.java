package com.nney.tt.aliens;

public class SineTable {
	private final int length;
	private final int mag;

	public SineTable(int length, int mag) {
		this.length = length;
		this.mag = mag;
	}

	public int get(int idx) {
		assert idx < length;
		double angle = (2 * Math.PI * idx) / length;
		return (int) (Math.sin(angle) * mag);
	}

	public int length() {
		return length;
	}
}
