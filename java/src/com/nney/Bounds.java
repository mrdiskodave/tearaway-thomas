package com.nney;

public class Bounds {
	public final int left;
	public final int top;
	public final int width;
	public final int height;

	public Bounds(int left, int top, int width, int height) {
		this.left = left;
		this.top = top;
		this.width = width;
		this.height = height;
	}
	
	@Override
	public String toString() {
		return String.format("Box(%d, %d, %d, %d)", left, top, width, height);
	}
}
