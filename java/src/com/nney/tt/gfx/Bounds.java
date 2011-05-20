package com.nney.tt.gfx;

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

	public boolean inside(int x, int y) {
		x -= left;
		y -= top;
		return x >= 0 & x < width && y >= 0 && y < height;
	}

	public Bounds(Bounds that) {
		this(that.left, that.top, that.width, that.height);
	}

	@Override
	public String toString() {
		return String.format("Bounds(%d, %d, %d, %d)", left, top, width, height);
	}
}
