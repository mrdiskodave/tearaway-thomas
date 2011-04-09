package com.nney.tt.geom;


public class Box {
	public int left;
	public int top;
	public int right;
	public int bottom;

	public Box(int left, int top, int right, int bottom) {
		this.left = left;
		this.top = top;
		this.right = right;
		this.bottom = bottom;
	}

	public boolean inside(Coord c) {
		return c.x >= left && c.x <= right && c.y >= top && c.y <= bottom;
	}

}
