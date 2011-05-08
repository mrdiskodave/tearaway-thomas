package com.nney.tt.geom;


public class Box {
	public int left;
	public int top;
	public int right;
	public int bottom;
	// inclusive!

	public Box(int left, int top, int right, int bottom) {
		this.left = left;
		this.top = top;
		this.right = right;
		this.bottom = bottom;
	}
	
	public Box(Box that) {
		this(that.left, that.top, that.right, that.bottom);
	}
	
	public static Box fromTopLeftAndSize(Coord c, int width, int height) {
		return Box.fromTopLeftAndSize(c.x, c.y, width, height);
	}

	public static Box fromSquare(int i) {
		return new Box(-i, -i, i, i);
	}

	
	public static Box fromTopLeftAndSize(int x, int y, int width, int height) {
		return new Box(x, y, x+width-1, y+height-1);
	}

	public static Box around(Coord c, int width, int height) {
		return new Box(c.x-width, c.y-height, c.x+width, c.y+height);
	}

	public void constrain(Coord c) {
		if (c.x<left) {
			c.x = left;
		}
		if (c.x>right) {
			c.x = right;
		}
		if (c.y<top) {
			c.y = top;
		}
		if (c.y>bottom) {
			c.y = bottom;
		}
		
	}

	public boolean inside(Coord c) {
		return c.x >= left && c.x <= right && c.y >= top && c.y <= bottom;
	}

	public void shrink(int i) {
		left += i;
		right -= i;
		top += i;
		bottom -= i;
	}
	
	public int width() {
		return 1 + right - left;
	}
	
	public int height() {
		return 1 + bottom - top;
	}
	
	@Override
	public String toString() {
		return String.format("Box(%d, %d, %d, %d)", left, top, right, bottom);
	}
}
