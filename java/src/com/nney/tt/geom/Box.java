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

	private Box(Box that) {
		this(that.left, that.top, that.right, that.bottom);
	}

	public static Box fromTopLeftAndSize(Coord c, int width, int height) {
		return Box.fromTopLeftAndSize(c.x, c.y, width, height);
	}

	public static Box fromSquare(int i) {
		return new Box(-i, -i, i, i);
	}

	public static Box fromTopLeftAndSize(int x, int y, int width, int height) {
		return new Box(x, y, x + width - 1, y + height - 1);
	}

	public static Box around(Coord c, int width, int height) {
		return around(c, -width, -height, width, height);
	}

	public static Box around(Coord c, int l, int t, int r, int b) {
		return new Box(c.x + l, c.y + t, c.x + r, c.y + b);
	}


	public void constrain(Coord c) {
		if (c.x < left) {
			c.x = left;
		}
		if (c.x > right) {
			c.x = right;
		}
		if (c.y < top) {
			c.y = top;
		}
		if (c.y > bottom) {
			c.y = bottom;
		}

	}

	public boolean inside(Coord c) {
		return c.x >= left && c.x <= right && c.y >= top && c.y <= bottom;
	}

	public void accommodate(Coord c) {
		left = Math.min(left, c.x);
		right = Math.max(right, c.x);
		top = Math.min(top, c.y);
		bottom = Math.max(bottom, c.y);
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

	public Box copy() {
		return new Box(this);
	}
	
	public void move(Coord c) {
		left += c.x;
		right += c.x;
		top += c.y;
		bottom += c.y;
	}
}
