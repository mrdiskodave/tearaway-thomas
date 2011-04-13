package com.nney.tt.geom;


public class Box {
	public int left;
	public int top;
	public int right;
	public int bottom;
	// TODO: inclusive -- really??

	public Box(int left, int top, int right, int bottom) {
		this.left = left;
		this.top = top;
		this.right = right;
		this.bottom = bottom;
	}
	
	public Box(Box that) {
		this(that.left, that.top, that.right, that.bottom);
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

}
