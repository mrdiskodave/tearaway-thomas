package com.nney.tt.geom;


public class Box {
	private int leftLimit;
	private int topLimit;
	private int rightLimit;
	private int bottomLimit;

	public Box(int leftLimit, int topLimit, int rightLimit, int bottomLimit) {
		this.leftLimit = leftLimit;
		this.topLimit = topLimit;
		this.rightLimit = rightLimit;
		this.bottomLimit = bottomLimit;
	}

	public boolean inside(Coord c) {
		return c.x >= leftLimit && c.x <= rightLimit && c.y >= topLimit && c.y <= bottomLimit;
	}

}
