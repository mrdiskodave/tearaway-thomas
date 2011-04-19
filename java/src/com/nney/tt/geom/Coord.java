package com.nney.tt.geom;

public class Coord {
	public int x;
	public int y;

	public Coord(int x, int y) {
		this.x = x;
		this.y = y;
	}

	private Coord(Coord c) {
		this(c.x, c.y);
	}

	public Coord() {
		this(0, 0);
	}

	public void sub(Coord other) {
		x -= other.x;
		y -= other.y;
	}

	public void add(Coord other) {
		x += other.x;
		y += other.y;
	}
	
	public Coord copy() {
		return new Coord(x, y);
	}
}
