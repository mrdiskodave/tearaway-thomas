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
	
	public void mul(int z) {
		x *= z;
		y *= z;
	}

	public void div(int z) {
		x /= z;
		y /= z;
	}
	
	public void and(int x2, int y2) {
		x &= x2;
		y &= y2;
	}

	public Coord copy() {
		return new Coord(this);
	}
	
	// short hand, as we do it so much
	public Coord copyAndAdd(int x, int y) {
		Coord answer = copy();
		answer.x += x;
		answer.y += y;
		return answer;
	}
	
	public Coord copyAndDiv(int z) {
		Coord answer = copy();
		answer.div(z);
		return answer;
	}
	
	
	
	@Override
	public String toString() {
		return String.format("%sx%s", x, y);
	}
}
