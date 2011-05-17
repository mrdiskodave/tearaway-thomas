package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxBM extends VisualProp {
	private final Box t;

	BoxBM(AlienProp p, Box t) {
		super(p);
		this.t = t;
	}
	
	@Override
	public void createBats(Coord alien, BatTarget rt) {
		rt.drawBox(t);
		// 0
		rt.drawBat(new Coord(t.left, t.top));
		// 1
		rt.drawBat(new Coord(t.right, t.bottom));
		// 2
		rt.drawBat(new Coord(t.right, t.top));
		// 3
		rt.drawBat(new Coord(t.left, t.bottom));
	}
	
	@Override
	void takeBatMovement(int what, Coord where) {
		switch (what) {
		case 0:
			t.left = where.x;
			t.top= where.y;
			break;
		case 1:
			t.right = where.x;
			t.bottom = where.y;
			break;
		case 2:
			t.right = where.x;
			t.top = where.y;
			break;
		case 3:
			t.left = where.x;
			t.bottom = where.y;
			break;
		default:
			assert false;
		}
	}
}

