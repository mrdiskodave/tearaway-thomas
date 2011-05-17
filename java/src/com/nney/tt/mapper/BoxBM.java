package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxBM extends BM {
	private final Box t;

	BoxBM(Box t) {
		this.t = t;
	}
	
	@Override
	public void sendBat(Coord alien, BatTarget rt) {
		rt.drawBox(t);
		rt.drawBat(new Coord(t.left, t.top));
		rt.drawBat(new Coord(t.right, t.bottom));
	}
	
	@Override
	void takeMovement(int what, Coord where) {
		assert what>=0 && what<=1;
		if (what==0) {
			t.left = where.x;
			t.top= where.y;
		}
		else {
			t.right = where.x;
			t.bottom = where.y;
		}
	}
}

