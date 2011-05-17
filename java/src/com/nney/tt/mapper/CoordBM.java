package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class CoordBM extends BM {
	private final Coord t;

	public CoordBM(Coord t) {
		this.t = t;
	}

	@Override
	public void sendBat(Coord alien, BatTarget rt) {
		rt.drawBat(t.copy());
	}
	
	@Override
	void takeMovement(int what, Coord where) {
		assert(what==0);
		t.x = where.x;
		t.y = where.y;
	}
}
