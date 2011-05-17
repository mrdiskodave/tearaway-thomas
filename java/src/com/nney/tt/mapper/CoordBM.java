package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

public class CoordBM extends VisualProp {
	private final Coord t;

	public CoordBM(AlienProp p, Coord t) {
		super(p);
		this.t = t;
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		// 0
		rt.drawBat(t.copy());
	}
	
	@Override
	void takeBatMovement(int what, Coord where) {
		assert what==0;
		t.x = where.x;
		t.y = where.y;
	}
}
