package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

public class CoordVisualProp extends VisualProp {
	private final Coord t;

	public CoordVisualProp(AlienProp p, Coord t) {
		super(p);
		this.t = t;
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		// 0
		rt.drawBat(t.copy());
	}

	@Override
	void moveTo(int what, Coord where) {
		assert what == 0;
		t.x = where.x;
		t.y = where.y;
	}

	@Override
	public String text() {
		return String.format("%dx%d", t.x, t.y);
	}
}
