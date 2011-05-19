package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

public class CoordVisualProp extends VisualProp {
	private final Coord t;

	public CoordVisualProp(AlienProp p, FieldAccessor fa) {
		super(p, fa);
		this.t = (Coord) fa.get();
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
		return String.format("x%dy%d", t.x, t.y);
	}
}
