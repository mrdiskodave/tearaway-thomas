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
	public Coord[] getBats(Coord alien) {
		return new Coord[] { t.copy() };
	}

	@Override
	void onBatMovement(int what, Coord where) {
		assert what == 0;
		onBring(where);
	}
	

	@Override
	void onBring(Coord c) {
		t.x = c.x;
		t.y = c.y;
	}

	@Override
	public String text() {
		return String.format("x%dy%d", t.x, t.y);
	}
}
