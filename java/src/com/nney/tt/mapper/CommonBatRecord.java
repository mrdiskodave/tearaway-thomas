package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class CommonBatRecord implements BatRecord {
	private final Coord where;
	private final Prop who;
	private final int what;

	CommonBatRecord(Prop who, int what, Coord where) {
		this.who = who;
		this.what = what;
		this.where = where;
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForBat(where).inside(c);
	}

	@Override
	public void press(Coord delta) {
		// Our lifetime is the same as the Pen#stroke()
		// because the BatMovingPen has a reference to us.
		// We track the cumulative movement here:
		where.add(delta);
		
		who.onBatMovement(what, where);
	}
}
