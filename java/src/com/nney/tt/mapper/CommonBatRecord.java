package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class CommonBatRecord implements BatRecord {
	private final Coord where;
	private Bat bat;

	public CommonBatRecord(Bat bat2) {
		where = bat2.where();
		bat = bat2;
		
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

		bat.onMove(where);
	}
}
