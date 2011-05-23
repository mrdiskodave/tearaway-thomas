package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatRecord implements Collidable {
	public final Coord where;
	private final Prop who;
	private final int what;

	BatRecord(Prop who, int what, Coord where) {
		this.who = who;
		this.what = what;
		this.where = where;
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForBat(where).inside(c);
	}

	public void press(Coord c) {
		who.onBatMovement(what, c);
	}
}
