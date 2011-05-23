package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatRecord implements Collidable {
	public final VisualAction action;
	public final Coord where;

	BatRecord(VisualAction action, Coord where) {
		this.action = action;
		this.where = where;
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForBat(where).inside(c);
	}
}
